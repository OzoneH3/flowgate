# Disposable isolated guest: direct kernel shaping lease expiry and recovery.
# No performance comparison, no host traffic or activation.
import resource
import os,sys,json,socket,subprocess,time,pathlib,sqlite3,select,traceback,shutil,threading
P=pathlib.Path('/work/m1');R=pathlib.Path('/work/.workspace/m1');R.mkdir(mode=0o700,exist_ok=True);API=R/'session'/'api.sock';children=[];records=[];backend=None
assert os.environ.get('FLOWGATE_PARENT_NETNS') and os.environ['FLOWGATE_PARENT_NETNS']!=os.readlink('/proc/self/ns/net')
DEV='fghost'
def cmd(*a):return subprocess.check_output([str(x) for x in a],text=True,timeout=20)
def launch(args,name):
 p=subprocess.Popen([str(x) for x in args],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=(R/(name+'.err')).open('a'),text=True,bufsize=1);children.append(p);return p
def line(p,timeout=25):
 if not select.select([p.stdout],[],[],timeout)[0]:raise RuntimeError('fixture timeout '+str(p.pid))
 s=p.stdout.readline()
 if not s:raise RuntimeError('fixture exited '+str(p.pid))
 return json.loads(s)
def write(p,s):p.stdin.write(s+'\n');p.stdin.flush()
def ask(p,s):write(p,s);return line(p)
def peerop(op):return ask(peer,json.dumps({'op':op}))
def request(op='list',ro=False,**kw):
 with socket.socket(socket.AF_UNIX) as s:
  s.settimeout(4);s.connect(str(API)+('.monitor' if ro else ''));s.sendall((json.dumps(dict(version=1,operation=op,**kw))+'\n').encode())
  return json.loads(s.makefile('rb').readline())
def api(op='list',**kw):
 d=request(op,**kw);assert not d.get('error'),d;return d
GEN=''
def status():return api('upload-status',generation=GEN)['upload_shaping']
def bindings(s=None):return (s or status()).get('kernel',{}) and ((s or status()).get('kernel') or {}).get('bindings',[]) or []
def wait(pred,timeout=35):
 until=time.monotonic()+timeout
 while time.monotonic()<until:
  s=status()
  if s['status']=='Unsupported':raise RuntimeError('shaping fault '+json.dumps(s))
  if pred(s):return s
  time.sleep(.25)
 raise RuntimeError('wait timeout '+json.dumps(s))
def configure(caps=None,enabled=True):
 before=status();r=api('upload-configure',generation=GEN,expected_version=before['version'],upload_config={'enabled':enabled,'caps':caps or []})['upload_shaping'];assert r['version']==before['version']+1
 return wait(lambda s:s['applied_version']==r['version'])
def cap(name,rate):return {'uid':0,'application':procs[name]['application']['key'],'bits_per_second':rate}
def appkey(name):return '0:'+procs[name]['application']['key']
def childpids():
 pids=set()
 for task in pathlib.Path(f'/proc/{backend.pid}/task').glob('*'):
  try:pids.update((task/'children').read_text().split())
  except FileNotFoundError:pass
 return [pid for pid in pids if b'controller.py' in pathlib.Path('/proc/'+pid+'/cmdline').read_bytes()]
def kernel_workers():
 out=[]
 for path in pathlib.Path('/proc').glob('[0-9]*/cmdline'):
  try:
   argv=path.read_bytes().split(b'\0')
   if argv[:2]==[b'/work/m1/kernel',b'serve']:out.append(int(path.parent.name))
  except (FileNotFoundError,ProcessLookupError):pass
 return out
def socket_workers():
 out=[]
 for path in pathlib.Path('/proc').glob('[0-9]*/cmdline'):
  try:
   if path.read_bytes().split(b'\0')[:2]==[b'/work/m1/probe',b'serve-sockets']:out.append(int(path.parent.name))
  except (FileNotFoundError,ProcessLookupError):pass
 return out
def start(binary,name):
 global backend,GEN
 args=[P/binary,'serve','--socket',API,'--database',R/'rules.db','--uid','0','--administrator','--allow-protection','--protection-state',R/'protection.json','--evaluation-state',R/'session'/'evaluation','--decision-timeout','2s','--experimental-upload-interface',DEV,'--experimental-upload-helpers',P,'--experimental-upload-state',R/'controller','--experimental-upload-parent-netns',os.environ['FLOWGATE_PARENT_NETNS']]
 backend=launch(args,name)
 for _ in range(300):
  try:
   s=api()
   if s.get('protection',{}).get('state')=='active':GEN=s['generation'];return s
  except (FileNotFoundError,ConnectionRefusedError,AssertionError):pass
  if backend.poll() is not None:raise RuntimeError('daemon exited '+str(backend.returncode))
  time.sleep(.1)
 raise RuntimeError('not ready')
def stop():
 global backend
 if backend and backend.poll() is None:
  backend.terminate()
  try:backend.wait(25)
  except subprocess.TimeoutExpired:backend.kill()
 backend=None
def record(kind,**kw):records.append(dict(kind=kind,**kw));(R/'records.json').write_text(json.dumps(records,indent=2));print(kind,flush=True)
def qdiscs():return json.loads(cmd('tc','-j','qdisc','show','dev',DEV))
def egress_filters():return json.loads(cmd('tc','-j','filter','show','dev',DEV,'egress'))
def flowkey(proto,info):
 s=info['sockets'][0];ip='10.79.0.1' if info['family']==4 else 'fd79::1'
 return f"{proto}:{ip}:{s['port']}"
def tree_ticks(root):
 stack=[root];seen=set();own=waited=0
 while stack:
  pid=stack.pop()
  if pid in seen:continue
  seen.add(pid)
  try:
   st=pathlib.Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split()
   own+=int(st[11])+int(st[12]);waited+=int(st[13])+int(st[14])
   for t in pathlib.Path(f'/proc/{pid}/task').glob('*'):
    try:stack.extend(map(int,(t/'children').read_text().split()))
    except FileNotFoundError:pass
  except FileNotFoundError:pass
 return {'self_and_live_ticks':own,'reaped_children_ticks':waited,'total_ticks':own+waited}
def accounting():
 roots={'daemon_tree':backend.pid,'sender_A':senders['A'].pid,'sender_B':senders['B'].pid,'peer':peer.pid,'latency':senders['L'].pid}
 out={n:tree_ticks(pid) for n,pid in roots.items()}
 out['cpu']=list(map(int,pathlib.Path('/proc/stat').read_text().splitlines()[0].split()[1:]))
 return out
def gaps():
 s=status();d=dict(s.get('discovery') or {});d['gap_unsupported_or_shared_discovery']=(s.get('known_gaps') or {}).get('unsupported_or_shared_discovery');d['gap_discovery_failed']=(s.get('known_gaps') or {}).get('discovery_failed');return d
def discovery_counters(g):return dict(g) if g else {}
def verification_counters():
 k=(status().get('kernel') or {});return {a:k.get(a) for a in ('verifications','status_reports','verified_age_ms','verification')}
def snapshot_fields():
 s=status();k=s.get('kernel') or {}
 return {'status':s['status'],'covered':k.get('covered_bindings'),'expired':s.get('coverage_snapshot_expired'),'verification_age_ms':s.get('verification_age_ms'),'verification':s.get('verification'),'valid_for_ms':k.get('valid_for_ms'),'status_reports':k.get('status_reports'),'verifications':k.get('verifications'),'fault':k.get('fault')}
def check_timeline(timeline):
 """Reader-side invariants: while the published kernel sample is unchanged (same status_reports), the derived age never
 decreases and the label never upgrades; an expired coverage snapshot reports covered 0; unknown/stale is never Active."""
 rank={'fresh':0,'stale':1,'unknown':2}
 for a,b in zip(timeline,timeline[1:]):
  if a['status_reports'] is not None and a['status_reports']==b['status_reports'] and a['verification_age_ms'] is not None:
   assert b['verification_age_ms']>=a['verification_age_ms'],(a,b)
   assert rank[b['verification']]>=rank[a['verification']],(a,b)
 for e in timeline:
  if e['expired']:assert e['covered']==0,e
  if e['verification']!='fresh':assert e['status']!='Active',e
assert not os.environ.get('FLOWGATE_PROFILE_DIR')
try:
 peer=launch(['unshare','--net','python3',P/'peer.py'],'peer')
 for _ in range(100):
  if os.readlink(f'/proc/{peer.pid}/ns/net')!=os.readlink('/proc/self/ns/net'):break
  time.sleep(.02)
 cmd('ip','link','set','nsim0','name',DEV);cmd('ip','link','set','nsim1','name','fgpeer')
 cmd('ip','link','set','fgpeer','netns',peer.pid)
 for a in [('link','set','dev',DEV,'addrgenmode','none'),('link','set',DEV,'up'),('addr','add','10.79.0.1/24','dev',DEV),('-6','addr','add','fd79::1/64','dev',DEV,'nodad')]:cmd('ip',*a)
 peerop('setup')
 original=qdiscs()
 feats={l.split(':')[0].strip():l.split(':',1)[1].strip().split()[0] for l in cmd('ethtool','-k',DEV).splitlines() if ':' in l and not l.startswith('Features')}
 record('nic-capabilities',device=DEV,link=json.loads(cmd('ip','-d','-j','link','show','dev',DEV))[0],offloads=feats,qdiscs=original,binaries={b:cmd('sha256sum',P/b).split()[0] for b in ('flowgate-old','flowgate-new')})
 senders={};procs={}
 # A capped bulk, C capped idle (second class), B uncapped bulk, L uncapped low-rate, D denied, X transfer target (alpha).
 for n,exe in [('A','alpha'),('C','gamma'),('B','beta'),('L','beta'),('D','denied'),('X','alpha')]:
  p=launch([P/exe],n);line(p);senders[n]=p;procs[n]=json.loads(cmd(P/'inspect','inspect',p.pid))
 db=sqlite3.connect(R/'rules.db');db.execute('create table rules(id text primary key,document text not null)');db.execute('pragma user_version=1')
 for n in ['A','C','B','D']:
  a=procs[n]['application'];rule={'schema':2,'id':'m0-'+n,'version':1,'created':'2026-01-01T00:00:00Z','action':'block' if n=='D' else 'allow','priority':0,'executable':a['executable'],'filter':{'application':a['key'],'revision':a['revision'],'uid':0,'direction':'outgoing','protocol':'*'}};db.execute('insert into rules values(?,?)',(rule['id'],json.dumps(rule)))
 db.commit();db.close();os.chmod(R/'rules.db',0o600)
 (R/'protection.json').write_text('{"schema":1,"mode":"both"}');os.chmod(R/'protection.json',0o600)
 (R/'session').mkdir(mode=0o711)
 # Bounded discovery and overload, actual daemon and receiver.
 start('flowgate-new','bounded')
 resource.setrlimit(resource.RLIMIT_NOFILE,(8192,8192))
 crowd=[]
 def population(n):
  while len(crowd)>n:crowd.pop().close()
  while len(crowd)<n:
   q=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);q.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEPORT,1);q.bind(('10.79.0.1',45001));crowd.append(q)
 population(1300)
 ainfo=ask(senders['A'],'OPEN 4 1 1 1 0 43003');akey=flowkey('tcp',ainfo)
 ask(senders['D'],'OPEN 4 0 1 1 0')
 t0=time.monotonic();cpu0=tree_ticks(backend.pid)
 configure([cap('A',8000000)])
 found=wait(lambda s:any(b['cookie']==ainfo['sockets'][0]['cookie'] for b in bindings(s)),timeout=60)
 record('existing-socket-found',population=len(crowd),delay_seconds=time.monotonic()-t0,cpu_before=cpu0,cpu_after=tree_ticks(backend.pid),status=found)
 journal=json.loads((R/'controller'/'owner.json').read_text());pin=journal['pin']
 minor=found['kernel']['apps'][appkey('A')]['minor'];classid=f"{journal['major']:x}:{minor:x}"
 def sample():
  classes=json.loads(cmd('tc','-s','-j','class','show','dev',DEV))
  cb=next(c.get('bytes',c.get('stats',{}).get('bytes')) for c in classes if c.get('kind',c.get('class'))=='htb' and c.get('handle',c.get('classid'))==classid)
  return {'t':time.monotonic(),'bytes':peerop('bulk').get(akey,{}).get('bytes',0),'charged':cb,'tree':tree_ticks(backend.pid),'status':status(),'rss':pathlib.Path(f'/proc/{backend.pid}/status').read_text()}
 def measure(label):
  write(senders['A'],f'BULK {label} 16000 65536 0');time.sleep(3)
  a=sample();time.sleep(7);b=sample();dt=b['t']-a['t']
  deny=ask(senders['D'],f'SEND {label} 12 10000');time.sleep(.2);rx=peerop('stats').get(label,{}).get('received',0)
  line(senders['A'])
  charged=(b['charged']-a['charged'])*8/dt/1e6;payload=(b['bytes']-a['bytes'])*8/dt/1e6
  record(label,elapsed=dt,charged_mbit=charged,payload_mbit=payload,deny_sent=deny,deny_received=rx,before=a,after=b)
  assert 6.8<charged<9.2 and payload>6.5 and rx==0,(charged,payload,rx)
  assert b['status']['status']!='Unsupported' and not (b['status'].get('kernel') or {}).get('fault')
  if label=='overload-maintains-cap':
   assert a['status']['discovery']['rows_visited']==b['status']['discovery']['rows_visited']
   assert b['status']['kernel']['existence_queries']==1
   assert b['status']['discovery']['census_errors']>a['status']['discovery']['census_errors']
 measure('within-capacity')
 population(4090)
 near=wait(lambda s:s['discovery_snapshot']['retained_rows']>=4090 and not s['discovery_snapshot']['incomplete'],timeout=60)
 record('near-capacity-snapshot',status=near,daemon_rss=pathlib.Path(f'/proc/{backend.pid}/status').read_text())
 population(4300)
 overloaded=wait(lambda s:s['discovery_snapshot']['overloaded'],timeout=60)
 assert overloaded['status']=='Partial' and len(bindings(overloaded))==1,overloaded
 record('overload-reported',population=len(crowd),status=overloaded)
 measure('overload-maintains-cap')
 population(1300)
 recovered=wait(lambda s:not s['discovery_snapshot']['incomplete'],timeout=60)
 record('population-recovered',status=recovered)
 # Choose a real existing UDP socket beyond row1024 in a fresh inventory.
 # Same-port population stays together; no port shard is used.
 for attempt in range(32):
  cinfo=ask(senders['C'],f'OPEN 4 0 1 1 {46000+attempt}')
  ccookie=cinfo['sockets'][0]['cookie']
  inventory=json.loads(cmd(P/'snapshot'))
  rank=next(i for i,row in enumerate(inventory) if row['cookie']==ccookie)
  if rank>=1024:break
 else:raise AssertionError('fixture could not place target after crowded port')
 t0=time.monotonic();before=status();configure([cap('A',8000000),cap('C',2000000)])
 tail=wait(lambda s:any(b['cookie']==ccookie and b['app']==appkey('C') for b in bindings(s)),timeout=60)
 record('tail-existing-socket-bound',inventory_rows=len(inventory),initial_rank=rank,delay_seconds=time.monotonic()-t0,before=before,after=tail)
 ask(senders['C'],'CLOSE');configure([cap('A',8000000)])
 # Repeated population churn is reflected only on the next complete generation.
 for n in (1350,1250,1400,1300):population(n);time.sleep(1)
 wait(lambda s:s['discovery_snapshot']['pending_rows']==0,timeout=60)
 record('churn-completed',status=status())
 population(0)
 ask(senders['A'],'CLOSE')
 configure([],False)
 # Reuse the established native identity scenarios with the new discovery path.
 assert qdiscs()==original and egress_filters()==[]
 assert not childpids() and not kernel_workers() and not socket_workers()
 ask(senders['B'],'OPEN 4 1 1 1 0 43003')
 configure([cap('A',8000000),cap('C',2000000)]);time.sleep(3)
 g=discovery_counters(gaps());assert (g.get('flows_resolved') or 0)>=1,g
 # (i-a) simultaneous holders: B gives its connected socket to A but keeps its own copy -> ambiguous, must stay unbound.
 ask(senders['A'],'RECV /work/.workspace/m1/xfer.sock');ask(senders['B'],'GIVE /work/.workspace/m1/xfer.sock');xinfo=line(senders['A'])
 xcookie=xinfo['sockets'][0]['cookie'];time.sleep(4)
 assert not any(b['cookie']==xcookie for b in bindings()),bindings()
 record('identity-scm-rights-shared-stays-unbound',cookie=xcookie,discovery=discovery_counters(gaps()))
 # (i-b) exclusive handoff: B closes its copy; A (capped) is now the sole holder -> bound on a later fresh pass.
 t_give=time.monotonic();ask(senders['B'],'CLOSE')
 s=wait(lambda s:any(b['cookie']==xcookie and b['app']==appkey('A') for b in bindings(s)),timeout=60);t_bound=time.monotonic()-t_give
 record('identity-scm-rights-exclusive-rebound',seconds_until_bound=t_bound,cookie=xcookie,discovery=discovery_counters(gaps()))
 ask(senders['A'],'CLOSE')
 # (ii) exec: B (uncapped) execs into the capped alpha image with its socket open: same PID and start, new executable.
 ask(senders['B'],'OPEN 4 1 1 1 0 43003');time.sleep(3)
 bpid=senders['B'].pid;t_exec=time.monotonic();binfo=ask(senders['B'],'EXEC '+str(P/'alpha'));bcookie=binfo['sockets'][0]['cookie']
 assert binfo['pid']==bpid
 s=wait(lambda s:any(b['cookie']==bcookie and b['app']==appkey('A') for b in bindings(s)),timeout=60);t_bound=time.monotonic()-t_exec
 record('identity-exec-rebound',seconds_until_bound=t_bound,cookie=bcookie,pid=bpid,discovery=discovery_counters(gaps()))
 ask(senders['B'],'CLOSE')
 # (iii) new cap for a previously uncapped application: a fresh discovery pass must bind its existing socket within one census pass.
 ask(senders['L'],'OPEN 4 1 1 1 0 43003');linfo=ask(senders['L'],'INFO');lcookie=linfo['sockets'][0]['cookie'];time.sleep(3)
 g0=discovery_counters(gaps());t_cap=time.monotonic();configure([cap('A',8000000),cap('C',2000000),cap('L',1000000)])
 s=wait(lambda s:any(b['cookie']==lcookie and b['app']==appkey('L') for b in bindings(s)),timeout=30);t_bound=time.monotonic()-t_cap
 record('identity-new-cap-bound',seconds_until_bound=t_bound,discovery_before=g0,discovery_after=discovery_counters(gaps()))
 ask(senders['L'],'CLOSE')
 configure([],False);assert qdiscs()==original and egress_filters()==[]
 assert not childpids() and not kernel_workers() and not socket_workers()
 record('cleanup',status=status(),qdiscs=qdiscs(),protection=api()['protection'])
 (R/'success.json').write_text(json.dumps({'result':'BOUNDED_DISCOVERY_CORE_COMPLETE'}))
except BaseException:
 (R/'failure.txt').write_text(traceback.format_exc());print(traceback.format_exc(),flush=True);raise
finally:
 stop()
 for p in reversed(children):
  if p.poll() is None:p.terminate()

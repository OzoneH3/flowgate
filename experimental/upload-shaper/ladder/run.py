# Disposable guest: matched binding-capacity ladder and private diagnostics.
# No host traffic or activation; production binaries unchanged.
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
resource.setrlimit(resource.RLIMIT_NOFILE,(8192,8192))
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
 resource.setrlimit(resource.RLIMIT_NOFILE,(8192,8192))
 start('flowgate-new','ladder')
 holders=[senders['A']]
 for i in range(15):
  q=launch([P/'alpha'],f'holder-{i}');line(q);holders.append(q)
 crowd=[]
 for i in range(1300):
  q=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);q.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEPORT,1);q.bind(('10.79.0.1',45001));crowd.append(q)
 binfo=ask(senders['B'],'OPEN 4 1 1 1 0 43003');bkey=flowkey('tcp',binfo)
 ask(senders['L'],'OPEN 4 1 1 1 0');ask(senders['D'],'OPEN 4 0 1 1 0')
 def sample(keys,pin,classid):
  t=time.monotonic();health=None;hs=he=None
  if pin:
   hs=time.monotonic_ns();health=json.loads(cmd(P/'kernel','health',pin));he=time.monotonic_ns()
  classes=json.loads(cmd('tc','-s','-j','class','show','dev',DEV))
  charged=next((c.get('bytes',c.get('stats',{}).get('bytes')) for c in classes if c.get('kind',c.get('class'))=='htb' and c.get('handle',c.get('classid'))==classid),0)
  bulk=peerop('bulk')
  cpu={'daemon':tree_ticks(backend.pid),'peer':tree_ticks(peer.pid),'low_sender':tree_ticks(senders['L'].pid),'bulk_senders':sum(tree_ticks(q.pid)['total_ticks'] for q in holders+[senders['B']])}
  result={'t':t,'status':status(),'health':health,'health_start_ns':hs,'health_end_ns':he,'charged':charged,'a_payload':sum(bulk.get(k,{}).get('bytes',0) for k in keys),'b_payload':bulk.get(bkey,{}).get('bytes',0),'cpu':cpu,'guest_stat':pathlib.Path('/proc/stat').read_text(),'tcp_snmp':pathlib.Path('/proc/net/snmp').read_text(),'tcp_netstat':pathlib.Path('/proc/net/netstat').read_text(),'qdiscs':json.loads(cmd('tc','-s','-j','qdisc','show','dev',DEV))}
  result['end_t']=time.monotonic();return result
 def phase(label,n,enabled,keys,diagnostic=False):
  assert qdiscs()==original and not childpids() and not socket_workers() and not kernel_workers()
  if diagnostic:
   peerop('traceon');ask(senders['L'],'TRACE 1')
   shutil.copy2(P/'controller-trace.py',P/'controller.py')
  else:
   peerop('traceoff');ask(senders['L'],'TRACE 0')
   shutil.copy2(P/'controller-new.py',P/'controller.py')
  pin=None;classid=None
  if enabled:
   configure([cap('A',8000000)]);full=wait(lambda s:len(bindings(s))==n,timeout=180)
   journal=json.loads((R/'controller'/'owner.json').read_text());pin=journal['pin'];minor=full['kernel']['apps'][appkey('A')]['minor'];classid=f"{journal['major']:x}:{minor:x}"
  else:configure([],False)
  for q in holders:write(q,f'BULK {label} 45000 65536 0')
  write(senders['B'],f'BULK {label} 45000 65536 0')
  time.sleep(3);samples=[sample(keys,pin,classid)];send_results=[];denies=[]
  for i in range(4):
   tag=f'{label}-{i}';send_results.append(ask(senders['L'],f'SEND {tag} 100 50000'))
   denies.append(ask(senders['D'],f'SEND {tag}d 4 10000'))
   samples.append(sample(keys,pin,classid))
  active=all(not select.select([q.stdout],[],[],0)[0] for q in holders+[senders['B']])
  rx=peerop('stats');low=[rx.get(f'{label}-{i}',{}) for i in range(4)];denyrx=sum(rx.get(f'{label}-{i}d',{}).get('received',0) for i in range(4))
  a,b=samples[0],samples[-1];dt=b['t']-a['t'];payload=(b['a_payload']-a['a_payload'])*8/dt/1e6;charged=(b['charged']-a['charged'])*8/dt/1e6
  bulk_results=[line(q,timeout=50) for q in holders+[senders['B']]]
  record('phase',label=label,bindings=n if enabled else 0,socket_population=n,bulk_active=16,diagnostic=diagnostic,enabled=enabled,elapsed=dt,samples=samples,lowrate=low,low_send=send_results,deny_send=denies,deny_received=denyrx,bulk_results=bulk_results,bulk_running_at_end=active,charged_mbit=charged,payload_mbit=payload,b_mbit=(b['b_payload']-a['b_payload'])*8/dt/1e6,daemon_tree_ticks_per_second=(b['cpu']['daemon']['total_ticks']-a['cpu']['daemon']['total_ticks'])/dt)
  assert active,'underfed window'
  # Retain complete ladder even if a performance criterion fails. Correctness
  # failures abort after evidence publication; latency gates computed afterward.
  assert all(x.get('received')==100 for x in low) and denyrx==0
  if enabled:
   assert all(len(x['health']['bindings'])==n for x in samples)
   assert all(min([x['health']['config_until']]+[z['until'] for z in x['health']['bindings']])>x['health_end_ns'] for x in samples)
   assert 7.2<charged<8.8 and payload>6.5,(label,charged,payload)
  configure([],False)
  assert qdiscs()==original and egress_filters()==[] and not childpids() and not socket_workers() and not kernel_workers()
  record('cleanup',label=label,status=status(),protection=api()['protection']);peerop('reset')
 for n in (32,64,128):
  infos=[ask(q,f'OPEN 4 1 {n//16} 1 0 43003') for q in holders]
  assert sum(len(x['sockets']) for x in infos)==n
  keys=['tcp:10.79.0.1:'+str(x['sockets'][0]['port']) for x in infos]
  for suffix,on in [('d1',False),('e1',True),('e2',True),('d2',False)]:phase(f'n{n}{suffix}',n,on,keys)
 for suffix,on in [('d',False),('e',True)]:phase('diag'+suffix,128,on,keys,True)
 record('final-cleanup',status=status(),qdiscs=qdiscs(),protection=api()['protection'])
 (R/'success.json').write_text(json.dumps({'result':'LADDER_COMPLETE','note':'latency/maintenance gates evaluated separately, no performance pass implied'}))
except BaseException:
 (R/'failure.txt').write_text(traceback.format_exc());print(traceback.format_exc(),flush=True);raise
finally:
 stop()
 for q in reversed(children):
  if q.poll() is None:q.terminate()

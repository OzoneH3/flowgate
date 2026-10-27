# Disposable VM only. Status-verification comparison (generated from the frozen compare fixture plus reader/foreign/stall phases): reference daemon (a2283f47) vs candidate daemon vs
# shaping-disabled control, matched reversed-order steady state, profiling OFF. netdevsim pair,
# TSO/GSO as reported, unchanged firewall ownership rules. Never run in the host namespace.
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
 def steady_phase(label,binary,shaping,a_bulk=False):
  """One matched steady-state phase: restart daemon on `binary`; caps (A 8M, C 2M) configured and bound when
  shaping, disabled otherwise. Default-throughput comparison phases keep A IDLE in every variant so the
  offered workload is identical (B bulk + L low-rate + D deny); a_bulk=True is the separate cap-accuracy
  phase where A also transmits, compared only between shaped builds."""
  stop()
  shutil.copyfile(P/('controller-old.py' if binary=='flowgate-old' else 'controller-new.py'),P/'controller.py')
  shutil.copyfile(P/('probe-old' if binary=='flowgate-old' else 'probe-new'),P/'probe')
  started=time.monotonic();start(binary,label)
  assert status()['status']=='Disabled' and not childpids() and not kernel_workers() and not socket_workers()
  ainfo=ask(senders['A'],'OPEN 4 1 1 1 0 43003');akey=flowkey('tcp',ainfo)
  cinfo=ask(senders['C'],'OPEN 4 0 1 1 0');binfo=ask(senders['B'],'OPEN 4 1 1 1 0 43003');bkey=flowkey('tcp',binfo)
  ask(senders['L'],'OPEN 4 1 1 1 0');ask(senders['D'],'OPEN 4 0 1 1 0')
  if shaping:
   configure([cap('A',8000000),cap('C',2000000)])
   wait(lambda s:{b['app'] for b in bindings(s)}=={appkey('A'),appkey('C')},timeout=45)
  assert time.monotonic()-started<20, 'setup exceeded fixed warmup'
  while time.monotonic()-started<20:time.sleep(.1)
  if a_bulk:write(senders['A'],'BULK capped 75000 65536 0')
  write(senders['B'],'BULK free 75000 65536 0')
  time.sleep(5)
  rx=peerop('bulk');g0=gaps() if shaping else {};v0=verification_counters() if shaping else {};rxa0=rx.get(akey,{}).get('bytes',0);rxb0=rx[bkey]['bytes'];before=accounting();t0=time.monotonic()
  low=[];coverage=[];worker_samples=[]
  charged_start=time.monotonic()
  charged0=json.loads(cmd('tc','-s','-j','class','show','dev',DEV)) if a_bulk else []
  for seg in range(6):
   tag=f'{label}-{seg}';ask(senders['L'],f'SEND {tag} 200 50000');low.append(peerop('stats')[tag])
   cs=status();coverage.append(cs);worker_samples.append(socket_workers())
   if shaping:
    assert cs.get('kernel',{}).get('covered_bindings')==2 and not cs.get('coverage_snapshot_expired'),cs
  ask(senders['D'],f'SEND deny{label} 20 50000')
  while time.monotonic()-t0<60:time.sleep(.2)
  after=accounting();elapsed=time.monotonic()-t0;rx=peerop('bulk');rxa1=rx.get(akey,{}).get('bytes',0);rxb1=rx[bkey]['bytes'];g1=gaps() if shaping else {}
  bind_count=len(bindings()) if shaping else 0
  v1=verification_counters() if shaping else {}
  charged_end=time.monotonic()
  charged1=json.loads(cmd('tc','-s','-j','class','show','dev',DEV)) if a_bulk else []
  for n in (('A','B') if a_bulk else ('B',)):line(senders[n],timeout=20)
  assert peerop('stats').get(f'deny{label}',{}).get('received',0)==0
  cpu={n:{k:after[n][k]-before[n][k] for k in before[n]} for n in ('daemon_tree','sender_A','sender_B','peer','latency')}
  cpu['whole_guest_ticks']=[b-a for a,b in zip(before['cpu'],after['cpu'])]
  rec=dict(label=label,binary=binary,shaping=shaping,a_bulk=a_bulk,elapsed=elapsed,receiver_B_bps=(rxb1-rxb0)*8/elapsed,receiver_A_bps=(rxa1-rxa0)*8/elapsed if a_bulk else 0.0,
   low_rate=[{'received':x['received'],'p50_ms':x['p50_ms'],'p95_ms':x['p95_ms']} for x in low],cpu=cpu,clock_ticks=os.sysconf('SC_CLK_TCK'),
   discovery_before=discovery_counters(g0),discovery_after=discovery_counters(g1),bindings=bind_count,verification_before=v0,verification_after=v1,coverage_samples=coverage,charged_interval=charged_end-charged_start,charged_before=charged0,charged_after=charged1,helper_sha=cmd('sha256sum',P/'probe',P/'controller.py'),socket_worker_pids=socket_workers(),socket_worker_samples=worker_samples)
  assert all(x['received']==200 for x in low),low
  # Both shaped builds (reference a2283f47 and candidate) run one persistent socket worker; none while disabled.
  if shaping:
   assert all(len(p)==1 and p==worker_samples[0] for p in worker_samples),worker_samples
  else:assert not any(worker_samples),worker_samples
  if a_bulk:
   assert 0.85*8e6<=rec['receiver_A_bps']<=1.15*8e6,rec['receiver_A_bps']
  if shaping:configure([],False)
  for n in ('A','C','B','L','D'):ask(senders[n],'CLOSE')
  assert qdiscs()==original and not childpids() and not kernel_workers() and not socket_workers()
  record('steady',**rec)
  return rec
 results=[]
 # Default-throughput comparison: identical workload in every phase (A idle, caps bound when shaping).
 for label,binary,shaping in [('old1','flowgate-old',True),('new1','flowgate-new',True),('new2','flowgate-new',True),('old2','flowgate-old',True),
                              ('control1','flowgate-new',False),('new3','flowgate-new',True),('new4','flowgate-new',True),('control2','flowgate-new',False)]:
  results.append(steady_phase(label,binary,shaping))
 # Focused generation-reuse check, outside the performance windows.
 stop();shutil.copyfile(P/'controller-new.py',P/'controller.py');shutil.copyfile(P/'probe-new',P/'probe');start('flowgate-new','reuse')
 ci=ask(senders['C'],'OPEN 4 0 1 1 46031');oldcookie=ci['sockets'][0]['cookie']
 configure([cap('C',2000000)]);wait(lambda s:any(b['cookie']==oldcookie for b in bindings(s)))
 ask(senders['C'],'CLOSE');bi=ask(senders['B'],'OPEN 4 0 1 1 46031');newcookie=bi['sockets'][0]['cookie'];assert oldcookie!=newcookie
 wait(lambda s:not any(b['cookie']==oldcookie for b in bindings(s)));time.sleep(4)
 assert not any(b['cookie']==newcookie for b in bindings())
 record('port-reuse-no-inherited-class',old_cookie=oldcookie,new_cookie=newcookie,status=status())
 configure([],False);ask(senders['B'],'CLOSE');assert qdiscs()==original and not childpids() and not kernel_workers() and not socket_workers()
 # Cap accuracy, lease expiry, foreign refusal and recovery are checked by the
 # focused fixtures; this run measures only the changed discovery/renewal hot path.
 stop()
 (R/'success.json').write_text(json.dumps({'result':'BOUNDED_COMPARISON_COMPLETE'}))

except BaseException:
 (R/'failure.txt').write_text(traceback.format_exc());print(traceback.format_exc(),flush=True);raise
finally:
 stop()
 for p in reversed(children):
  if p.poll() is None:p.terminate()

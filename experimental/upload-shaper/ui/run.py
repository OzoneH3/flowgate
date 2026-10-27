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
 args=[P/binary,'serve','--socket',API,'--database',R/'rules.db','--uid','0','--administrator','--allow-protection','--protection-state',R/'protection.json','--evaluation-state',R/'session'/'evaluation','--decision-timeout','2s','--experimental-upload-interface',DEV,'--experimental-upload-helpers',P,'--experimental-upload-state',R/'controller','--experimental-upload-host-trial']
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
 start('flowgate-new','ui-journey')
 ainfo=ask(senders['A'],'OPEN 4 1 1 1 0 43003');akey=flowkey('tcp',ainfo)
 ask(senders['D'],'OPEN 4 0 1 0 0')
 # Create real attributed activity before the UI selects its native target.
 write(senders['A'],'BULK warmup 1500 65536 0');line(senders['A'])
 initial_rules=api().get('rules',[])
 assert len(initial_rules)==4 and {r['id'] for r in initial_rules}=={'m0-A','m0-B','m0-C','m0-D'}
 jobs={};job_lock=threading.Lock();finished=threading.Event()
 def measure(label):
  try:
   before_rules=api().get('rules',[])
   write(senders['A'],f'BULK {label} 10000 65536 0');time.sleep(2)
   start=time.monotonic();before=peerop('bulk').get(akey,{}).get('bytes',0)
   time.sleep(4)
   end=time.monotonic();after=peerop('bulk').get(akey,{}).get('bytes',0)
   sent=line(senders['A'],timeout=20)
   deny=ask(senders['D'],f'SEND {label}d 8 50000');rx=peerop('stats').get(label+'d',{}).get('received',0)
   result={'elapsed':end-start,'receiver_payload_mbit':(after-before)*8/(end-start)/1e6,'send':sent,'deny_send':deny,'deny_receiver':rx,'status':status(),'rules_unchanged':api().get('rules',[])==initial_rules==before_rules,'qdiscs':qdiscs(),'protection':api()['protection']}
   record('receiver',label=label,**result);jobs[label]=result
  except BaseException:jobs[label]={'error':traceback.format_exc()}
 def fixture(req):
  op=req.get('operation')
  if op=='ready':return {'ready':True,'application':procs['A']['application'],'pid':senders['A'].pid,'generation':GEN,'status':status(),'rules':initial_rules}
  if op=='measure':
   label=req['label'];assert label in ('set8','edit16','disabled') and label not in jobs
   assert not any(v is None for v in jobs.values())
   jobs[label]=None;threading.Thread(target=measure,args=(label,),daemon=True).start();return {'started':label}
  if op=='result':return {'result':jobs.get(req['label'])}
  if op=='finish':
   assert not any(v is None for v in jobs.values())
   assert status()['status']=='Disabled' and not childpids() and not socket_workers() and not kernel_workers()
   assert qdiscs()==original and not egress_filters()
   assert api().get('rules',[])==initial_rules
   assert set(jobs)=={'set8','edit16','disabled'}
   assert 6.5<jobs['set8']['receiver_payload_mbit']<8.6
   assert 13<jobs['edit16']['receiver_payload_mbit']<17.2
   assert jobs['disabled']['receiver_payload_mbit']>24
   assert all(v['deny_receiver']==0 and v['rules_unchanged'] for v in jobs.values())
   record('final-cleanup',status=status(),qdiscs=qdiscs(),rules_unchanged=True)
   (R/'success.json').write_text(json.dumps({'result':'REAL_UI_RECEIVER_JOURNEY_COMPLETE'}));finished.set();return {'finished':True}
  raise ValueError('unknown fixture operation')
 # Bounded private guest bridge. UI requests still use the real Unix API with
 # root peer credentials; this does not prove host GUI peer-auth deployment.
 ports=[p.name for p in pathlib.Path('/sys/class/virtio-ports').glob('*') if (p/'name').read_text().strip()=='org.flowgate.ui']
 assert len(ports)==1,ports
 print('UI_READY',flush=True)
 fd=os.open('/dev/'+ports[0],os.O_RDWR)
 with os.fdopen(fd,'r+b',buffering=0) as wire:
  while not finished.is_set():
   frame=wire.readline(2*1024*1024+1)
   if not frame:break
   try:
    assert len(frame)<=2*1024*1024 and frame.endswith(b'\n')
    msg=json.loads(frame);endpoint=msg['endpoint'];req=msg['request']
    if endpoint=='fixture':response=fixture(req)
    else:
     assert endpoint in ('control','monitor')
     with socket.socket(socket.AF_UNIX) as api_sock:
      api_sock.settimeout(4);api_sock.connect(str(API)+('.monitor' if endpoint=='monitor' else ''))
      api_sock.sendall(json.dumps(req).encode()+b'\n');response=json.loads(api_sock.makefile('rb').readline(4*1024*1024))
   except BaseException:response={'fixture_error':traceback.format_exc()}
   data=memoryview(json.dumps(response).encode()+b'\n')
   while data:data=data[os.write(wire.fileno(),data):]
 assert finished.is_set(),'UI journey ended without completion'
except BaseException:
 (R/'failure.txt').write_text(traceback.format_exc());print(traceback.format_exc(),flush=True);raise
finally:
 stop()
 for q in reversed(children):
  if q.poll() is None:q.terminate()

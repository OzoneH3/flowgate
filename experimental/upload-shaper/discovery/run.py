# Disposable VM only. Discovery-overhead comparison: old daemon (834debf) vs candidate daemon vs
# shaping-disabled control, matched reversed-order steady state, profiling OFF. netdevsim pair,
# TSO/GSO as reported, unchanged firewall ownership rules. Never run in the host namespace.
import os,sys,json,socket,subprocess,time,pathlib,sqlite3,select,traceback,shutil
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
  stop();start(binary,label)
  assert status()['status']=='Disabled' and not childpids() and not kernel_workers()
  ainfo=ask(senders['A'],'OPEN 4 1 1 1 0 43003');akey=flowkey('tcp',ainfo)
  cinfo=ask(senders['C'],'OPEN 4 0 1 1 0');binfo=ask(senders['B'],'OPEN 4 1 1 1 0 43003');bkey=flowkey('tcp',binfo)
  ask(senders['L'],'OPEN 4 1 1 1 0');ask(senders['D'],'OPEN 4 0 1 1 0')
  if shaping:
   configure([cap('A',8000000),cap('C',2000000)])
   wait(lambda s:{b['app'] for b in bindings(s)}=={appkey('A'),appkey('C')},timeout=45)
  if a_bulk:write(senders['A'],'BULK capped 40000 65536 0')
  write(senders['B'],'BULK free 40000 65536 0')
  time.sleep(5)
  rx=peerop('bulk');g0=gaps() if shaping else {};rxa0=rx.get(akey,{}).get('bytes',0);rxb0=rx[bkey]['bytes'];before=accounting();t0=time.monotonic()
  low=[]
  for seg in range(3):
   tag=f'{label}-{seg}';ask(senders['L'],f'SEND {tag} 200 50000');low.append(peerop('stats')[tag])
  ask(senders['D'],f'SEND deny{label} 20 50000')
  while time.monotonic()-t0<30:time.sleep(.2)
  after=accounting();elapsed=time.monotonic()-t0;rx=peerop('bulk');rxa1=rx.get(akey,{}).get('bytes',0);rxb1=rx[bkey]['bytes'];g1=gaps() if shaping else {}
  bind_count=len(bindings()) if shaping else 0
  for n in (('A','B') if a_bulk else ('B',)):line(senders[n],timeout=20)
  assert peerop('stats').get(f'deny{label}',{}).get('received',0)==0
  cpu={n:{k:after[n][k]-before[n][k] for k in before[n]} for n in ('daemon_tree','sender_A','sender_B','peer','latency')}
  cpu['whole_guest_ticks']=[b-a for a,b in zip(before['cpu'],after['cpu'])]
  rec=dict(label=label,binary=binary,shaping=shaping,a_bulk=a_bulk,elapsed=elapsed,receiver_B_bps=(rxb1-rxb0)*8/elapsed,receiver_A_bps=(rxa1-rxa0)*8/elapsed if a_bulk else 0.0,
   low_rate=[{'received':x['received'],'p50_ms':x['p50_ms'],'p95_ms':x['p95_ms']} for x in low],cpu=cpu,clock_ticks=os.sysconf('SC_CLK_TCK'),
   discovery_before=discovery_counters(g0),discovery_after=discovery_counters(g1),bindings=bind_count)
  assert all(x['received']==200 for x in low),low
  if a_bulk:
   assert 0.85*8e6<=rec['receiver_A_bps']<=1.15*8e6,rec['receiver_A_bps']
  if shaping:configure([],False)
  for n in ('A','C','B','L','D'):ask(senders[n],'CLOSE')
  assert qdiscs()==original and not childpids() and not kernel_workers()
  record('steady',**rec)
  return rec
 results=[]
 # Default-throughput comparison: identical workload in every phase (A idle, caps bound when shaping).
 for label,binary,shaping in [('old1','flowgate-old',True),('new1','flowgate-new',True),('new2','flowgate-new',True),('old2','flowgate-old',True),
                              ('control1','flowgate-new',False),('new3','flowgate-new',True),('new4','flowgate-new',True),('control2','flowgate-new',False)]:
  results.append(steady_phase(label,binary,shaping))
 # Separate cap-accuracy phases with A transmitting (shaped builds only).
 for label,binary in [('capload-old','flowgate-old'),('capload-new','flowgate-new')]:
  results.append(steady_phase(label,binary,True,a_bulk=True))
 # Identity-change tests on the candidate: a cached negative verdict must not outlive its bound.
 stop();start('flowgate-new','identity')
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
 # (iii) new cap for a previously uncapped application: the verdict flush must bind its existing socket within one census pass.
 ask(senders['L'],'OPEN 4 1 1 1 0 43003');linfo=ask(senders['L'],'INFO');lcookie=linfo['sockets'][0]['cookie'];time.sleep(3)
 g0=discovery_counters(gaps());t_cap=time.monotonic();configure([cap('A',8000000),cap('C',2000000),cap('L',1000000)])
 s=wait(lambda s:any(b['cookie']==lcookie and b['app']==appkey('L') for b in bindings(s)),timeout=30);t_bound=time.monotonic()-t_cap
 record('identity-new-cap-bound',seconds_until_bound=t_bound,discovery_before=g0,discovery_after=discovery_counters(gaps()))
 ask(senders['L'],'CLOSE')
 # Bounded failure, Deny, owned cleanup, zero workers when disabled.
 kp=kernel_workers();assert len(kp)==1,kp;os.kill(kp[0],9)
 deadline=time.monotonic()+10
 while status()['status']!='Unsupported' and time.monotonic()<deadline:time.sleep(.1)
 assert status()['status']=='Unsupported'
 configure([],False);assert qdiscs()==original and not childpids() and not kernel_workers()
 ask(senders['D'],'OPEN 4 0 1 1 0');ask(senders['D'],'SEND denyfinal 12 10000');time.sleep(.3)
 assert peerop('stats').get('denyfinal',{}).get('received',0)==0
 time.sleep(2);assert status()['status']=='Disabled' and not childpids() and not kernel_workers()
 record('bounded-failure-deny-cleanup-disabled',qdiscs=qdiscs(),protection=api()['protection'])
 (R/'success.json').write_text(json.dumps({'result':'DISCOVERY_COMPARISON_COMPLETE'}));print('INTEGRATION_PROOF_COMPLETE',flush=True)
except BaseException:
 (R/'failure.txt').write_text(traceback.format_exc());print(traceback.format_exc(),flush=True);raise
finally:
 stop()
 for p in reversed(children):
  if p.poll() is None:p.terminate()

# Disposable VM only: default-path cost isolation on a netdevsim pair (TSO/GSO on),
# actual serve API, unchanged firewall ownership rules. Never run in the host namespace.
import os,sys,json,socket,subprocess,time,pathlib,sqlite3,select,traceback
P=pathlib.Path('/work/m1');R=pathlib.Path('/work/.workspace/m1');R.mkdir(mode=0o700,exist_ok=True);API=R/'session'/'api.sock';children=[];records=[];backend=None
assert os.environ.get('FLOWGATE_PARENT_NETNS') and os.environ['FLOWGATE_PARENT_NETNS']!=os.readlink('/proc/self/ns/net')
DEV='fghost'
def cmd(*a):return subprocess.check_output([str(x) for x in a],text=True,timeout=20)
def launch(args,name):
 p=subprocess.Popen([str(x) for x in args],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=(R/(name+'.err')).open('w'),text=True,bufsize=1);children.append(p);return p
def line(p,timeout=25):
 if not select.select([p.stdout],[],[],timeout)[0]:raise RuntimeError('fixture timeout '+str(p.pid))
 s=p.stdout.readline()
 if not s:raise RuntimeError('fixture exited '+str(p.pid))
 return json.loads(s)
def write(p,s):p.stdin.write(s+'\n');p.stdin.flush()
def ask(p,s):write(p,s);return line(p)
def peerop(op):return ask(peer,json.dumps({'op':op}))
def request(op='list',ro=False,lost=False,**kw):
 with socket.socket(socket.AF_UNIX) as s:
  s.settimeout(4);s.connect(str(API)+('.monitor' if ro else ''));s.sendall((json.dumps(dict(version=1,operation=op,**kw))+'\n').encode())
  if lost:return
  return json.loads(s.makefile('rb').readline())
def api(op='list',**kw):
 d=request(op,**kw);assert not d.get('error'),d;return d
GEN=''
def status():return api('upload-status',generation=GEN)['upload_shaping']
def wait(pred,timeout=35):
 until=time.monotonic()+timeout
 while time.monotonic()<until:
  s=status()
  if s['status']=='Unsupported':raise RuntimeError('shaping fault '+json.dumps(s))
  if pred(s):return s
  time.sleep(.3)
 raise RuntimeError('wait timeout '+json.dumps(s))
def configure(caps=None,enabled=True,**kw):
 before=status();r=api('upload-configure',generation=GEN,expected_version=before['version'],upload_config={'enabled':enabled,'caps':caps or []},**kw)['upload_shaping'];assert r['version']==before['version']+1
 return wait(lambda s:s['applied_version']==r['version'])
def cap(name,rate):return {'uid':0,'application':procs[name]['application']['key'],'bits_per_second':rate}
def childpids():
 pids=set()
 for task in pathlib.Path(f'/proc/{backend.pid}/task').glob('*'):
  try:pids.update((task/'children').read_text().split())
  except FileNotFoundError:pass
 result=[]
 for pid in pids:
  try:
   if b'controller.py' in pathlib.Path('/proc/'+pid+'/cmdline').read_bytes():result.append(pid)
  except FileNotFoundError:pass
 return result
def start(name):
 global backend,GEN
 args=[P/'flowgate','serve','--socket',API,'--database',R/'rules.db','--uid','0','--administrator','--allow-protection','--protection-state',R/'protection.json','--evaluation-state',R/'session'/'evaluation','--decision-timeout','2s','--experimental-upload-interface',DEV,'--experimental-upload-helpers',P,'--experimental-upload-state',R/'controller','--experimental-upload-parent-netns',os.environ['FLOWGATE_PARENT_NETNS']]
 backend=launch(args,name)
 for _ in range(200):
  try:
   s=api()
   if s.get('protection',{}).get('state')=='active':GEN=s['generation'];return s
  except (FileNotFoundError,ConnectionRefusedError,AssertionError):pass
  if backend.poll() is not None:raise RuntimeError('daemon exited '+str(backend.returncode))
  time.sleep(.1)
 raise RuntimeError('not ready')
def record(kind,**kw):records.append(dict(kind=kind,**kw));(R/'records.json').write_text(json.dumps(records,indent=2));print(kind,flush=True)
def qdiscs():return json.loads(cmd('tc','-j','qdisc','show','dev',DEV))
def classes_stats():return json.loads(cmd('tc','-s','-j','class','show','dev',DEV))
def qdisc_stats():return json.loads(cmd('tc','-s','-j','qdisc','show','dev',DEV))
def class_bytes(stats,classid):
 for c in stats:
  if c.get('handle')==classid:return c.get('stats',{}).get('bytes',c.get('bytes',0))
 return None
def leaf_stats(stats,minor):
 for q in stats:
  if q.get('kind')=='fq_codel' and q.get('handle')==f'{minor:x}:':return q
 return None
def flowkey(proto,info):
 s=info['sockets'][0];ip='10.79.0.1' if info['family']==4 else 'fd79::1'
 return f"{proto}:{ip}:{s['port']}"
def counters():
 k=status()['kernel'];return k['counters'],k.get('segmentation')
def sample(app_minor):
 cs=classes_stats();qs=qdisc_stats();c,seg=counters();rx=peerop('bulk')
 return {'t':time.monotonic(),'class_bytes':class_bytes(cs,f'{journal_major:x}:{app_minor:x}') if app_minor else None,'leaf':leaf_stats(qs,app_minor) if app_minor else None,'classifier':c,'segmentation':seg,'rx':rx}
def rate_of(a,b,key):
 return (b[key]-a[key])/(b['t']-a['t']) if b['t']>a['t'] else None
def measure(label,sender,bulk,rate,app_minor,rxkey,seconds):
 """Sustained interval: per-second samples of HTB class bytes, classifier/GSO counters, leaf queue stats and receiver bytes."""
 pre=sample(app_minor);write(sender,bulk);samples=[pre];t_end=time.monotonic()+seconds
 while time.monotonic()<t_end:
  time.sleep(1.0);samples.append(sample(app_minor))
 result=line(sender,timeout=30);time.sleep(.5);post=sample(app_minor)
 def rxb(s):return s['rx'].get(rxkey,{}).get('bytes',0)
 steady=[s for s in samples[1:]]  # exclude pre; first interval includes the token burst
 cls=[(steady[i]['class_bytes']-steady[i-1]['class_bytes'])/(steady[i]['t']-steady[i-1]['t']) for i in range(2,len(steady)) if steady[i]['class_bytes'] is not None and steady[i-1]['class_bytes'] is not None]
 rxs=[(rxb(steady[i])-rxb(steady[i-1]))/(steady[i]['t']-steady[i-1]['t']) for i in range(2,len(steady))]
 total_t=post['t']-pre['t']
 out={'label':label,'rate_bps':rate,'seconds':seconds,'sender':result,
  'class_total_bytes':(post['class_bytes']-pre['class_bytes']) if app_minor else None,
  'classifier_total_bytes':post['classifier'][1]['bytes']-pre['classifier'][1]['bytes'],
  'classifier_total_packets':post['classifier'][1]['packets']-pre['classifier'][1]['packets'],
  'receiver_total_bytes':rxb(post)-rxb(pre),'interval_s':total_t,
  'steady_class_bps':sorted(cls)[len(cls)//2]*8 if cls else None,'steady_class_bps_series':[round(x*8) for x in cls],
  'steady_receiver_bps_series':[round(x*8) for x in rxs],
  'gso_superpackets_classified':post['classifier'][2]['packets']-pre['classifier'][2]['packets'],
  'gso_superpacket_bytes_classified':post['classifier'][2]['bytes']-pre['classifier'][2]['bytes'],
  'gso_segments_classified':post['classifier'][4]['packets']-pre['classifier'][4]['packets'],
  'gso_superpackets_unbound':post['classifier'][3]['packets']-pre['classifier'][3]['packets'],
  'leaf_before':pre['leaf'],'leaf_after':post['leaf'],
  'leaf_peak_memory_used':max([s['leaf'].get('memory_used',0) for s in samples+[post] if s['leaf']] or [0]),
  'leaf_peak_backlog':max([s['leaf'].get('backlog',0) for s in samples+[post] if s['leaf']] or [0]),
  'leaf_peak_qlen':max([s['leaf'].get('qlen',0) for s in samples+[post] if s['leaf']] or [0]),
  'leaf_drops':(post['leaf'].get('drops',0)-pre['leaf'].get('drops',0)) if pre['leaf'] and post['leaf'] else None,
  'samples':samples+[post]}
 if rate and app_minor:
  expected=rate/8*total_t
  out['class_accuracy']=out['class_total_bytes']/expected
  out['steady_accuracy']=out['steady_class_bps']/rate if out['steady_class_bps'] else None
  out['allowance_bytes']=65536
 return out
def wrapper_interrupt(match):
 w=R/'interrupt.py'
 w.write_text("import sys,os,types\nsys.path.insert(0,'/work/m1')\nimport controller\nclass Interrupted(controller.Controller):\n def call(self,*args):\n  out=super().call(*args)\n  if args[:%d]==%r: os._exit(77)\n  return out\nInterrupted(types.SimpleNamespace(interface=%r,helpers='/work/m1',state='/work/.workspace/m1/controller',lab_parent_netns=os.environ['FLOWGATE_PARENT_NETNS'],cleanup_only=False))\n"%(len(match),match,DEV))
 r=subprocess.run(['python3','-I',str(w)],capture_output=True,text=True,timeout=30)
 assert r.returncode==77,(r.returncode,r.stdout,r.stderr)
journal_major=None
gates={}
def cpu_ticks():
 out={}
 procs_=[('peer',peer.pid)]+[('sender_'+n,p.pid) for n,p in senders.items()]
 if backend is not None:procs_+=[('daemon',backend.pid)]+[('controller_'+c,int(c)) for c in childpids()]
 for name,pid in procs_:
  try:
   st=pathlib.Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split();out[name]=int(st[11])+int(st[12])
  except (FileNotFoundError,IndexError):pass
 total=pathlib.Path('/proc/stat').read_text().splitlines()[0].split()[1:];out['_all']=sum(int(x) for x in total);out['_idle']=int(total[3])
 return out
def cpu_delta(a,b):return {k:b.get(k,0)-a.get(k,0) for k in set(a)|set(b)}
def efficiency(rx,cpu):
 # payload bytes per CPU tick spent by the bulk sender and the receiver: datapath cost independent of CPU share
 ticks=cpu.get('sender_B',0)+cpu.get('peer',0);return rx['bytes']/ticks if ticks else None
try:
 peer=launch(['unshare','--net','python3',P/'peer.py'],'peer')
 for _ in range(100):
  if os.readlink(f'/proc/{peer.pid}/ns/net')!=os.readlink('/proc/self/ns/net'):break
  time.sleep(.02)
 cmd('ip','link','set','nsim0','name',DEV);cmd('ip','link','set','nsim1','name','fgpeer')
 # Offloads are left exactly as the device reports them: nothing is switched on or off.
 cmd('ip','link','set','fgpeer','netns',peer.pid)
 for a in [('link','set','dev',DEV,'addrgenmode','none'),('link','set',DEV,'up'),('addr','add','10.79.0.1/24','dev',DEV),('-6','addr','add','fd79::1/64','dev',DEV,'nodad')]:cmd('ip',*a)
 peerop('setup')
 original=qdiscs()
 link=json.loads(cmd('ip','-d','-j','link','show','dev',DEV))[0]
 record('nic-capabilities',device=DEV,default_sysctl_exists=pathlib.Path('/proc/sys/net/core/default_qdisc').exists(),link=link,offloads=cmd('ethtool','-k',DEV),qdiscs=original,
  virtio_hub_offloads=cmd('ethtool','-k','eth0'),virtio_hub_link=json.loads(cmd('ip','-d','-j','link','show','dev','eth0'))[0])
 feats={l.split(':')[0].strip():l.split(':',1)[1].strip().split()[0] for l in cmd('ethtool','-k',DEV).splitlines() if ':' in l and not l.startswith('Features')}
 assert feats['tcp-segmentation-offload']=='on' and feats['generic-segmentation-offload']=='on' and feats['scatter-gather']=='on',feats
 assert original[0]['kind']=='fq_codel' and original[0]['handle']=='0:',original
 senders={};procs={}
 for n,exe in [('A','alpha'),('A2','alpha'),('B','beta'),('D','denied')]:
  p=launch([P/exe],n);line(p);senders[n]=p;procs[n]=json.loads(cmd(P/'inspect','inspect',p.pid))
 db=sqlite3.connect(R/'rules.db');db.execute('create table rules(id text primary key,document text not null)');db.execute('pragma user_version=1')
 for n in ['A','B','D']:
  a=procs[n]['application'];rule={'schema':2,'id':'m0-'+n,'version':1,'created':'2026-01-01T00:00:00Z','action':'block' if n=='D' else 'allow','priority':0,'executable':a['executable'],'filter':{'application':a['key'],'revision':a['revision'],'uid':0,'direction':'outgoing','protocol':'*'}};db.execute('insert into rules values(?,?)',(rule['id'],json.dumps(rule)))
 db.commit();db.close();os.chmod(R/'rules.db',0o600)
 (R/'protection.json').write_text('{"schema":1,"mode":"both"}');os.chmod(R/'protection.json',0o600)
 (R/'session').mkdir(mode=0o711)

 start('serve');assert status()['status']=='Disabled'
 import types
 sys.path.insert(0,str(P));import controller
 static=None
 latency=launch([P/'beta'],'latency');line(latency);senders['L']=latency
 def accounting():
  # Self and reaped-child times; include live descendants separately. No sampled
  # short-lived process can disappear from the cumulative waited-child total.
  roots={'daemon':backend.pid,'sender':senders['B'].pid,'peer':peer.pid,'latency':latency.pid}
  result={}
  for name,root in roots.items():
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
   result[name]={'self_and_live_ticks':own,'reaped_children_ticks':waited,'total_ticks':own+waited}
  result['cpu']=list(map(int,pathlib.Path('/proc/stat').read_text().splitlines()[0].split()[1:]))
  return result
 def setup(variant):
  global static
  if variant in (2,3):
   static=controller.Controller(types.SimpleNamespace(interface=DEV,helpers=str(P),state=str(R/'static'),lab_parent_netns=os.environ['FLOWGATE_PARENT_NETNS'],cleanup_only=False))
   if variant==2:static.mutate('filter','del','dev',DEV,'egress','pref','10000','handle','1','bpf')
   assert not static.bindings
  elif variant==5:
   configure([])
  elif variant==4:
   ask(senders['A'],'OPEN 4 0 1 1 0')
   configure([cap('A',8000000)]);wait(lambda s:len((s.get('kernel') or {}).get('bindings',[]))==1)
  assert api()['protection']['state']=='active'
 def teardown(variant):
  global static
  if static:static.close();os.close(static.lock);static=None
  if variant in (4,5):configure([],False)
  if variant==4:ask(senders['A'],'CLOSE')
  assert qdiscs()==original
 mode=os.environ.get('FLOWGATE_DEFAULT_COST_MODE','candidate')
 schedules={'isolation':[1,2,3,4,4,3,2,1], 'split':[3,5,4,4,5,3],
            'candidate':[False,True,True,False], 'control':[False,True,True,False]}
 if mode not in schedules:raise ValueError('unknown comparison mode')
 for ordinal,item in enumerate(schedules[mode]):
  candidate=bool(item) if mode in ('candidate','control') else False
  import shutil
  shutil.copyfile(P/('controller-candidate.py' if candidate or mode=='control' else 'controller-baseline.py'),P/'controller.py')
  variant=(4 if candidate else 1) if mode=='control' else (4 if mode=='candidate' else item)
  setup(variant)
  binfo=ask(senders['B'],'OPEN 4 1 1 1 0 43003');key=flowkey('tcp',binfo)
  ask(latency,'OPEN 4 1 1 1 0');time.sleep(.5)
  before=accounting();t0=time.monotonic()
  write(senders['B'],f'BULK v{variant} 6000 65536 0')
  low=ask(latency,f'SEND p{ordinal} 120 50000')
  sent=line(senders['B']);elapsed=time.monotonic()-t0;after=accounting()
  time.sleep(.3);rx=peerop('bulk')[key];lat=peerop('stats')[f'p{ordinal}']
  cpu={n:{k:after[n][k]-before[n][k] for k in before[n]} for n in ('daemon','sender','peer','latency')}
  cpu['whole_guest_ticks']=[b-a for a,b in zip(before['cpu'],after['cpu'])]
  record('comparison',mode=mode,candidate=candidate,ordinal=ordinal,variant=variant,elapsed=elapsed,offloads=feats,sent=sent,receiver=rx,receiver_bps=rx['bytes']*8/elapsed,latency=lat,cpu=cpu,clock_ticks=os.sysconf('SC_CLK_TCK'),qdiscs=qdiscs())
  assert lat['received']==120
  ask(senders['B'],'CLOSE');ask(latency,'CLOSE');teardown(variant)
 # Fresh-query equivalence and foreign-object refusal on actual kernel objects.
 import importlib.util
 shutil.copyfile(P/'controller-candidate.py',P/'controller.py')
 spec=importlib.util.spec_from_file_location('oldcontroller',P/'controller-baseline.py');old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)
 setup(3)
 assert static.topology()==old.Controller.topology(static)
 cmd('tc','filter','add','dev',DEV,'egress','pref','31000','matchall','action','drop')
 refused=False
 try:static.verify()
 except RuntimeError:refused=True
 assert refused
 before=qdiscs()
 try:static.close();raise AssertionError('foreign cleanup accepted')
 except RuntimeError:pass
 assert qdiscs()==before
 cmd('tc','filter','del','dev',DEV,'egress','pref','31000')
 teardown(3)
 record('fresh-batch-equivalence-foreign-refusal',qdiscs=qdiscs())
 # Deny is still independently enforced by the running daemon.
 ask(senders['D'],'OPEN 4 0 1 1 0');ask(senders['D'],'SEND deniedcheck 12 10000');time.sleep(.3)
 assert peerop('stats').get('deniedcheck',{}).get('received',0)==0
 record('deny-zero',received=0)
 record('final-cleanup',qdiscs=qdiscs(),protection=api()['protection'])
 (R/'success.json').write_text(json.dumps({'result':'ISOLATION_COMPLETE'}))
except BaseException:
 (R/'failure.txt').write_text(traceback.format_exc());print(traceback.format_exc(),flush=True);raise
finally:
 if backend and backend.poll() is None:
  backend.terminate()
  try:backend.wait(25)
  except subprocess.TimeoutExpired:backend.kill()
 for p in reversed(children):
  if p.poll() is None:p.terminate()

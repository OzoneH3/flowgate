# Disposable guest: pending IFB TC intent interruption and refusal checks.
# No host traffic or activation; candidate controller only.
import resource
import os,sys,json,socket,subprocess,time,pathlib,sqlite3,select,traceback,shutil,threading
P=pathlib.Path('/work/m1');R=pathlib.Path('/work/.workspace/m1');R.mkdir(mode=0o700,exist_ok=True);API=R/'session'/'api.sock';children=[];records=[];backend=None
assert os.environ.get('FLOWGATE_PARENT_NETNS') and os.environ['FLOWGATE_PARENT_NETNS']!=os.readlink('/proc/self/ns/net')
DEV='fghost';HELPERS=P
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
  except (FileNotFoundError,ProcessLookupError):pass
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
 args=[P/binary,'serve','--socket',API,'--database',R/'rules.db','--uid','0','--administrator','--allow-protection','--protection-state',R/'protection.json','--evaluation-state',R/'session'/'evaluation','--decision-timeout','2s','--experimental-upload-interface',DEV,'--experimental-upload-helpers',HELPERS,'--experimental-upload-state',R/'controller','--experimental-upload-host-trial']
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
    except (FileNotFoundError,ProcessLookupError):pass
  except (FileNotFoundError,ProcessLookupError):pass
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
 stop()

 def cleanup(state):
  return subprocess.run(['python3',str(P/'controller.py'),'--interface',DEV,'--state',str(state),'--helpers',str(P),'--lab-parent-netns',os.environ['FLOWGATE_PARENT_NETNS'],'--cleanup-only'],capture_output=True,text=True,timeout=25)
 def queues(dev):
  return {k:json.loads(cmd('tc','-d','-j',op,'show','dev',dev)) for k,op in [('qdisc','qdisc'),('class','class')]}
 def stable(v):
  if isinstance(v,dict):return {k:stable(x) for k,x in v.items() if k not in ('refcnt','direct_packets_stat')}
  if isinstance(v,list):return [stable(x) for x in v]
  return v
 def wrapper_text(kind,boundary):
  return """import sys,os,json
sys.path.insert(0,'/work/m1')
import controller
orig=controller.Controller.call
save=controller.Controller.save
KIND=%r;BOUNDARY=%r
def matches(self):
 s=getattr(self,'setup_step',None) or []
 return len(s)>4 and s[1:4]==['add','dev',self.ifb] and self.setup_queue_key(tuple(s))==KIND
def call(self,*args):
 hit=matches(self) and args[0]=='tc' and list(args[1:])==self.setup_step
 if hit and BOUNDARY=='absent':os._exit(73)
 r=orig(self,*args)
 if hit:
  with open('/work/.workspace/m1/last-command.json','w') as f:json.dump(self.setup_step,f)
 if hit and BOUNDARY in ('present','different','foreign-filter','foreign-alias'):os._exit(73)
 return r
def saved(self):
 r=save(self)
 if BOUNDARY in ('committed','committed-different') and getattr(self,'ifb_detail_expected',None) and not self.setup_step:
  ts=self.setup_templates.get(KIND)
  if ts:
   # Stop after the matching IFB phase has been durably adopted.
   n=len(self.ifb_detail_expected['classes']);q=len(self.ifb_detail_expected['qdiscs'])
   if (KIND=='root' and n==0) or (KIND=='class' and n==1 and q==1) or (KIND=='leaf' and q==2):os._exit(73)
 return r
controller.Controller.call=call
controller.Controller.save=saved
controller.main()
"""%(kind,boundary)
 cmd('ip','link','add','ifb0','type','ifb');foreign0=json.loads(cmd('ip','-d','-j','link','show','dev','ifb0'))
 cases=[(k,b) for k in ('root','class','leaf') for b in ('absent','present','committed','different','committed-different')]+[('leaf','foreign-filter'),('leaf','foreign-alias')]
 for kind,boundary in cases:
  name=kind+'-'+boundary;state=R/name;wrapper=R/(name+'.py');wrapper.write_text(wrapper_text(kind,boundary))
  crash=launch(['python3',wrapper,'--interface',DEV,'--state',state,'--helpers',P,'--lab-parent-netns',os.environ['FLOWGATE_PARENT_NETNS']],name)
  assert crash.wait(35)==73,(name,(R/(name+'.err')).read_text())
  owner=json.loads((state/'owner.json').read_text());dev=owner['ifb'];step=owner.get('setup_step') or json.loads((R/'last-command.json').read_text());before=queues(dev);ul=stable(queues(DEV));journal=(state/'owner.json').read_bytes()
  record('interrupted',case=name,journal=owner,ifb=before,upload=ul)
  bad=boundary in ('different','committed-different','foreign-filter','foreign-alias')
  if boundary in ('different','committed-different'):
   change=list(step);change[1]='change'
   if kind=='root':
    cmd('tc','qdisc','del','dev',dev,'root','handle',step[step.index('handle')+1]);change[1]='add';change[change.index('default')+1]='1234'
   elif kind=='class':change[change.index('quantum')+1]='9000'
   else:change+=['limit','128']
   cmd('tc',*change)
  if boundary=='foreign-filter':cmd('tc','filter','add','dev',dev,'parent',f"{owner['dl_major']:x}:",'pref','321','matchall','action','pass')
  if boundary=='foreign-alias':cmd('ip','link','set',dev,'alias','fixture-foreign-owner')
  changed=stable(queues(dev));filters=json.loads(cmd('tc','-j','filter','show','dev',dev,'parent',f"{owner['dl_major']:x}:")) if kind!='root' or boundary!='absent' else []
  out=cleanup(state)
  if bad:
   assert out.returncode!=0,(name,out.stdout)
   assert (state/'owner.json').read_bytes()==journal,name
   assert stable(queues(dev))==changed and stable(queues(DEV))==ul,name
   if boundary=='foreign-filter':
    assert json.loads(cmd('tc','-j','filter','show','dev',dev,'parent',f"{owner['dl_major']:x}:"))==filters
    cmd('tc','filter','del','dev',dev,'parent',f"{owner['dl_major']:x}:",'pref','321')
   elif boundary=='foreign-alias':cmd('ip','link','set',dev,'alias','flowgate:'+owner['token'])
   else:
    restore=list(step);restore[1]='change'
    if kind=='root':
     cmd('tc','qdisc','del','dev',dev,'root','handle',step[step.index('handle')+1]);restore[1]='add'
    if kind=='leaf':restore+=['limit',str((owner.get('setup_tc_intent') or {'after':owner['ifb_detail_expected']})['after']['qdiscs'][-1]['options']['limit'])]
    cmd('tc',*restore)
   record('refused-preserved',case=name,error=out.stdout+out.stderr,upload_preserved=True,journal_preserved=True,changed=changed,filters=filters,evidence=(state/'pending-ifb-mismatch.json').exists())
   out=cleanup(state)
  assert out.returncode==0,(name,out.stdout,out.stderr)
  assert qdiscs()==original and not (state/'owner.json').exists(),name
  assert json.loads(cmd('ip','-d','-j','link','show','dev','ifb0'))==foreign0
  record('owned-cleanup',case=name,reply=out.stdout,qdiscs=qdiscs(),unrelated_ifb_preserved=True)
 # API-level configuration retention during startup failure and refused cleanup.
 failhelpers=R/'fail-helpers';failhelpers.mkdir()
 for f in P.iterdir():
  if f.name!='controller.py' and f.is_file():shutil.copy2(f,failhelpers/f.name)
 (failhelpers/'controller.py').write_text("""import sys
sys.path.insert(0,'/work/m1')
import controller
from pathlib import Path
orig=controller.Controller.call
def call(self,*args):
 r=orig(self,*args)
 s=getattr(self,'setup_step',None) or []
 if Path('/work/.workspace/m1/inject.flag').exists() and args[0]=='tc' and len(s)>4 and s[1:4]==['add','dev',self.ifb] and self.setup_queue_key(tuple(s))=='leaf' and list(args[1:])==s:
  orig(self,'tc','qdisc','change','dev',self.ifb,'parent',self.dl_handle(0xfffe),'handle','fffe:','fq_codel','limit','128')
 return r
controller.Controller.call=call
controller.main()
""")
 HELPERS=failhelpers;start('flowgate-new','api-failure')
 initial_upload=[cap('A',8000000)];configure(initial_upload,True)
 assert status()['configured_caps']==initial_upload
 record('upload-config-before-failure',status=status())
 (R/'inject.flag').touch()
 os.kill(int(childpids()[0]),9)
 for _ in range(100):
  if status()['status']=='Unsupported':break
  time.sleep(.2)
 assert status()['status']=='Unsupported'
 caps=[dict(cap('A',8000000),download_bits_per_second=16000000)]
 before_status=status();ack=api('upload-configure',generation=GEN,expected_version=before_status['version'],upload_config={'enabled':True,'caps':caps})['upload_shaping']
 for _ in range(100):
  s=status()
  if s['status']=='Unsupported':break
  time.sleep(.2)
 assert s['status']=='Unsupported',s
 assert s['configured_caps']==caps,s
 state=R/'controller';owner=json.loads((state/'owner.json').read_text());ul=stable(queues(DEV));journal=(state/'owner.json').read_bytes()
 out=cleanup(state);assert out.returncode!=0
 assert stable(queues(DEV))==ul and (state/'owner.json').read_bytes()==journal
 assert status()['configured_caps']==caps
 record('upload-config-retained',ack=ack,status=status(),cleanup_error=out.stdout+out.stderr,upload_resources_preserved=True,note='configuration retained; no claim of ongoing enforcement after shared worker startup fault')
 # Fixture removes only its own changed option, then explicit API disable cleans.
 dev=owner['ifb'];cmd('tc','qdisc','change','dev',dev,'parent',f"{owner['dl_major']:x}:fffe",'handle','fffe:','fq_codel','limit',str((owner.get('setup_tc_intent') or {'after':owner['ifb_detail_expected']})['after']['qdiscs'][-1]['options']['limit']))
 configure([],False);assert qdiscs()==original
 stop();cmd('ip','link','del','ifb0')
 record('final-cleanup',qdiscs=qdiscs(),helpers=kernel_workers()+socket_workers())
 assert not kernel_workers() and not socket_workers()
 (R/'success.json').write_text(json.dumps({'scope':'pending-ifb-intent','cases':len(cases),'api_config_retained':True}));print('VM_RESULT=0',flush=True)
except BaseException:
 (R/'failure.txt').write_text(traceback.format_exc());print(traceback.format_exc(),flush=True)
finally:
 stop()
 for p in reversed(children):
  if p.poll() is None:p.terminate()

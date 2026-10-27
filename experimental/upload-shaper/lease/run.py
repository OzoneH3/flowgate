# Disposable isolated guest: direct kernel shaping lease expiry and recovery.
# No performance comparison, no host traffic or activation.
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
 # Targeted lease correctness proof: no performance acceptance comparison.
 start('flowgate-new','lease')
 ainfo=ask(senders['A'],'OPEN 4 1 1 1 0 43003');akey=flowkey('tcp',ainfo)
 ask(senders['D'],'OPEN 4 0 1 1 0')
 configure([cap('A',8000000)]);wait(lambda s:len(bindings(s))==1)
 journal=json.loads((R/'controller'/'owner.json').read_text());pin=journal['pin']
 minor=status()['kernel']['apps'][appkey('A')]['minor'];classid=f"{journal['major']:x}:{minor:x}"
 write(senders['A'],'BULK lease 90000 65536 0');time.sleep(3)
 def sample(label):
  sampled_before=time.monotonic_ns()
  h=json.loads(cmd(P/'kernel','health',pin));k=json.loads(cmd(P/'kernel','stats',pin))
  classes=json.loads(cmd('tc','-s','-j','class','show','dev',DEV))
  rx=peerop('bulk').get(akey,{}).get('bytes',0)
  return {'label':label,'t':time.monotonic(),'kernel_sample_before_ns':sampled_before,'kernel_health':h,'kernel_stats':k,'classes':classes,'receiver_bytes':rx,'status':status()}
 def deny(tag):
  ack=ask(senders['D'],f'SEND {tag} 12 10000');time.sleep(.1)
  got=peerop('stats').get(tag,{}).get('received',0)
  assert got==0,(tag,got)
  return {'tag':tag,'sender':ack,'received':got}
 def classbytes(s):
  return next(c.get('bytes',c.get('stats',{}).get('bytes')) for c in s['classes'] if c.get('kind',c.get('class'))=='htb' and c.get('handle',c.get('classid'))==classid)
 def window(a,b):
  dt=b['t']-a['t']
  return {'seconds':dt,'payload_mbit':(b['receiver_bytes']-a['receiver_bytes'])*8/dt/1e6,'charged_mbit':(classbytes(b)-classbytes(a))*8/dt/1e6,'classified_packets':b['kernel_stats'][1]['packets']-a['kernel_stats'][1]['packets'],'expired_packets':b['kernel_stats'][17]['packets']-a['kernel_stats'][17]['packets']}
 samples=[];denies=[]
 pre=sample('pre');samples.append(pre);denies.append(deny('denypre'));time.sleep(6)
 before_stop=sample('before-stop');samples.append(before_stop);record('pre-samples',samples=samples,classid=classid);pre_window=window(pre,before_stop)
 cp=childpids();assert len(cp)==1,cp;pid=int(cp[0]);os.kill(pid,19);stopped=time.monotonic()
 i=0
 while time.monotonic()-stopped<10.5:
  time.sleep(.7);samples.append(sample('stopped-'+str(i)));denies.append(deny('denystop'+str(i)));i+=1
  (R/'live-samples.json').write_text(json.dumps({'samples':samples,'denies':denies},indent=2))
 expired=[s for s in samples if s['label'].startswith('stopped') and s['kernel_health']['config_until']<s['kernel_sample_before_ns'] and all(b['until']<s['kernel_sample_before_ns'] for b in s['kernel_health']['bindings'])]
 assert len(expired)>=2,len(expired)
 e0,e1=expired[0],expired[-1];ew=window(e0,e1)
 assert ew['seconds']>=3,ew
 assert ew['expired_packets']>0 and ew['classified_packets']==0,ew
 assert e1['receiver_bytes']>e0['receiver_bytes'],ew
 record('direct-expired-window',window=ew,samples=samples,denies=denies,classid=classid,stopped_at=stopped)
 recovery='resume'
 try:os.kill(pid,18)
 except ProcessLookupError:recovery='killed-controller-explicit-cas'
 if recovery!='resume' or status().get('last_error') or (status().get('kernel') or {}).get('fault'):
  recovery='explicit-cas';configure([],False);configure([cap('A',8000000)])
  journal=json.loads((R/'controller'/'owner.json').read_text());pin=journal['pin']
 wait(lambda s:s.get('kernel',{}).get('covered_bindings')==1 and not s.get('coverage_snapshot_expired'),timeout=15)
 minor=status()['kernel']['apps'][appkey('A')]['minor'];classid=f"{journal['major']:x}:{minor:x}"
 time.sleep(3);recovered=sample('recovered');denies.append(deny('denyrec'));time.sleep(6);after=sample('after-recovery')
 pw=pre_window;rw=window(recovered,after)
 assert rw['classified_packets']>0 and rw['expired_packets']==0,rw
 assert 6.8<=pw['charged_mbit']<=9.2 and 6.8<=rw['charged_mbit']<=9.2,(pw,rw)
 assert ew['payload_mbit']>rw['payload_mbit']*1.5,(ew,rw)
 record('lease-recovered',recovery=recovery,pre=pw,expired=ew,recovered=rw,samples=[recovered,after],denies=denies)
 # Stop the allowed load only after every measurement; no host traffic was generated.
 senders['A'].terminate();senders['A'].wait(5)
 configure([],False);assert qdiscs()==original and egress_filters()==[]
 assert not childpids() and not kernel_workers() and not socket_workers()
 record('cleanup',qdiscs=qdiscs(),status=status(),protection=api()['protection'])
 (R/'success.json').write_text(json.dumps({'result':'DIRECT_LEASE_PROOF_COMPLETE'}));print('INTEGRATION_PROOF_COMPLETE',flush=True)
except BaseException:
 (R/'failure.txt').write_text(traceback.format_exc());print(traceback.format_exc(),flush=True);raise
finally:
 stop()
 for p in reversed(children):
  if p.poll() is None:p.terminate()

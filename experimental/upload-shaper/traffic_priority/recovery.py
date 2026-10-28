# Disposable guest only: traffic priority in the shared UL/DL limiter, real daemon,
# controller, BPF adapters and receivers. Expectations are fixed below BEFORE the
# run; results are recorded, never tuned. No host traffic or activation.
import resource
failed=True
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
def configure(caps=None,ub=0,db=0,enabled=True,schema=2):
 before=status();cfg={'enabled':enabled,'caps':caps or [],'schema':schema,'upload_budget_bits_per_second':ub,'download_budget_bits_per_second':db}
 r=api('upload-configure',generation=GEN,expected_version=before['version'],upload_config=cfg)['upload_shaping'];assert r['version']==before['version']+1
 return wait(lambda s:s['applied_version']==r['version'])
def cap(name,ul=0,dl=0,prio=''):
 c={'uid':0,'application':procs[name]['application']['key'],'bits_per_second':ul}
 if dl:c['download_bits_per_second']=dl
 if prio:c['traffic_priority']=prio
 return c
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
B=40_000_000
def tp(s=None):return ((s or status()).get('kernel') or {}).get('traffic_priority') or {}
def counters():return tp().get('counters') or {}
def nbind(s,name):return sum(1 for b in bindings(s) if b['app']==appkey(name))
def spawn(exe,name):
 p=launch([P/exe],name);line(p);return p
def deny_check(label):
 r=ask(senders['D'],'SEND '+label[:12]+'d 8 10000');time.sleep(.3);rx=peerop('stats').get(label[:12]+'d',{}).get('received',0)
 assert r['sent']==8 and rx==0,(label,r,rx);return {'sent':r['sent'],'received':rx}
def phase(label,ul=None,dl=None,expect=None,edit=None,dur=9000,latency=None):
 """ul: {app:[process count]} each one socket uploading; dl: {app:(processes, sockets per process)}."""
 ul=ul or {};dl=dl or {};expect=expect or {};procs_ul={};procs_dl={};keys={}
 for app,n in ul.items():
  for i in range(n):
   p=spawn(EXE[app],f'{label}-ul-{app}{i}');info=ask(p,'OPEN 4 1 1 1 0 43003');assert 'error' not in info,info
   procs_ul[(app,i)]=p;keys[(app,i)]=flowkey('tcp',info)
 for app,(n,k) in dl.items():
  for i in range(n):
   p=spawn(EXE[app],f'{label}-dl-{app}{i}');info=ask(p,f'OPEN 4 1 {k} 1 0 43005');assert 'error' not in info,info
   procs_dl[(app,i)]=p
 want={}
 for app,n in ul.items():want[app]=want.get(app,0)+n
 for app,(n,k) in dl.items():want[app]=want.get(app,0)+n*k
 configured={c['application'] for c in status()['configured_caps']}
 wait(lambda s:all(nbind(s,a)>=c for a,c in want.items() if procs[a]['application']['key'] in configured),45)
 lat=None
 if latency:
  lat=spawn(EXE[latency],label+'-lat');assert 'error' not in ask(lat,'OPEN 4 0 1 1 0 43001')
  wait(lambda s:nbind(s,latency)>=want.get(latency,0)+1,45)
 for p in procs_ul.values():write(p,f'BULK {label[:12]} {dur} 65536 0')
 for p in procs_dl.values():write(p,'DRAIN 2000')
 for p in procs_dl.values():line(p)
 if not procs_dl:time.sleep(2)
 def window(seconds=4):
  # Discard data queued in receive buffers while nobody was draining (e.g.
  # during a configuration edit); it would inflate the measured window.
  for p in procs_dl.values():write(p,'DRAIN 1000')
  for p in procs_dl.values():line(p)
  a=peerop('bulk');t=time.monotonic()
  if lat:write(lat,f'SEND L{label[:10]} 150 20000')
  for p in procs_dl.values():write(p,f'DRAIN {seconds*1000}')
  got={k:line(p) for k,p in procs_dl.items()}
  if not procs_dl:time.sleep(seconds)
  b=peerop('bulk');e=time.monotonic();out={}
  for (app,i),key in keys.items():out['ul:'+app]=out.get('ul:'+app,0)+(b.get(key,{}).get('bytes',0)-a.get(key,{}).get('bytes',0))*8/(e-t)/1e6
  for (app,i),r in got.items():out['dl:'+app]=out.get('dl:'+app,0)+r['bytes']*8e3/r['elapsed_ns']
  return {k:round(v,3) for k,v in out.items()}
 c0=counters();cpu0=pathlib.Path('/proc/stat').read_text().splitlines()[0].split()[1:];dt0=tree_ticks(backend.pid)
 first=window();second=None
 cpu1=pathlib.Path('/proc/stat').read_text().splitlines()[0].split()[1:];dt1=tree_ticks(backend.pid)
 lr=None
 if lat:line(lat,20);time.sleep(.3);lr=peerop('stats').get(f'L{label[:10]}')
 if edit:
  edit();time.sleep(1.5);second=window()
 for p in procs_ul.values():line(p,30)
 c1=counters();s=status()
 checks={}
 for k,(lo,hi) in expect.items():
  v=(second if k.startswith('2:') else first).get(k.split(':',1)[1] if k.startswith('2:') else k,0)
  checks[k]={'value':v,'band':[lo,hi],'pass':lo<=v<=hi}
 d=[int(y)-int(x) for x,y in zip(cpu0,cpu1)]
 record('phase',label=label,first=first,second=second,expect=checks,latency=lr,deny=deny_check(label),
        counters_delta={k:{'packets':(c1.get(k) or {}).get('packets',0)-(c0.get(k) or {}).get('packets',0)} for k in c1},
        cpu_busy=round(1-(d[3]+d[4])/max(1,sum(d)),3),daemon_ticks=dt1['total_ticks']-dt0['total_ticks'],
        traffic_priority=tp(s),qdiscs=json.loads(cmd('tc','-s','-j','qdisc','show','dev',DEV)),status=s['status'])
 for p in list(procs_ul.values())+list(procs_dl.values())+([lat] if lat else []):
  p.terminate();p.wait()
 children[:]=[c for c in children if c.poll() is None]
 wait(lambda s:all(nbind(s,a)==0 for a in want),40)
 return checks
results={}
def gate(label,checks):
 results[label]={k:v['pass'] for k,v in checks.items()}
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
 EXE={'A':'alpha','C':'gamma','U':'beta','D':'denied'}
 senders={};procs={}
 for n in ['A','C','U','D']:
  p=spawn(EXE[n],n);senders[n]=p;procs[n]=json.loads(cmd(P/'inspect','inspect',p.pid))
 db=sqlite3.connect(R/'rules.db');db.execute('create table rules(id text primary key,document text not null)');db.execute('pragma user_version=1')
 for n in ['A','C','U','D']:
  a=procs[n]['application'];rule={'schema':2,'id':'tp-'+n,'version':1,'created':'2026-01-01T00:00:00Z','action':'block' if n=='D' else 'allow','priority':0,'executable':a['executable'],'filter':{'application':a['key'],'revision':a['revision'],'uid':0,'direction':'outgoing','protocol':'*'}};db.execute('insert into rules values(?,?)',(rule['id'],json.dumps(rule)))
 db.commit();db.close();os.chmod(R/'rules.db',0o600)
 (R/'protection.json').write_text('{"schema":1,"mode":"both"}');os.chmod(R/'protection.json',0o600)
 (R/'session').mkdir(mode=0o711)
 resource.setrlimit(resource.RLIMIT_NOFILE,(8192,8192))
 start('flowgate-new','daemon')
 assert 'experimental-traffic-priority-v1' in api()['capabilities']
 ask(senders['D'],'OPEN 4 0 1 0 0')
 record('setup',qdiscs=original,binaries={b:cmd('sha256sum',P/b).split()[0] for b in ('flowgate-new','controller.py','classify.bpf.o','kernel','probe','alpha')})
 configure([cap('A',prio='low'),cap('C',prio='high')],ub=B,db=B)
 owner=json.loads((R/'controller'/'owner.json').read_text());major=owner['major']
 # S1: an unconfigured app tries to pick reserved/app classes through SO_PRIORITY.
 for label,minor in [('bypass',0xfff1),('budget-parent',0xfff0),('app-minor-1',1)]:
  u=spawn('beta','soprio-'+label);info=ask(u,'OPEN 4 1 1 1 0 43003');key=flowkey('tcp',info)
  assert ask(u,f'SOPRIO {(major<<16)|minor}')['so_priority_set']==1
  write(u,f'BULK so{label[:8]} 7000 65536 0');time.sleep(2);a=peerop('bulk').get(key,{}).get('bytes',0);t=time.monotonic();time.sleep(4);b=peerop('bulk').get(key,{}).get('bytes',0);e=time.monotonic();line(u,20)
  rate=(b-a)*8/(e-t)/1e6;record('so-priority',attempt=label,priority=(major<<16)|minor,payload_mbit=rate,within_budget=rate<=40.5)
  results['S1-'+label]=rate<=40.5;u.terminate();u.wait()
 # S2: controller killed during saturation; per-0.5 s receiver samples show residual and bypass.
 ups={n:spawn(EXE[n],'kill-ul-'+n) for n in ('A','U')};downs={n:spawn(EXE[n],'kill-dl-'+n) for n in ('A','U')}
 keys={n:flowkey('tcp',ask(p,'OPEN 4 1 1 1 0 43003')) for n,p in ups.items()}
 for p in downs.values():assert 'error' not in ask(p,'OPEN 4 1 1 1 0 43005')
 wait(lambda s:nbind(s,'A')>=2,45)
 for p in ups.values():write(p,'BULK kill 22000 65536 0')
 for p in downs.values():write(p,'DRAIN 2000')
 for p in downs.values():line(p)
 samples=[];killed_at=None
 for i in range(24):
  if i==4:
   cp=childpids();assert len(cp)==1,cp;os.kill(int(cp[0]),9);killed_at=time.monotonic()
  a=peerop('bulk');t=time.monotonic()
  for p in downs.values():write(p,'DRAIN 500')
  got={n:line(p) for n,p in downs.items()};b=peerop('bulk');e=time.monotonic()
  samples.append({'t_after_kill_s':None if killed_at is None else round(t-killed_at,2),
   **{'ul:'+n:round((b.get(k,{}).get('bytes',0)-a.get(k,{}).get('bytes',0))*8/(e-t)/1e6,2) for n,k in keys.items()},
   **{'dl:'+n:round(r['bytes']*8e3/r['elapsed_ns'],2) for n,r in got.items()}})
 for p in ups.values():line(p,30)
 deny=deny_check('afterkill')
 record('controller-kill',samples=samples,deny=deny,status=request('upload-status',generation=GEN).get('upload_shaping',{}).get('status'))
 late=[s for s in samples if s['t_after_kill_s'] is not None and s['t_after_kill_s']>=6]
 results['S2-new-packets-bypass-after-lease']=all(s['ul:A']>20 and s['dl:A']>20 for s in late)
 for p in list(ups.values())+list(downs.values()):p.terminate();p.wait()
 s=request('upload-status',generation=GEN)['upload_shaping'];assert s['status']=='Unsupported',s['status']
 api('upload-configure',generation=GEN,expected_version=s['version'],upload_config={'enabled':False,'caps':[],'schema':2})
 until=time.monotonic()+30
 while time.monotonic()<until and request('upload-status',generation=GEN)['upload_shaping']['status']!='Disabled':time.sleep(.5)
 ifbs=[l['ifname'] for l in json.loads(cmd('ip','-j','link','show','type','ifb'))]
 results['S2-cleanup-after-fault']=qdiscs()==original and not [n for n in ifbs if n.startswith('fgdl')] and not kernel_workers() and not childpids()
 record('cleanup-after-fault',status=request('upload-status',generation=GEN)['upload_shaping']['status'],qdiscs=qdiscs(),ifbs=ifbs)
 stop()
 # S3: interrupted setup at every new-tree step on both devices, then cleanup-only.
 cmd('ip','link','add','ifb0','type','ifb');foreign0=json.loads(cmd('ip','-d','-j','link','show','dev','ifb0'))
 def wrapper(key,devkind,boundary):return f"""import sys,os
sys.path.insert(0,'/work/m1')
import controller
orig=controller.Controller.call;save=controller.Controller.save
KEY={key!r};DEVKIND={devkind!r};BOUNDARY={boundary!r}
def matches(self,args):
 s=getattr(self,'setup_step',None) or []
 if not getattr(self,'pending_setup',False) or getattr(self,'cleaning',False):return False
 dev=self.ifb if DEVKIND=='ifb' else self.dev
 return args[0]=='tc' and list(args[1:])==s and len(s)>3 and s[2:4]==['dev',dev] and self.setup_queue_key(tuple(s))==KEY
def call(self,*args):
 hit=matches(self,args)
 if hit and BOUNDARY=='absent':os._exit(73)
 r=orig(self,*args)
 if hit:self._hit=True
 if hit and BOUNDARY in ('present','different'):os._exit(73)
 return r
def saved(self):
 r=save(self)
 if BOUNDARY=='committed' and getattr(self,'_hit',False) and not self.setup_step:os._exit(73)
 return r
controller.Controller.call=call;controller.Controller.save=saved
controller.main()
"""
 def cleanup(state):return subprocess.run(['python3',str(P/'controller.py'),'--interface',DEV,'--state',str(state),'--helpers',str(P),'--host-trial','--cleanup-only'],capture_output=True,text=True,timeout=60)
 keys=['root','class:fff0','class:fff1','class:fffe','leaf']
 cases=[(k,'ul',b) for k in keys for b in ('absent','present')]+[(k,'ifb',b) for k in keys for b in ('absent','present','committed')]+[('class:fff1','ifb','different')]
 for key,devkind,boundary in cases:
  name=f"{devkind}-{key.replace(':','-')}-{boundary}";state=R/name;w=R/(name+'.py');w.write_text(wrapper(key,devkind,boundary))
  crash=launch(['python3',w,'--interface',DEV,'--state',state,'--helpers',P,'--host-trial'],name)
  rc=crash.wait(60);assert rc==73,(name,rc,(R/(name+'.err')).read_text()[-800:])
  owner=json.loads((state/'owner.json').read_text());journal=(state/'owner.json').read_bytes();ifb=owner.get('ifb')
  if boundary=='different':
   cmd('tc','class','change','dev',ifb,'parent',f"{owner['dl_major']:x}:",'classid',f"{owner['dl_major']:x}:fff1",'htb','rate','100gbit','ceil','100gbit','quantum','9000')
   before=json.loads(cmd('tc','-d','-j','class','show','dev',ifb));out=cleanup(state)
   refused=out.returncode!=0 and (state/'owner.json').read_bytes()==journal and json.loads(cmd('tc','-d','-j','class','show','dev',ifb))==before
   record('refused-preserved',case=name,refused=refused,reply=(out.stdout+out.stderr)[-600:])
   results['S3-'+name+'-refused']=refused
   cmd('tc','class','change','dev',ifb,'parent',f"{owner['dl_major']:x}:",'classid',f"{owner['dl_major']:x}:fff1",'htb','rate','100gbit','ceil','100gbit','quantum',str(json.loads(cmd('ip','-j','link','show','dev',DEV))[0]['mtu']))
  out=cleanup(state)
  ifbs=[l['ifname'] for l in json.loads(cmd('ip','-j','link','show','type','ifb'))]
  ok=out.returncode==0 and qdiscs()==original and not (state/'owner.json').exists() and not [n for n in ifbs if n.startswith('fgdl')] and json.loads(cmd('ip','-d','-j','link','show','dev','ifb0'))==foreign0
  record('interrupted-cleanup',case=name,ok=ok,reply=(out.stdout+out.stderr)[-600:])
  results['S3-'+name]=ok
 (R/'results.json').write_text(json.dumps(results,indent=1))
 (R/'success.json').write_text('{"scope":"reserved SO_PRIORITY, controller kill residual/bypass and cleanup, interrupted new-tree setup; fixture complete is not all expectations passed"}');print('PRIO_RESULTS',json.dumps(results),flush=True)
except Exception:
 (R/'results.json').write_text(json.dumps(results,indent=1))
 (R/'failure.txt').write_text(traceback.format_exc());print(traceback.format_exc(),flush=True);failed=True
else:
 failed=False
finally:
 stop()
 for p in reversed(children):
  if p.poll() is None:p.terminate()
sys.exit(1 if failed else 0)

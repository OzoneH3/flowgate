# Disposable guest only: traffic priority in the shared UL/DL limiter, real daemon,
# controller, BPF adapters and receivers. Expectations are fixed below BEFORE the
# run; results are recorded, never tuned. No host traffic or activation.
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
 record('setup',qdiscs=original,tree_before_enable=qdiscs(),binaries={b:cmd('sha256sum',P/b).split()[0] for b in ('flowgate-new','controller.py','classify.bpf.o','kernel','probe')})
 # Schema guard: a schema-1 request carrying traffic priority is refused, no version change.
 s=status();r=request('upload-configure',generation=GEN,expected_version=s['version'],upload_config={'enabled':True,'caps':[cap('C',prio='high')]})
 assert r.get('error_code')=='schema_upgrade_required' and status()['version']==s['version'],r
 # P0 legacy regression (no budgets): UL-only and DL-only caps unchanged, priority dormant.
 configure([cap('A',ul=8_000_000)])
 gate('P0a-legacy-ul-cap',phase('P0a',ul={'A':1,'U':1},expect={'ul:A':(6.0,8.2),'ul:U':(30,1e9)}))
 configure([cap('A',dl=16_000_000),cap('C',prio='high')])
 tree=json.loads(cmd('tc','-j','class','show','dev',DEV));record('legacy-tree',classes=tree,tp=tp())
 assert tp()['apps'].get(appkey('C'),{}).get('upload') is None
 gate('P0b-legacy-dl-cap-priority-dormant',phase('P0b',dl={'A':(1,1),'C':(1,1)},expect={'dl:A':(12.0,16.5),'dl:C':(30,1e9)}))
 # Expected with budget 40 and population {default N, A Low, C High}: floors 6/4/8 Mbit/s (charged).
 SAT={'ul:A':(3.0,5.0),'ul:U':(4.5,7.5),'ul:C':(22,31)}
 SATD={k.replace('ul:','dl:'):v for k,v in SAT.items()}
 configure([cap('A',prio='low'),cap('C',prio='high')],ub=B)
 gate('P1-ul-saturation',phase('P1',ul={'A':1,'C':1,'U':1},expect=SAT,latency='A'))
 configure([cap('A',prio='low'),cap('C',prio='high')],ub=B,db=B)
 gate('P2-dl-saturation',phase('P2',dl={'A':(1,1),'C':(1,1),'U':(1,1)},expect=SATD))
 gate('P3-simultaneous',phase('P3',ul={'A':1,'C':1,'U':1},dl={'A':(1,1),'C':(1,1),'U':(1,1)},expect={**SAT,**SATD}))
 # Matched aggregation: Low 1 vs Normal-default 1, then Low 4 vs Normal-default 1 (C idle).
 AGG={'ul:A':(3.0,5.5),'ul:U':(28,38),'dl:A':(3.0,5.5),'dl:U':(28,38)}
 one=phase('P4a',ul={'A':1,'U':1},dl={'A':(1,1),'U':(1,1)},expect=AGG);gate('P4a-low1-vs-default1',one)
 four=phase('P4b',ul={'A':4,'U':1},dl={'A':(1,4),'U':(1,1)},expect=AGG);gate('P4b-low4-vs-default1',four)
 ratio={d:four[d+':A']['value']/max(.001,one[d+':A']['value']) for d in ('ul','dl')}
 record('aggregation-ratio',ratio=ratio,within_25_percent={d:0.75<=v<=1.25 for d,v in ratio.items()})
 results['P4-matched-ratio']={d:0.75<=v<=1.25 for d,v in ratio.items()}
 gate('P5-low-alone',phase('P5',ul={'A':1},dl={'A':(1,1)},expect={'ul:A':(32,41),'dl:A':(32,41)}))
 configure([cap('A',prio='low'),cap('C',ul=8_000_000,dl=8_000_000,prio='high')],ub=B,db=B)
 gate('P6-high-capped',phase('P6',ul={'A':1,'C':1,'U':1},dl={'A':(1,1),'C':(1,1),'U':(1,1)},expect={'ul:C':(5,8.0),'dl:C':(5,8.0),'ul:A':(3.0,5.0),'dl:A':(3.0,5.0),'ul:U':(20,30),'dl:U':(20,30)}))
 configure([cap('A',prio='low'),cap('C',prio='high')],ub=B,db=B)
 def swap():configure([cap('A',prio='high'),cap('C',prio='low')],ub=B,db=B)
 gate('P7-live-swap',phase('P7',ul={'A':1,'C':1,'U':1},dl={'A':(1,1),'C':(1,1),'U':(1,1)},dur=20000,edit=swap,
      expect={'ul:C':(22,31),'dl:C':(22,31),'2:ul:A':(22,31),'2:dl:A':(22,31),'2:ul:C':(3.0,5.0),'2:dl:C':(3.0,5.0)}))
 # Mode change while caps/priorities active: remove UL budget only (A keeps UL cap 8, DL priority remains).
 configure([cap('A',ul=8_000_000,prio='low'),cap('C',prio='high')],ub=B,db=B)
 def drop_ul():configure([cap('A',ul=8_000_000,prio='low'),cap('C',prio='high')],ub=0,db=B)
 gate('P8-ul-budget-removed',phase('P8',ul={'A':1,'U':1},dl={'A':(1,1),'C':(1,1),'U':(1,1)},dur=20000,edit=drop_ul,
      expect={'ul:A':(3.0,5.0),'2:ul:A':(6.0,8.2),'2:ul:U':(30,1e9),'2:dl:A':(3.0,5.0),'2:dl:C':(22,31)}))
 record('legacy-after-mode-change',tp=tp(),classes=json.loads(cmd('tc','-j','class','show','dev',DEV)))
 # Scope negatives: wildcard listener/socket hit by a non-local destination, and connected UDP positive.
 configure([cap('A',prio='low'),cap('C',prio='high')],ub=B,db=B)
 hostmac=json.loads(cmd('ip','-j','link','show','dev',DEV))[0]['address']
 wl=launch(['python3','-c','import socket,sys,time\nt=socket.socket();t.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);t.bind(("0.0.0.0",45000));t.listen(8)\nu=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);u.bind(("0.0.0.0",45001))\nc=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);c.bind(("10.79.0.1",45002));c.connect(("10.79.0.2",43001))\nprint("{}",flush=True);n=0\nc.settimeout(.2);end=time.time()+8\nwhile time.time()<end:\n try:c.recv(2048);n+=1\n except OSError:pass\nprint(\'{"connected_udp_received":%d}\'%n,flush=True)'],'scope-listeners');line(wl)
 before=counters()
 nspeer=['nsenter','-t',str(peer.pid),'-n']
 cmd(*nspeer,'ip','neigh','replace','10.79.0.99','lladdr',hostmac,'dev','fgpeer','nud','permanent')
 cmd(*nspeer,'python3','-c','import socket\nfor p in (45000,):\n s=socket.socket();s.setblocking(False)\n try:s.connect(("10.79.0.99",p))\n except OSError:pass\nu=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\nfor i in range(50):u.sendto(b"x"*200,("10.79.0.99",45001))\nimport time;time.sleep(.5)')
 mid=counters()
 cmd(*nspeer,'python3','-c','import socket,time\nu=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);u.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);u.bind(("10.79.0.2",43001))\nfor i in range(50):u.sendto(b"y"*200,("10.79.0.1",45002));time.sleep(.01)')
 got=line(wl,20);after=counters()
 delta=lambda a,b,k:(b.get(k) or {}).get('packets',0)-(a.get(k) or {}).get('packets',0)
 neg={'excluded_no_exact':delta(before,mid,'download_excluded_no_exact_socket'),'default_redirected':delta(before,mid,'download_default_redirected')}
 pos={'default_redirected':delta(mid,after,'download_default_redirected'),'received':got['connected_udp_received']}
 record('scope',nonlocal_wildcard=neg,connected_udp=pos)
 results['P9-scope']={'nonlocal_not_redirected':neg['default_redirected']==0 and neg['excluded_no_exact']>=50,'connected_udp_redirected':pos['default_redirected']>=45 and pos['received']>=45}
 # Foreign class filter under the owned budget parent: refusal and exact preservation.
 owner=json.loads((R/'controller'/'owner.json').read_text());budget_parent=f"{owner['major']:x}:fff0"
 cmd('tc','filter','add','dev',DEV,'parent',budget_parent,'pref','321','matchall','action','pass')
 until=time.monotonic()+15
 while time.monotonic()<until and status()['status']!='Unsupported':time.sleep(.2)
 roots=qdiscs();classes=json.loads(cmd('tc','-j','class','show','dev',DEV))
 s=status();assert s['status']=='Unsupported'
 api('upload-configure',generation=GEN,expected_version=s['version'],upload_config={'enabled':False,'caps':[],'schema':2});time.sleep(2)
 assert status()['status']=='Unsupported' and qdiscs()==roots and json.loads(cmd('tc','-j','class','show','dev',DEV))==classes
 record('foreign-refusal',filters=json.loads(cmd('tc','-j','filter','show','dev',DEV,'parent',budget_parent)))
 cmd('tc','filter','del','dev',DEV,'parent',budget_parent,'pref','321')
 configure([],enabled=False);assert qdiscs()==original and not kernel_workers()
 # Lease expiry / controller failure during saturation: new packets bypass both budgets.
 configure([cap('A',prio='low'),cap('C',prio='high')],ub=B,db=B)
 def kill():
  cp=childpids();assert len(cp)==1,cp;os.kill(int(cp[0]),9);time.sleep(6)
 gate('P10-lease-expiry',phase('P10',ul={'A':1,'U':1},dl={'A':(1,1),'U':(1,1)},dur=24000,edit=kill,
      expect={'ul:A':(3.0,5.0),'2:ul:A':(45,1e9),'2:dl:A':(45,1e9)}))
 record('after-expiry',status=status(),counters=counters())
 configure([],enabled=False);assert qdiscs()==original and not kernel_workers() and not socket_workers()
 record('cleanup',qdiscs=qdiscs(),rules=len(api().get('rules',[])),protection=api()['protection'])
 (R/'results.json').write_text(json.dumps(results,indent=1))
 stop();(R/'success.json').write_text('{"scope":"traffic priority kernel proof; fixture complete is not all expectations passed"}');print('PRIO_RESULTS',json.dumps(results),flush=True);print('VM_RESULT=0',flush=True)
except Exception:
 (R/'results.json').write_text(json.dumps(results,indent=1))
 (R/'failure.txt').write_text(traceback.format_exc());print(traceback.format_exc(),flush=True);print('VM_RESULT=1',flush=True)
finally:
 stop()
 for p in reversed(children):
  if p.poll() is None:p.terminate()

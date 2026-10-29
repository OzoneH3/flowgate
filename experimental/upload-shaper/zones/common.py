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
def configure(caps=None,ub=0,db=0,enabled=True,schema=3):
 before=status();cfg={'enabled':enabled,'caps':caps or [],'schema':schema,'upload_budget_bits_per_second':ub,'download_budget_bits_per_second':db}
 r=api('upload-configure',generation=GEN,expected_version=before['version'],upload_config=cfg)['upload_shaping'];assert r['version']==before['version']+1
 return wait(lambda s:s['applied_version']==r['version'])
def cap(name,ul=0,dl=0,prio='',scope=''):
 c={'uid':0,'application':procs[name]['application']['key'],'bits_per_second':ul}
 if dl:c['download_bits_per_second']=dl
 if prio:c['traffic_priority']=prio
 if scope:c['scope']=scope
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
 args=[P/binary,'serve','--socket',API,'--database',R/'rules.db','--uid','0','--administrator','--allow-protection','--protection-state',R/'protection.json','--evaluation-state',R/'session'/'evaluation','--decision-timeout','2s','--experimental-upload-interface',DEV,'--experimental-upload-helpers',P,'--experimental-upload-state',R/'controller','--experimental-upload-host-trial','--zone-local','10.79.0.2/32','--zone-internet','fd79::2/128']
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

# Fixed classifier fixtures: IPv4 peer is Local; IPv6 peer is synthetic Internet.
# Both peers are private, inside one disposable VM; this is NOT public connectivity.
ZONES={'local':4,'internet':6};EXE={'A':'alpha','D':'denied'};results={};RETRIES=[]
def spawn(exe,name):
 p=launch([P/exe],name);line(p);return p
def open_retry(p,command,name):
 for attempt in range(5):
  info=ask(p,command)
  if 'error' not in info:return info
  RETRIES.append({'name':name,'attempt':attempt,'error':info});time.sleep(1)
 raise AssertionError((name,info))
def deny_check(label):
 tag=label[:12]+'d';r=ask(senders['D'],'SEND '+tag+' 8 10000');time.sleep(.3)
 received=peerop('stats').get(tag,{}).get('received',0);assert r['sent']==8 and received==0,(r,received)
 return {'sent':r['sent'],'received':received}
def zonebindings(s,zone):return [b for b in bindings(s) if b['app']==appkey('A') and b.get('zone')==zone]
def checked(label,values,bands):
 checks={k:{'value':values.get(k,0),'band':[lo,hi],'pass':lo<=values.get(k,0)<=hi} for k,(lo,hi) in bands.items()}
 results[label]={k:v['pass'] for k,v in checks.items()};return checks

def phase(label,bands,edit=None,after_bands=None):
 # UL uses two independent processes/sockets per zone, all same executable;
 # DL uses one process with two sockets per zone. They share their zone class.
 uploads={};downloads={};keys={};phase_children=[]
 for zone,fam in ZONES.items():
  for i in range(2):
   p=spawn('alpha',f'{label}-{zone}-ul{i}');phase_children.append(p)
   info=open_retry(p,f'OPEN {fam} 1 1 1 0 43003',f'{label}-{zone}-ul{i}')
   uploads[(zone,i)]=p;keys[(zone,i)]=flowkey('tcp',info)
  p=spawn('alpha',f'{label}-{zone}-dl');phase_children.append(p)
  info=open_retry(p,f'OPEN {fam} 1 2 1 0 43005',f'{label}-{zone}-dl');downloads[zone]=p
 wait(lambda s:all(len(zonebindings(s,z))==4 for z in ZONES),60)
 # Keep uploads alive through settle + two eight-second windows + optional edit.
 for p in uploads.values():write(p,f'BULK {label[:12]} 90000 65536 0')
 def drain(ms):
  for p in downloads.values():write(p,f'DRAIN {ms}')
  return {z:line(p,ms/1000+15) for z,p in downloads.items()}
 def window():
  # Drain receive buffers and settle for three seconds before an eight-second
  # measurement. Receiver bytes, not API acknowledgements or sender writes.
  drain(3000);a=peerop('bulk');start=time.monotonic();got=drain(8000);b=peerop('bulk');elapsed=time.monotonic()-start
  values={}
  for z in ZONES:
   n=sum(b.get(keys[(z,i)],{}).get('bytes',0)-a.get(keys[(z,i)],{}).get('bytes',0) for i in range(2))
   values['ul:'+z]=round(n*8/elapsed/1e6,3)
   values['dl:'+z]=round(got[z]['bytes']*8e3/got[z]['elapsed_ns'],3)
  for direction in ('ul','dl'):values[direction+':combined']=round(sum(values[direction+':'+z] for z in ZONES),3)
  return values
 first=window();checks=checked(label,first,bands)
 # A second independent settled window detects sustained overshoot vs startup burst.
 sustained=window();sustained_checks=checked(label+'-settled-repeat',sustained,bands)
 second=None;second_checks=None
 if edit:
  edit();second=window();second_checks=checked(label+'-edit',second,after_bands)
 record('receiver-phase',label=label,first=first,sustained=sustained,after_edit=second,checks=checks,sustained_checks=sustained_checks,after_checks=second_checks,
        deny=deny_check(label),snapshot=status(),classes=json.loads(cmd('tc','-s','-j','class','show','dev',DEV)))
 for p in phase_children:p.terminate();p.wait(10)
 children[:]=[p for p in children if p.poll() is None]
 wait(lambda s:not bindings(s),60)
 return first,second
def run(case_name):
 global peer,senders,procs,GEN,backend,failed
 try:
  peer=launch(['unshare','--net','python3',P/'peer.py'],'peer')
  for _ in range(100):
   if os.readlink(f'/proc/{peer.pid}/ns/net')!=os.readlink('/proc/self/ns/net'):break
   time.sleep(.02)
  cmd('ip','link','set','nsim0','name',DEV);cmd('ip','link','set','nsim1','name','fgpeer');cmd('ip','link','set','fgpeer','netns',peer.pid)
  for a in [('link','set','dev',DEV,'addrgenmode','none'),('link','set',DEV,'up'),('addr','add','10.79.0.1/24','dev',DEV),('-6','addr','add','fd79::1/64','dev',DEV,'nodad')]:cmd('ip',*a)
  peerop('setup');original=qdiscs()
  if case_name=='capacity':
   EXE.update({'B':'beta','C':'gamma','E':'delta'});shutil.copy2(P/'alpha',P/'delta')
  senders={};procs={}
  for n in EXE:
   p=spawn(EXE[n],n);senders[n]=p;procs[n]=json.loads(cmd(P/'inspect','inspect',p.pid))
  db=sqlite3.connect(R/'rules.db');db.execute('create table rules(id text primary key,document text not null)');db.execute('pragma user_version=1')
  for n in EXE:
   a=procs[n]['application'];rule={'schema':2,'id':'zone-'+n,'version':1,'created':'2026-01-01T00:00:00Z','action':'block' if n=='D' else 'allow','priority':0,'executable':a['executable'],'filter':{'application':a['key'],'revision':a['revision'],'uid':0,'direction':'outgoing','protocol':'*'}};db.execute('insert into rules values(?,?)',(rule['id'],json.dumps(rule)))
  db.commit();db.close();os.chmod(R/'rules.db',0o600)
  (R/'protection.json').write_text('{"schema":1,"mode":"both"}');os.chmod(R/'protection.json',0o600);(R/'session').mkdir(mode=0o711)
  resource.setrlimit(resource.RLIMIT_NOFILE,(8192,8192));start('flowgate-new','daemon')
  assert 'experimental-zone-shaping-v1' in api()['capabilities'];initial_rules=api().get('rules',[])
  ask(senders['D'],'OPEN 4 0 1 0 0')
  peermac=json.loads(cmd('nsenter','-t',str(peer.pid),'-n','ip','-j','link','show','dev','fgpeer'))[0]['address']
  cmd('ip','-6','neigh','replace','fd79::2','lladdr',peermac,'dev',DEV,'nud','permanent')
  cmd('nsenter','-t',str(peer.pid),'-n','ip','-6','neigh','replace','fd79::1','lladdr',json.loads(cmd('ip','-j','link','show','dev',DEV))[0]['address'],'dev','fgpeer','nud','permanent')
  record('setup',synthetic_assignments={'local':'10.79.0.2/32','internet':'fd79::2/128'},public_connectivity=False,original_qdiscs=original,binaries={b:cmd('sha256sum',P/b).split()[0] for b in ('flowgate-new','controller.py','classify.bpf.o','kernel','probe','alpha')})
  exec(compile((P/'case.py').read_text(),str(P/'case.py'),'exec'),globals())
  configure([],enabled=False);assert qdiscs()==original
  assert api().get('rules',[])==initial_rules
  record('cleanup',qdiscs=qdiscs(),rules_unchanged=True,connect_retries=RETRIES,results=results)
  assert all(all(v.values()) for v in results.values()),results
  (R/'success.json').write_text(json.dumps({'result':'ZONE_RECEIVER_PASS'}))
 except Exception:
  (R/'failure.txt').write_text(traceback.format_exc());print(traceback.format_exc(),flush=True);failed=True
 else:failed=False
 finally:
  (R/'results.json').write_text(json.dumps(results,indent=2));stop()
  for p in reversed(children):
   if p.poll() is None:p.terminate()
 sys.exit(1 if failed else 0)

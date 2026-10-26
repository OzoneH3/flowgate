# Disposable VM only: actual serve API + unchanged firewall ownership rules.
import os,sys,json,socket,subprocess,time,pathlib,sqlite3,select,traceback
P=pathlib.Path('/work/m1');R=pathlib.Path('/work/.workspace/m1');R.mkdir(mode=0o700,exist_ok=True);API=R/'session'/'api.sock';children=[];records=[];backend=None
assert os.environ.get('FLOWGATE_PARENT_NETNS') and os.environ['FLOWGATE_PARENT_NETNS']!=os.readlink('/proc/self/ns/net')
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
def caps(rate=4000000):return [{'uid':0,'application':procs['A']['application']['key'],'bits_per_second':rate}]
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
 args=[P/'flowgate','serve','--socket',API,'--database',R/'rules.db','--uid','0','--administrator','--allow-protection','--protection-state',R/'protection.json','--evaluation-state',R/'session'/'evaluation','--decision-timeout','2s','--experimental-upload-interface','fghost','--experimental-upload-helpers',P,'--experimental-upload-state',R/'controller','--experimental-upload-parent-netns',os.environ['FLOWGATE_PARENT_NETNS']]
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
def phase(label,change=None):
 before=status();tc_before=json.loads(cmd('tc','-s','-j','class','show','dev','fghost'));startt=time.monotonic();tags={n:label+n for n in senders}
 for n,p in senders.items():write(p,f'SEND {tags[n]} {700 if n.startswith("A") else 120 if n=="B" else 12} {2000 if n.startswith("A") else 10000 if n=="B" else 30000}')
 if change:time.sleep(.4);configure(caps(change))
 sent={n:line(p) for n,p in senders.items()};time.sleep(.3);rx=peerop('stats');out={n:rx.get(t,{'received':0}) for n,t in tags.items()}
 assert out['A']['received']==700 and out['A2']['received']==700,out
 assert out['B']['received']==120 and out['D']['received']==0,out
 assert max(out['A']['p95_ms'],out['A2']['p95_ms'])<1000,out
 record('phase',tc_before=tc_before,tc_after=json.loads(cmd('tc','-s','-j','class','show','dev','fghost')),label=label,elapsed=time.monotonic()-startt,sent=sent,received=out,before=before,after=status())
try:
 peer=launch(['unshare','--net','python3',P/'peer.py'],'peer')
 for _ in range(100):
  if os.readlink(f'/proc/{peer.pid}/ns/net')!=os.readlink('/proc/self/ns/net'):break
  time.sleep(.02)
 cmd('ip','link','set','eth0','name','fghost');cmd('ip','link','set','eth1','name','fgpeer')
 for dev in ['fghost','fgpeer']:cmd('ethtool','-K',dev,'tso','off','gso','off','tx-udp-segmentation','off')
 cmd('ip','link','set','fgpeer','netns',peer.pid)
 for a in [('link','set','dev','fghost','addrgenmode','none'),('link','set','fghost','up'),('addr','add','10.79.0.1/24','dev','fghost'),('-6','addr','add','fd79::1/64','dev','fghost','nodad')]:cmd('ip',*a)
 peerop('setup')
 original=json.loads(cmd('tc','-j','qdisc','show','dev','fghost'))
 record('nic-capabilities',default_sysctl_exists=pathlib.Path('/proc/sys/net/core/default_qdisc').exists(),link=json.loads(cmd('ip','-d','-j','link','show','dev','fghost')),offloads=cmd('ethtool','-k','fghost'),qdiscs=original)
 senders={};procs={}
 for n,exe in [('A','alpha'),('A2','alpha'),('B','beta'),('D','denied')]:
  p=launch([P/exe],n);line(p);senders[n]=p;procs[n]=json.loads(cmd(P/'inspect','inspect',p.pid))
 db=sqlite3.connect(R/'rules.db');db.execute('create table rules(id text primary key,document text not null)');db.execute('pragma user_version=1')
 for n in ['A','B','D']:
  a=procs[n]['application'];rule={'schema':2,'id':'m0-'+n,'version':1,'created':'2026-01-01T00:00:00Z','action':'block' if n=='D' else 'allow','priority':0,'executable':a['executable'],'filter':{'application':a['key'],'revision':a['revision'],'uid':0,'direction':'outgoing','protocol':'*'}};db.execute('insert into rules values(?,?)',(rule['id'],json.dumps(rule)))
 db.commit();db.close();os.chmod(R/'rules.db',0o600)
 (R/'protection.json').write_text('{"schema":1,"mode":"both"}');os.chmod(R/'protection.json',0o600)
 (R/'session').mkdir(mode=0o711)
 start('serve');assert status()['status']=='Disabled';time.sleep(1)
 assert not childpids(),childpids();assert json.loads(cmd('tc','-j','qdisc','show','dev','fghost'))==original
 record('disabled-no-helper-no-tc',status=status())
 infos={}
 for n,p in senders.items():
  infos[n]=ask(p,f'OPEN 4 1 {2 if n.startswith("A") else 1} 1 0')
  if n=='D':assert 'error' in infos[n],infos[n]
 # Existing sockets must be discovered with NO further traffic or GUI calls.
 s=configure(caps());s=wait(lambda s:len(s.get('kernel',{}).get('bindings',[]))==4)
 assert len(s['kernel']['apps'])==1,s
 record('existing-auto-aggregate',status=s)
 journal=json.loads((R/'controller'/'owner.json').read_text())
 for value,expected in [(0,0),(6,6),((journal['major']<<16)|1,0)]:
  result=json.loads(cmd(P/'kernel','priority-test',journal['pin'],value));assert result['priority']==expected,result
 record('unbound-priority-preserved-and-class-forgery-refused')
 configure(caps());phase('cap4');phase('live8',8000000);configure([],False);phase('removed')
 # New sockets are observed through the daemon, and new unconnected UDP peers
 # are bound without any explicit bind API call.
 for n in ['A','A2']:ask(senders[n],'CLOSE')
 configure(caps(8000000));s=wait(lambda s:len(s.get('kernel',{}).get('bindings',[]))==0)
 u=senders['A'];inf=ask(u,'OPEN 6 0 1 0 0');ask(u,'SEND warm6 2 10000')
 s=wait(lambda s:len(s.get('kernel',{}).get('bindings',[]))==1);binding=s['kernel']['bindings'][0]
 for port,tag in [(43001,'udp6a'),(43002,'udp6b')]:
  ask(u,f'PEER {port}');r=ask(u,f'SEND {tag} 12 20000');assert r['sent']==12,r
 time.sleep(.3);rx=peerop('stats');assert rx['udp6a']['received']==12 and rx['udp6b']['received']==12,rx
 # Same bound socket survives exec; no automatic reassignment to Beta.
 before=binding;after=ask(u,'EXEC '+str(P/'beta'));time.sleep(2);s=status();assert s['kernel']['bindings'][0]==before,s
 ask(u,'SEND afterexec 12 20000');time.sleep(.3);assert peerop('stats')['afterexec']['received']==12
 record('new-udp6-multipeer-and-exec-origin',binding=before,status=s)
 api('rule',generation=GEN,id='m0-B',action='disable',expected_version=1)
 ask(u,'SEND policyremoved 12 20000');time.sleep(3)
 assert peerop('stats').get('policyremoved',{}).get('received',0)==0
 assert status()['kernel']['bindings'][0]==before
 api('rule',generation=GEN,id='m0-B',action='enable',expected_version=2)
 ask(u,'SEND policyrestored 12 20000');time.sleep(.3)
 assert peerop('stats')['policyrestored']['received']==12
 record('rule-update-independent',binding=before)

 # A denied executable can have a shaping cap, never permission inheritance.
 dc={'uid':0,'application':procs['D']['application']['key'],'bits_per_second':8000000}
 configure(caps(8000000)+[dc]);d=senders['D'];ask(d,'OPEN 6 0 1 1 0');ask(d,'SEND denied6 12 20000');time.sleep(.5);assert peerop('stats').get('denied6',{}).get('received',0)==0
 record('firewall-deny-independent',status=status())
 ask(senders['A2'],'OPEN 4 1 1 1 0')
 app='0:'+procs['A']['application']['key']
 new_info=ask(senders['A2'],'OPEN 6 1 1 1 0')
 new_port=new_info['sockets'][0]['port']
 rows=json.loads(cmd(P/'probe','sockets'))
 cookie=next(r['cookie'] for r in rows if r['local']==f'[fd79::1]:{new_port}' and r['protocol']=='tcp')
 wait(lambda x:any(b['app']==app and b['cookie']==cookie for b in x.get('kernel',{}).get('bindings',[])))
 ask(senders['A2'],'SEND newtcp6 100 2000');time.sleep(.3)
 assert peerop('stats')['newtcp6']['received']==100
 record('new-tcp6',status=status())

 # Controller failure must become Unsupported; restart only through explicit CAS.
 cp=childpids();assert len(cp)==1,cp;os.kill(int(cp[0]),9)
 end=time.monotonic()+10
 while time.monotonic()<end:
  s=status()
  if s['status']=='Unsupported':break
  time.sleep(.3)
 assert s['status']=='Unsupported',s;time.sleep(5.5)
 record('controller-failure',status=s)
 configure([],False)
 assert not childpids(),childpids()
 assert json.loads(cmd('tc','-j','qdisc','show','dev','fghost'))==original
 record('failure-disable-cleanup',qdiscs=json.loads(cmd('tc','-j','qdisc','show','dev','fghost')),helper_pids=childpids())
 configure(caps(8000000));s=wait(lambda x:x.get('kernel') is not None)
 record('controller-recovery-fresh',status=s)
 # Abrupt daemon/controller loss leaves an owned journal. Startup must expose
 # residual state without attaching; explicit disable cleans only verified objects.
 oldgen=GEN;cp=childpids();assert len(cp)==1,cp;os.kill(int(cp[0]),9);backend.kill();backend.wait(20);time.sleep(5.5);start('serve-restart')
 assert GEN!=oldgen and status()['status']=='Unsupported' and not childpids()
 record('orphan-journal-startup',status=status())
 configure([],False);assert status()['status']=='Disabled' and not childpids()
 record('orphan-cleanup',status=status(),qdiscs=json.loads(cmd('tc','-j','qdisc','show','dev','fghost')))
 assert request('upload-configure',generation=oldgen,expected_version=1,upload_config={'enabled':True,'caps':caps()})['error_code']=='stale_generation'
 configure(caps());record('daemon-restart',status=status())
 # Replacing selected interface must stop renewal and refuse foreign deletion.
 cmd('ip','link','set','fghost','name','fgold')
 cmd('ip','link','add','fghost','type','veth','peer','name','fgnewpeer')
 foreign_replacement=json.loads(cmd('tc','-j','qdisc','show','dev','fghost'))
 end=time.monotonic()+12
 while time.monotonic()<end:
  st=status()
  if st['status']=='Unsupported':break
  time.sleep(.3)
 assert st['status']=='Unsupported',st
 rec=request('upload-configure',generation=GEN,expected_version=st['version'],upload_config={'enabled':False,'caps':[]});assert not rec.get('error'),rec
 time.sleep(2);assert status()['status']=='Unsupported',status()
 assert json.loads(cmd('tc','-j','qdisc','show','dev','fghost'))==foreign_replacement
 record('interface-replacement-refused',status=status(),foreign_before=foreign_replacement,foreign_after=json.loads(cmd('tc','-j','qdisc','show','dev','fghost')))
 cmd('ip','link','del','fghost');cmd('ip','link','set','fgold','name','fghost')
 configure([],False)
 assert not childpids(),childpids()
 assert json.loads(cmd('tc','-j','qdisc','show','dev','fghost'))==original
 assert api()['protection']['state']=='active'
 record('final-cleanup-firewall-active',rules=len(api()['rules']),qdiscs=json.loads(cmd('tc','-j','qdisc','show','dev','fghost')))
 # Crash exactly after root replacement, before the post-mutation journal save.
 wrapper=R/'interrupt.py'
 wrapper.write_text("import sys,os,types\nsys.path.insert(0,'/work/m1')\nimport controller\nclass Interrupted(controller.Controller):\n def call(self,*args):\n  out=super().call(*args)\n  if args[:3]==('tc','qdisc','replace'): os._exit(77)\n  return out\nInterrupted(types.SimpleNamespace(interface='fghost',helpers='/work/m1',state='/work/.workspace/m1/controller',lab_parent_netns=os.environ['FLOWGATE_PARENT_NETNS'],cleanup_only=False))\n")
 interrupted=subprocess.run(['python3','-I',str(wrapper)],capture_output=True,text=True,timeout=20)
 assert interrupted.returncode==77,(interrupted.returncode,interrupted.stdout,interrupted.stderr)
 journal=json.loads((R/'controller'/'owner.json').read_text())
 assert journal['pending_setup'] and journal['setup_step'][0:2]==['qdisc','replace'],journal
 (R/'controller'/'owner.new').write_text('uncommitted crash residue')
 cmd('tc','qdisc','add','dev','fghost','clsact') # fixture-owned foreign addition
 foreign=json.loads(cmd('tc','-j','qdisc','show','dev','fghost'))
 backend.terminate();backend.wait(25);start('interrupted-restart')
 assert status()['status']=='Unsupported'
 st=status();api('upload-configure',generation=GEN,expected_version=st['version'],upload_config={'enabled':False,'caps':[]})
 time.sleep(2);assert status()['status']=='Unsupported',status()
 assert json.loads(cmd('tc','-j','qdisc','show','dev','fghost'))==foreign
 record('interrupted-setup-foreign-refused',status=status(),journal=journal,foreign=foreign)
 cmd('tc','qdisc','del','dev','fghost','clsact') # remove only the fixture's addition
 configure([],False)
 assert json.loads(cmd('tc','-j','qdisc','show','dev','fghost'))==original
 assert not (R/'controller'/'owner.json').exists() and not (R/'controller'/'owner.new').exists()
 record('interrupted-setup-restored',qdiscs=original,status=status())
 # Simulate reboot's vanished kernel state with a previous-boot private journal.
 stale=dict(journal,boot_id='previous-test-boot',netns='net:[1]',ifindex=99999)
 (R/'controller'/'owner.json').write_text(json.dumps(stale));os.chmod(R/'controller'/'owner.json',0o600)
 backend.terminate();backend.wait(25);start('stale-boot-restart')
 assert status()['status']=='Unsupported' and not childpids()
 configure([],False)
 assert not (R/'controller'/'owner.json').exists()
 assert json.loads(cmd('tc','-j','qdisc','show','dev','fghost'))==original
 record('previous-boot-empty-state-reconciled',status=status(),qdiscs=original)
 # MTU changes stop renewal; cleanup must remove only ours, not reset the MTU.
 configure(caps());cmd('ip','link','set','fghost','mtu','1400')
 until=time.monotonic()+12
 while time.monotonic()<until:
  if status()['status']=='Unsupported':break
  time.sleep(.2)
 st=status();assert st['status']=='Unsupported',st
 api('upload-configure',generation=GEN,expected_version=st['version'],upload_config={'enabled':False,'caps':[]})
 time.sleep(2)
 assert json.loads(cmd('ip','-j','link','show','dev','fghost'))[0]['mtu']==1400
 assert not (R/'controller'/'owner.json').exists()
 restored=json.loads(cmd('tc','-j','qdisc','show','dev','fghost'))
 assert restored[0]['kind']=='fq_codel' and restored[0]['handle']=='0:',restored
 record('mtu-change-owned-cleanup-no-reset',status=status(),qdiscs=restored)
 (R/'success.json').write_text(json.dumps({'result':'INTEGRATION_PASS'}));print('INTEGRATION_PROOF_COMPLETE',flush=True)
except BaseException:
 (R/'failure.txt').write_text(traceback.format_exc());print(traceback.format_exc(),flush=True);raise
finally:
 if backend and backend.poll() is None:
  backend.terminate()
  try:backend.wait(25)
  except subprocess.TimeoutExpired:backend.kill()
 for p in reversed(children):
  if p.poll() is None:p.terminate()

# VM-only M0 proof. No host runtime path or network is reachable.
import os,sys,json,socket,subprocess,time,pathlib,sqlite3,select,hashlib,traceback,struct
P=pathlib.Path('/work/m1');R=pathlib.Path('/work/.workspace/m1');R.mkdir(mode=0o700,exist_ok=True);API=R/'api.sock';children=[];records=[];bindings=[];backend=None;shape=False
assert os.environ.get('FLOWGATE_PARENT_NETNS')!=os.readlink('/proc/self/ns/net') and os.environ.get('FLOWGATE_PARENT_NETNS')
def cmd(*a,**kw):return subprocess.check_output([str(x) for x in a],text=True,timeout=15,**kw)
def run(*a):return cmd(*a)
def launch(args,name):
 p=subprocess.Popen([str(x) for x in args],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=(R/(name+'.err')).open('w'),text=True,bufsize=1);children.append(p);return p
def line(p,timeout=25):
 if not select.select([p.stdout],[],[],timeout)[0]:raise RuntimeError('fixture timeout '+str(p.pid))
 s=p.stdout.readline()
 if not s:raise RuntimeError('fixture exited '+str(p.pid))
 return json.loads(s)
def write(p,s):p.stdin.write(s+'\n');p.stdin.flush()
def ask(p,s):write(p,s);return line(p)
def peerop(s):return ask(peer,json.dumps({'op':s}))
def api(op='list',**fields):
 with socket.socket(socket.AF_UNIX) as s:
  s.settimeout(3);s.connect(str(API));s.sendall((json.dumps(dict(version=1,operation=op,**fields))+'\n').encode());d=json.loads(s.makefile('rb').readline());assert not d.get('error'),d;return d
def inspect(p):return json.loads(cmd(P/'inspect','inspect',p.pid))
def cpu():
 f=pathlib.Path('/proc/stat').read_text().splitlines()[0].split()[1:];v=list(map(int,f));return (sum(v)-v[3]-v[4])/os.sysconf('SC_CLK_TCK')
def procusage(pid=None):
 f=pathlib.Path(f'/proc/{pid or backend.pid}/stat').read_text().rsplit(')',1)[1].split();rss=int(next(l.split()[1] for l in pathlib.Path(f'/proc/{pid or backend.pid}/status').read_text().splitlines() if l.startswith('VmRSS:')));return {'cpu':(int(f[11])+int(f[12]))/os.sysconf('SC_CLK_TCK'),'rss_kib':rss}
def foreign():return json.loads(cmd('tc','-j','filter','show','dev','fghost','egress','pref','40000'))

ctl=None
def startctl(name='controller'):
 p=launch(['python3',P/'controller.py','--interface','fghost','--state',R/'controller','--helpers',P,'--lab-parent-netns',os.environ['FLOWGATE_PARENT_NETNS']],name)
 return p,line(p)
def control(op,**kw):
 d=ask(ctl,json.dumps(dict(op=op,**kw)));assert 'error' not in d,d;return d
def binding(n,inf,rate=4000000,**kw):
 local=f'10.79.0.1:{inf["sockets"][0]["port"]}' if inf['family']==4 else f'[fd79::1]:{inf["sockets"][0]["port"]}'
 remote='10.79.0.2:43001' if inf['family']==4 else '[fd79::2]:43001'
 out=[]
 for s in inf['sockets']:
  local=f'10.79.0.1:{s["port"]}' if inf['family']==4 else f'[fd79::1]:{s["port"]}'
  d=control('bind',protocol=inf['protocol'],local=local,remote=remote,rate=rate,**kw);out.append(d)
 return out

def measure(label,count=1000,delay=2000,change=None):
 h0=api();c0=cpu();p0=procusage();cp0=procusage(ctl.pid) if ctl and ctl.poll() is None else None;t=time.monotonic();tags={n:label+n for n in senders}
 for n,p in senders.items():write(p,f'SEND {tags[n]} {count if n.startswith("A") else 200 if n=="B" else 12} {delay if n.startswith("A") else 10000 if n=="B" else 50000}')
 if change:time.sleep(1);control('cap',app=change,rate=8000000)
 sent={n:line(p) for n,p in senders.items()};time.sleep(.5);elapsed=time.monotonic()-t;rx=peerop('stats');p1=procusage()
 rec={'kind':'phase','label':label,'wall_seconds':elapsed,'send':sent,'receive':{n:rx.get(tag,{'received':0}) for n,tag in tags.items()},'system_cpu_seconds':cpu()-c0,'daemon_cpu_seconds':p1['cpu']-p0['cpu'],'daemon_rss_kib':p1['rss_kib'],'controller_cpu_seconds':(procusage(ctl.pid)['cpu']-cp0['cpu']) if cp0 else None,'controller_rss_kib':procusage(ctl.pid)['rss_kib'] if cp0 else None,'queue_before':h0.get('queue_health'),'queue_after':api().get('queue_health'),'tc':json.loads(cmd('tc','-j','-s','qdisc','show','dev','fghost'))}
 assert rec['receive']['D']['received']==0,rec
 assert rec['receive']['B']['received']==sent['B']['sent'],rec
 records.append(rec);(R/'records.json').write_text(json.dumps(records,indent=2));print('PHASE',label,rec['receive'],flush=True);return rec

try:
 peer=launch(['unshare','--net','python3',P/'peer.py'],'peer')
 for _ in range(100):
  if os.readlink(f'/proc/{peer.pid}/ns/net')!=os.readlink('/proc/self/ns/net'):break
  time.sleep(.02)
 cmd('ip','link','add','fghost','type','veth','peer','name','fgpeer');cmd('ip','link','set','fgpeer','netns',peer.pid)
 for args in [('link','set','dev','fghost','addrgenmode','none'),('link','set','fghost','up'),('addr','add','10.79.0.1/24','dev','fghost'),('-6','addr','add','fd79::1/64','dev','fghost','nodad')]:cmd('ip',*args)
 peerop('setup')
 # Foreign tc object is installed by the test's separate owner and kept intact.
 cmd('tc','qdisc','add','dev','fghost','clsact');cmd('tc','filter','add','dev','fghost','egress','pref','40000','handle','7','matchall','action','pass');foreign_before=foreign()
 senders={};procs={}
 for name,exe in [('A','alpha'),('A2','alpha'),('B','beta'),('D','denied')]:
  p=launch([P/exe],name);line(p);senders[name]=p;procs[name]=inspect(p)
 assert procs['A']['application']['key']==procs['A2']['application']['key']!=procs['B']['application']['key']
 db=sqlite3.connect(R/'rules.db');db.execute('create table rules(id text primary key, document text not null)');db.execute('pragma user_version=1')
 for name in ['A','B','D']:
  a=procs[name]['application'];rule={'schema':2,'id':'m0-'+name,'version':1,'created':'2026-01-01T00:00:00Z','action':'block' if name=='D' else 'allow','priority':0,'executable':a['executable'],'filter':{'application':a['key'],'revision':a['revision'],'uid':0,'direction':'outgoing','protocol':'*'}};db.execute('insert into rules values(?,?)',(rule['id'],json.dumps(rule)))
 db.commit();db.close();os.chmod(R/'rules.db',0o600);(R/'state').mkdir(mode=0o700)
 backend=launch([P/'flowgate','host-start','--state',R/'state','--socket',API,'--database',R/'rules.db','--uid','0','--administrator','--profile','both','--duration','15m','--timeout','3s'],'daemon')
 for _ in range(150):
  try:
   if api().get('enforcement',{}).get('state')=='active':break
  except (FileNotFoundError,ConnectionRefusedError):pass
  time.sleep(.1)
 else:raise RuntimeError('daemon not ready')
 (R/'ready.json').write_text(json.dumps(api(),indent=2))

 # Existing foreign configuration: controller must refuse without deleting anything.
 rejected,hello=startctl('foreign-refusal');assert hello['status']=='Unsupported',hello;rejected.wait(5);assert foreign()==foreign_before
 records.append({'kind':'foreign-refusal','preserved':True,'response':hello})
 cmd('tc','qdisc','del','dev','fghost','clsact') # fixture owner's cleanup only
 infos={}
 for n,p in senders.items():
  inf=ask(p,f'OPEN 4 1 {2 if n.startswith("A") else 1} 1 0')
  if n=='D':assert 'error' in inf;inf={'family':4,'protocol':'tcp','sockets':[]}
  infos[n]=inf
 baseline=measure('baseline')
 ctl,hello=startctl();assert hello.get('ready'),hello
 initial=control('status');assert initial['status']=='Partial'
 ba=binding('A',infos['A']);binding('A2',infos['A2']);binding('B',infos['B'],100000000);app=ba[0]['app']
 first=control('status');assert len(first['bindings'])==5
 low=measure('cap4m')
 control('cap',app=app,rate=8000000);high=measure('cap8m')
 control('cap',app=app,rate=4000000);live=measure('livechange',change=app)
 control('remove',app=app);removed=measure('removed')
 assert all(b['app']!=app for b in control('status')['bindings'])
 records.append({'kind':'live-cap','same_existing_connections':True,'class_retired':True,'first_status':first['status']})
 # Failed/unknown new bindings never inherit a class. Inherited FD before binding refuses.
 for p in senders.values():ask(p,'CLOSE')
 a=ask(senders['A'],'OPEN 4 0 1 0 0');ask(senders['A'],'FORK')
 local=f'10.79.0.1:{a["sockets"][0]["port"]}'
 refusal=ask(ctl,json.dumps({'op':'bind','protocol':'udp','local':local,'remote':'10.79.0.2:43001','rate':4000000}))
 assert 'error' in refusal,refusal
 ask(senders['A'],'UNFORK');bound=binding('A',a)[0]
 # Unconnected socket, two peers, unchanged cookie/class across destinations.
 for port,tag in [(43001,'udppeer1'),(43002,'udppeer2')]:
  ask(senders['A'],f'PEER {port}');sent=ask(senders['A'],f'SEND {tag} 20 50000');time.sleep(.3);assert peerop('stats')[tag]['received']==sent['sent']==20
 after=control('status');assert any(b['cookie']==a['sockets'][0]['cookie'] and b['app']==bound['app'] for b in after['bindings'])
 records.append({'kind':'unconnected-multipeer','received_each':20,'same_binding':True,'inherited_unbound_refused':refusal})
 # Already-bound inheritance preserves origin; explicit fresh rebind of shared socket refuses.
 ask(senders['A'],'FORK');refusal=ask(ctl,json.dumps({'op':'bind','protocol':'udp','local':local,'remote':'10.79.0.2:43002','rate':4000000,'rebind':True}));assert 'error' in refusal
 assert any(b['cookie']==a['sockets'][0]['cookie'] for b in control('status')['bindings']);ask(senders['A'],'UNFORK')
 # Descriptor transfer keeps an existing origin binding; fresh ambiguous rebind refuses.
 up=str(R/'transfer.sock');write(senders['B'],'RECV '+up);assert line(senders['B'])['listening'];assert ask(senders['A'],'GIVE '+up)['sent_fd'];transferred=line(senders['B']);assert transferred['sockets'][0]['cookie']==a['sockets'][0]['cookie']
 refusal=ask(ctl,json.dumps({'op':'bind','protocol':'udp','local':local,'remote':'10.79.0.2:43002','rate':4000000,'rebind':True}));assert 'error' in refusal
 st=control('status');assert any(b['cookie']==a['sockets'][0]['cookie'] and b['app']==bound['app'] for b in st['bindings'])
 ask(senders['B'],'CLOSE');records.append({'kind':'descriptor-transfer','old_binding_preserved':True,'ambiguous_rebind_refused':True})
 # Kernel lease expiry after abrupt controller death. No stale cap automatically restored.
 ctl.kill();ctl.wait(3);time.sleep(5.5)
 journal=json.loads((R/'controller/owner.json').read_text());expired0=json.loads(cmd(P/'kernel','stats',journal['pin']))
 ask(senders['A'],'SEND expired 12 50000');time.sleep(.3);expired1=json.loads(cmd(P/'kernel','stats',journal['pin']));assert expired1[17]['packets']>expired0[17]['packets']
 assert peerop('stats')['expired']['received']==12
 ctl,hello=startctl('reconcile');assert hello.get('ready'),hello
 restarted=control('status');assert not restarted['bindings'] and restarted['status']=='Partial',restarted
 records.append({'kind':'failure-restart','lease_expired':True,'delivery_after_expiry':12,'fresh_binding_required':True,'status':restarted})
 # Bind again, close, and verify closure removes the kernel/controller entry.
 newbound=binding('A',a)[0];ask(senders['A'],'CLOSE');time.sleep(2.2);closed=control('status');assert not closed['bindings'],closed
 # Class retirement after ten seconds idle is bounded and non-reusing.
 time.sleep(10.5);retired=control('status');assert not retired['apps'],retired
 records.append({'kind':'close-retirement','binding_removed':True,'idle_class_retired':True})
 # IPv6 unconnected/multi-peer, and a denied exe deliberately bound for shaping.
 av6=ask(senders['A'],'OPEN 6 0 1 0 0');binding('A',av6)
 dv6=ask(senders['D'],'OPEN 6 0 1 0 0');binding('D',dv6)
 for port,tag in [(43001,'v6peer1'),(43002,'v6peer2')]:
  ask(senders['A'],f'PEER {port}');ask(senders['A'],f'SEND {tag} 12 50000');ask(senders['D'],f'SEND deny{port} 12 50000');time.sleep(.3);rx=peerop('stats');assert rx[tag]['received']==12 and rx.get(f'deny{port}',{}).get('received',0)==0
 records.append({'kind':'v6-multipeer-deny','allowed_each':12,'denied_each':0})
 # A foreign addition after acquisition must stop renewals and refuse destructive cleanup.
 cmd('tc','filter','add','dev','fghost','egress','pref','40000','handle','7','matchall','action','pass');foreign_added=foreign()
 time.sleep(1.5)
 msg=line(ctl);assert msg['status']=='Unsupported',msg;ctl.wait(5);assert foreign()==foreign_added
 records.append({'kind':'foreign-mutation','refused':msg,'preserved':True})
 # The fixture owner removes its own addition, enabling journal-based restart cleanup.
 cmd('tc','filter','del','dev','fghost','egress','pref','40000','handle','7','matchall')
 ctl,hello=startctl('final-reconcile');assert hello.get('ready'),hello;control('stop');ctl.wait(5)
 q=json.loads(cmd('tc','-j','qdisc','show','dev','fghost'));assert len(q)==1 and q[0]['kind']=='noqueue',q
 assert not (R/'controller/owner.json').exists()
 records.append({'kind':'cleanup','restored_noqueue':True,'owned_journal_removed':True})
 (R/'records.json').write_text(json.dumps(records,indent=2));(R/'success.json').write_text(json.dumps({'result':'M1_PASS','scope':'isolated native upload socket-binding controller'}));print('M1_PROOF_COMPLETE',flush=True)
except BaseException:
 (R/'failure.txt').write_text(traceback.format_exc());print(traceback.format_exc(),flush=True);raise
finally:
 if ctl and ctl.poll() is None:
  try:ask(ctl,json.dumps({'op':'stop'}));ctl.wait(5)
  except Exception:ctl.kill();ctl.wait()
 if backend and backend.poll() is None:
  try:cmd(P/'flowgate','host-stop','--state',R/'state')
  except Exception as e:print('STOP_ERROR',str(e),flush=True)
 for p in reversed(children):
  if p.poll() is None:p.terminate()
 for p in reversed(children):
  try:p.wait(3)
  except subprocess.TimeoutExpired:p.kill();p.wait()
 (R/'records.json').write_text(json.dumps(records,indent=2))

 for p in children:
  if p.stdout:
   rest=p.stdout.read()
   if rest:(R/f'child-{p.pid}-unread.txt').write_text(rest)
 if (R/'controller/ownership-mismatch.json').exists():(R/'ownership-mismatch.json').write_text((R/'controller/ownership-mismatch.json').read_text())

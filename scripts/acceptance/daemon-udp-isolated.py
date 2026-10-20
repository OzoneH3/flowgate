#!/usr/bin/env python3
"""Consolidated real daemon API check; never runs in the host network namespace.
--kernel requires initial-user-namespace root via check-daemon-udp.sh --kernel.
Default proves unavailable isolation, not kernel byte accuracy.
"""
import argparse,hashlib,json,os,signal,socket,subprocess,time
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--run',required=True);p.add_argument('--uid',type=int,required=True);p.add_argument('--gid',type=int,required=True);p.add_argument('--kernel',action='store_true');p.add_argument('--hold',action='store_true');p.add_argument('--traffic',action='store_true');p.add_argument('--evaluation-continuity',action='store_true');p.add_argument('--binary');a=p.parse_args()
root=Path(__file__).resolve().parents[2];run=Path(a.run).resolve();assert run.is_relative_to(root/'.workspace')
assert os.geteuid()==0 and os.environ['FLOWGATE_PARENT_NETNS']!=os.readlink('/proc/self/ns/net')
api_dir=run/'api';data=run/'data';api_dir.mkdir(mode=0o711);data.mkdir(mode=0o700)
binary=Path(a.binary).resolve() if a.binary else root/'.workspace/flowgate-udp-daemon';helper=root/'.workspace/udp-collector'
subprocess.run(['ip','link','set','lo','up'],check=True)
if a.kernel:
 # Private mount namespace overlays only the already-authorized FlowGate runtime
 # paths; backing files are in this test's workspace. Host paths/data stay intact.
 assert len(Path('/proc/self/uid_map').read_text().splitlines())==1 and Path('/proc/self/uid_map').read_text().split()[2]!='1'
 subprocess.run(['mount','--bind',str(api_dir),'/run/flowgate-api'],check=True)
 subprocess.run(['mount','--bind',str(data),'/var/lib/flowgate'],check=True)
 daemon_socket='/run/flowgate-api/daemon.sock';database='/var/lib/flowgate/rules.db'
else:
 daemon_socket=str(api_dir/'daemon.sock');database=str(data/'rules.db')
endpoint=api_dir/'daemon.sock';children=[];daemon=None
user={} if (a.uid==os.geteuid() and a.gid==os.getegid()) else dict(user=a.uid,group=a.gid,extra_groups=[])
def log(s):
 print(s,flush=True)
 with (run/'verification.log').open('a')as f:f.write(s+'\n')
def wait(f,seconds=12):
 until=time.monotonic()+seconds
 while time.monotonic()<until:
  v=f()
  if v:return v
  time.sleep(.05)
 raise AssertionError('timeout: '+str(f))
def api(op='list',root_peer=False,readonly=False,**q):
 old=os.geteuid()
 try:
  if not root_peer:os.seteuid(a.uid)
  s=socket.socket(socket.AF_UNIX);s.settimeout(4);s.connect(str(endpoint)+('.monitor'if readonly else ''))
 finally:os.seteuid(old)
 with s:
  s.sendall((json.dumps(dict(version=1,operation=op,**q))+'\n').encode());b=b''
  while b'\n'not in b:
   d=s.recv(65536)
   if not d:raise RuntimeError('API closed')
   b+=d
  return json.loads(b)
def start_daemon(admin=True):
 global daemon
 cmd=[str(binary),'serve','--socket',daemon_socket,'--database',database,'--uid',str(a.uid),'--udp-helper',str(helper)]
 if a.evaluation_continuity:cmd+=['--allow-evaluation','--evaluation-state','/run/flowgate-api/evaluation']
 if admin:cmd+=['--administrator','--allow-traffic-control']
 with (run/'daemon.log').open('a')as f:daemon=subprocess.Popen(cmd,stdout=f,stderr=f)
 def ready():
  if daemon.poll()is not None:raise RuntimeError((run/'daemon.log').read_text())
  try:return api()['enforcement']['state']=='stopped'
  except (OSError,ValueError):return False
 wait(ready);return api()
def mutate(op,root_peer=False):
 s=api(root_peer=root_peer)
 return api(op,root_peer=root_peer,generation=s['generation'],collector_generation=s['traffic_monitor'].get('generation',''))
def fixture(family):
 f=subprocess.Popen([str(root/'.workspace/udp-fixtures/alpha'),family,'basic'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True,**user);children.append(f);s=json.loads(f.stdout.readline());return f,s
def transfer(f):f.stdin.write('transfer\n');f.stdin.flush();return json.loads(f.stdout.readline())
def measured(state):
 rows={r['socket']['cookie']:r for r in api()['activity']['rows']}
 return all(k in rows and rows[k]['traffic']['available'] for k in state['cookies'])
def verify(state):
 def equal():
  rows={r['socket']['cookie']:r for r in api()['activity']['rows']}
  for i,k in enumerate(state['cookies']):
   t=rows.get(k,{}).get('traffic',{})
   if not t.get('available')or t['uploaded']!=state['uploaded'][i]or t['downloaded']!=state['downloaded'][i]:return False
  return True
 wait(equal)
def tcp_present():return any(r['socket']['protocol']=='tcp'and r['traffic']['available']for r in api().get('activity',{}).get('rows',[]))
def cpu(pid):
 f=Path(f'/proc/{pid}/stat').read_text().split(') ')[1].split();rss=int(next(v.split()[1]for v in Path(f'/proc/{pid}/status').read_text().splitlines()if v.startswith('VmRSS:')));return (int(f[11])+int(f[12]))/os.sysconf('SC_CLK_TCK'),rss
def native_pid():
 # Go forks the helper from whichever OS thread runs the Start goroutine, and
 # task/<tid>/children is per-thread: take the union over the daemon's threads,
 # then require exactly one direct child running the pinned reviewed helper.
 ids=set()
 for t in Path(f'/proc/{daemon.pid}/task').iterdir():
  try:ids.update(int(v)for v in (t/'children').read_text().split())
  except FileNotFoundError:pass
 want=hashlib.sha256(helper.read_bytes()).digest();found=[]
 for c in sorted(ids):
  try:
   ppid=int(Path(f'/proc/{c}/stat').read_text().rsplit(') ',1)[1].split()[1])
   exe=os.readlink(f'/proc/{c}/exe');image=Path(f'/proc/{c}/exe').read_bytes()
  except OSError:continue
  if ppid==daemon.pid and Path(exe).parent==Path(daemon_socket).parent and Path(exe).name.startswith('.flowgate-udp-')and hashlib.sha256(image).digest()==want:found.append(c)
 assert len(found)==1,(sorted(ids),found);return found[0]
try:
 before_rules=subprocess.check_output(['nft','-j','list','ruleset'])
 before_routes=subprocess.check_output(['ip','-j','route','show','table','all'])
 before_routes6=subprocess.check_output(['ip','-6','-j','route','show','table','all'])
 if a.evaluation_continuity:
  assert a.kernel, 'continuity requires isolated initial-namespace BPF authority'
  subprocess.run(['nft','-f','-'],input='table inet unrelated_fixture {\n chain track {\n  type filter hook input priority 0; policy accept;\n  ct state established counter;\n }\n}\n',text=True,check=True)
 s=start_daemon();assert 'daemon-udp-monitor-v1'in s['capabilities']and s['traffic_monitor']['state']=='disabled'
 # Real persistent TCP exchange continues regardless of UDP lifecycle/failure.
 listen=socket.socket();listen.bind(('127.0.0.1',0));listen.listen();client=socket.socket();client.connect(listen.getsockname());accepted,_=listen.accept();client.sendall(b'tcp-baseline');assert accepted.recv(12)==b'tcp-baseline';wait(tcp_present)
 denied=api('traffic-start',readonly=True,generation=s['generation'],collector_generation='');assert denied['error_code']=='forbidden'
 assert api('traffic-start',generation='stale',collector_generation='')['error_code']=='generation_conflict'
 assert api('traffic-start',generation=s['generation'],collector_generation='stale')['error_code']=='collector_conflict'
 if a.evaluation_continuity:
  from evaluation_udp_continuity import check
  check(globals())
  raise SystemExit(0)
 if a.hold:
  import sys,threading
  held=[(f,fam)for fam in ['4','6']for f,_ in [fixture(fam)]];lock=threading.Lock();done=threading.Event()
  def exchange():
   # Cumulative fixture-side counts, atomically published so a UI can compare
   # displayed totals with receiver truth. Fixtures outlive collector Stop/Start.
   states=[dict(transfer(f),pid=f.pid,family=fam)for f,fam in held]
   tmp=run/'receiver.json.tmp';tmp.write_text(json.dumps(dict(states=states,at=time.time()),indent=2));os.replace(tmp,run/'receiver.json')
   return states
  def steady():
   # --traffic: one UDP4/6 + TCP exchange per second; the collector stays
   # disabled until a client Starts it. Touching run/quit ends the hold.
   while not done.wait(1):
    if (run/'quit').exists():done.set();break
    with lock:exchange();client.sendall(b'tcp-baseline');accepted.recv(12)
  def commands():
   for line in sys.stdin:
    q=json.loads(line)if line.strip().startswith('{')else dict(operation=line.strip())
    if q.get('operation')=='quit':break
    if q.get('operation')=='transfer':
     with lock:states=exchange()
     print(json.dumps(dict(receiver_states=states)),flush=True)
   else:
    if a.traffic:return  # EOF: unattended continuous hold ends only via quit/file/Ctrl+C
   done.set()
  threading.Thread(target=commands,daemon=True).start()
  if a.traffic:threading.Thread(target=steady,daemon=True).start()
  (run/'ready.json').write_text(json.dumps(dict(socket=str(endpoint),monitor_socket=str(endpoint)+'.monitor',pid=daemon.pid,generation=s['generation'],kernel=a.kernel,collector=api()['traffic_monitor']['state'],continuous_traffic=a.traffic,fixture='owned isolated native UDP4/UDP6, no host collection')))
  log('READY isolated UI attachment '+str(endpoint)+('; continuous UDP4/6+TCP'if a.traffic else '')+'; end with a quit line'+(', Ctrl+C'if a.traffic else ' or Ctrl+D')+' or touch '+str(run/'quit'))
  while not done.wait(.5):
   if (run/'quit').exists():done.set()
  with lock:log('HOLD ended; cleaning up owned fixtures/daemon/helper')
  raise SystemExit(0)
 first=mutate('traffic-start');assert 'error'not in first,first
 (run/'api-example.json').write_text(json.dumps(dict(request=dict(version=1,operation='traffic-start',generation=s['generation'],collector_generation=''),response={k:first[k]for k in ['version','generation','permissions','traffic_monitor','enforcement','capabilities']}),indent=2))
 if not a.kernel:
  failed=wait(lambda:api()['traffic_monitor']if api()['traffic_monitor']['state']=='failed'else None)
  assert failed['reason_code']in ['bpf_load_failed','permission_required'],failed
  (run/'actual-load-error.json').write_text(json.dumps(failed,indent=2));wait(tcp_present)
  stop=mutate('traffic-stop');assert stop['traffic_monitor']['state']=='disabled'
  assert api()['enforcement']['state']=='stopped'
  c0,rss=cpu(daemon.pid);at=time.monotonic();time.sleep(3);c1,_=cpu(daemon.pid);log(f'BASELINE ONLY (UDP denied): daemon {time.monotonic()-at:.2f}s CPU {c1-c0:.3f}s RSS {rss}KiB; no BPF overhead measured')
  log('PASS actual production serve/authenticated API: denied BPF in user namespace -> failed; Stop leaves TCP/rules/daemon alive; read-only lifecycle denied')
  log('KERNEL UDP ACCURACY NOT VERIFIED: '+failed['reason'])
 else:
  active=wait(lambda:api()['traffic_monitor']if api()['traffic_monitor']['state']=='active'else None)
  repeat=mutate('traffic-start');assert repeat['traffic_monitor']['generation']==active['generation'];hp=native_pid()
  conflict=subprocess.run([str(helper),'all',str(os.stat('/proc/self/ns/net').st_ino)],input='',capture_output=True,text=True);assert conflict.returncode!=0 and 'collector_conflict'in conflict.stderr
  held=[]
  for family in ['4','6']:
   f,state=fixture(family);wait(lambda:measured(state));state=transfer(f);verify(state);held.append((f,state))
   log('PASS receiver-backed consolidated UDP'+family+' connected/unconnected/peers: API-returned byte counts equal fixture receiver/send counts')
  old=active['generation'];mutate('traffic-stop');wait(tcp_present)
  wait(lambda:not any(r['traffic']['available']for r in api()['activity']['rows']if r['socket']['protocol']=='udp'))
  assert mutate('traffic-start')['traffic_monitor']['state']=='starting'
  new=wait(lambda:api()['traffic_monitor']if api()['traffic_monitor']['state']=='active'else None);assert new['generation']!=old
  stale=api('traffic-stop',generation=s['generation'],collector_generation=old);assert stale['error_code']=='collector_conflict'
  for f,state in held:
   wait(lambda:measured(state));rows={r['socket']['cookie']:r for r in api()['activity']['rows']};assert all(rows[k]['traffic']['uploaded']==0 for k in state['cookies'])
  hp=native_pid();c0,rss=cpu(daemon.pid);h0,hrss=cpu(hp);start=time.monotonic()
  for f,state in held:transfer(f)
  time.sleep(3);c1,_=cpu(daemon.pid);h1,_=cpu(hp);elapsed=time.monotonic()-start
  log(f'OVERHEAD consolidated daemon+helper {elapsed:.2f}s CPU {c1+h1-c0-h0:.3f}s RSS {rss+hrss}KiB (probe time in callers excluded)')
  os.kill(hp,signal.SIGKILL);wait(lambda:api()['traffic_monitor']['state']=='failed');wait(tcp_present)
  assert mutate('traffic-start')['traffic_monitor']['state']=='starting';wait(lambda:api()['traffic_monitor']['state']=='active');mutate('traffic-stop')
  log('PASS duplicate Start, namespace exclusion, client disconnect, Stop, restart baseline, stale Stop, owned helper crash/restart; TCP continuous')
  # Restart same database without delegated lifecycle permission. Root explicitly
  # controls collector while the ordinary peer keeps only its visible measurements.
  daemon.terminate();daemon.wait(8);s=start_daemon(False)
  assert not s['permissions']['can_control_traffic'];assert mutate('traffic-start')['error_code']=='forbidden'
  assert 'error'not in mutate('traffic-start',root_peer=True);wait(lambda:api()['traffic_monitor']['state']=='active')
  f,state=held[0];wait(lambda:measured(state));root_udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);root_udp.bind(('127.0.0.1',0));foreign_port=root_udp.getsockname()[1]
  time.sleep(1.5);s=api();assert all(not(r['socket']['protocol']=='udp'and r['socket']['local'].endswith(':'+str(foreign_port)))for r in s['activity']['rows']);assert s['traffic_monitor']['missed_operations']==0
  assert mutate('traffic-stop')['error_code']=='forbidden';assert 'error'not in mutate('traffic-stop',root_peer=True)
  log('PASS ordinary measurement visibility/self projection, foreign root socket withheld, no ordinary machine lifecycle authority; same rules/database preserved')
 assert subprocess.check_output(['nft','-j','list','ruleset'])==before_rules
 assert subprocess.check_output(['ip','-j','route','show','table','all'])==before_routes
 assert subprocess.check_output(['ip','-6','-j','route','show','table','all'])==before_routes6
 assert not api().get('rules')and api()['enforcement']['state']=='stopped'
 (run/'result.json').write_text(json.dumps(dict(kernel=a.kernel,namespace=os.readlink('/proc/self/ns/net'),state=api()['traffic_monitor'],firewall_unchanged=True,routes_unchanged=True),indent=2))
 log('EVIDENCE '+str(run))
finally:
 for f in children:
  if f.poll()is None:f.terminate();f.wait(4)
 if daemon and daemon.poll()is None:daemon.terminate();daemon.wait(8)

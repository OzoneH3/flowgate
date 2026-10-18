#!/usr/bin/env python3
"""Disposable current-netns/cgroup-filtered TCP event verification, never host API."""
import argparse,json,os,pathlib,socket,subprocess,time,signal
ROOT=pathlib.Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument('--run',required=True);p.add_argument('--binary',required=True);p.add_argument('--helper',required=True);p.add_argument('--native',required=True);p.add_argument('--expect-failed',action='store_true');p.add_argument('--observe-shared',action='store_true');a=p.parse_args()
assert os.environ['FLOWGATE_PARENT_NETNS']!=os.readlink('/proc/self/ns/net')
RUN=pathlib.Path(a.run).resolve();assert RUN.is_relative_to(ROOT/'.workspace');RUN.mkdir(mode=0o700,parents=True,exist_ok=True)
for d in ['api','data']:(RUN/d).mkdir(mode=0o700)
subprocess.run(['ip','link','set','lo','up'],check=True)
API=str(RUN/'api/c.sock');DATABASE=str(RUN/'data/rules.db');backend=native=None;foreign_before=None;passed=False
# Initial-root test credentials must retain their authority, but the production
# daemon refuses a runtime/database beneath user-owned ancestors. Reuse the UDP
# fixture's PRIVATE mount overlays, backed solely by this workspace's directories.
# Never chown the repository or weaken production SecureDirectory.
if os.geteuid()==0 and pathlib.Path('/proc/self/uid_map').read_text().split()[2]!='1':
 assert os.environ['FLOWGATE_PARENT_MNTNS']!=os.readlink('/proc/self/ns/mnt')
 subprocess.run(['mount','--bind',str(RUN/'api'),'/run/flowgate-api'],check=True)
 subprocess.run(['mount','--bind',str(RUN/'data'),'/var/lib/flowgate'],check=True)
 API='/run/flowgate-api/c.sock';DATABASE='/var/lib/flowgate/rules.db'
 foreign_before=json.loads(subprocess.check_output(['bpftool','-j','cgroup','show','/sys/fs/cgroup','effective'],text=True))
 (RUN/'foreign-programs-before.json').write_text(json.dumps(foreign_before,indent=2))
def log(message):
 print(message,flush=True)
 with (RUN/'verification.log').open('a') as f:f.write(message+'\n')

def api():
 with socket.socket(socket.AF_UNIX)as s:s.settimeout(10);s.connect(API);s.sendall(b'{"version":1,"operation":"list"}\n');return json.loads(s.makefile('rb').readline())
def wait(fn,seconds=12):
 end=time.monotonic()+seconds
 while time.monotonic()<end:
  try:
   v=fn()
   if v:return v
  except (OSError,ValueError):pass
  time.sleep(.05)
 raise AssertionError('timeout')
def ask(op,n=8):
 native.stdin.write(json.dumps(dict(op=op,n=n))+'\n');native.stdin.flush();return json.loads(native.stdout.readline())
def start(events):
 global backend
 args=[a.binary,'serve','--socket',API,'--database',DATABASE,'--uid','0','--administrator']
 if events:args+=['--tcp-initiation-helper',a.helper,'--tcp-initiation-cgroup','/sys/fs/cgroup']
 if events and a.observe_shared:args+=['--tcp-initiation-observe-shared']
 backend=subprocess.Popen(args,stdout=(RUN/'daemon.log').open('a'),stderr=subprocess.STDOUT)
 def ready():
  if backend.poll()is not None:raise RuntimeError((RUN/'daemon.log').read_text())
  return api()
 return wait(ready)
def stop():
 if backend and backend.poll()is None:backend.terminate();backend.wait(15)
 assert not pathlib.Path(API).exists()
def checkrows(expected,known):
 snap=wait(lambda:(lambda r:r if all(x['cookie']in {y['socket']['cookie']for y in r['activity']['rows']}for x in expected)else None)(api()))
 rows={r['socket']['cookie']:r for r in snap['activity']['rows']}
 for x in expected:
  row=rows[x['cookie']];v=row['initiation'];assert row['socket']['state']==1
  if known:assert v['state']=='known'and v['direction']==x['role']and v['source'].startswith('cgroup-sockops-'),(x,v)
  else:assert v['state']=='unknown',(x,v)
 return snap
try:
 native=subprocess.Popen([a.native],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True);assert json.loads(native.stdout.readline())['ready']
 start(False);before=ask('open');baseline=checkrows(before['rows'],False);(RUN/'sampling-missed-fast-handshakes.json').write_text(json.dumps({'native':before,'states':[{k:r[k]for k in ['id','initiation']}for r in baseline['activity']['rows']if r['socket']['cookie']in{x['cookie']for x in before['rows']}]},indent=2));log('PASS ordinary fast native TCP4/6 handshakes establish before snapshot; sampling reports unknown')
 ask('close');stop();start(True)
 status=wait(lambda:(lambda s:s if s['state']in ['active','failed']else None)(api()['activity'].get('tcp_initiation',{})))
 (RUN/'collector-status.json').write_text(json.dumps(status,indent=2))
 if a.expect_failed:
  assert status['state']=='failed',status
  fresh=ask('open');checkrows(fresh['rows'],False);assert api()['enforcement']['state']=='stopped'
  log('PASS actual BPF refusal captured; native TCP observations/rules/monitor remain usable: '+status['reason'])
 else:
  assert status['state']=='active',status
  fresh=ask('open');s=wait(lambda:checkrows(fresh['rows'],True));generation=s['activity']['tcp_initiation']['generation'];(RUN/'event-known.json').write_text(json.dumps({'native':fresh,'activity':s['activity']},indent=2));log('PASS fast native TCP4/6 active+passive and both loopback ends known by exact cookies')
  ask('close');wait(lambda:not any(r['socket']['cookie']in{x['cookie']for x in fresh['rows']}for r in api()['activity']['rows']))
  next=ask('open');assert not ({x['cookie']for x in fresh['rows']}&{x['cookie']for x in next['rows']});checkrows(next['rows'],True);log('PASS closure/new sockets use distinct cookies, no initiation inheritance')
  stop();start(True);new=wait(lambda:(lambda s:s if s['state']in ['active','failed']else None)(api()['activity'].get('tcp_initiation',{})));assert new['state']=='active'and new['generation']!=generation;checkrows(next['rows'],False);ask('close');last=ask('open');checkrows(last['rows'],True);log('PASS collector restart clears evidence: pre-existing established sockets unknown, new connections known')
  children=pathlib.Path(f'/proc/{backend.pid}/task/{backend.pid}/children').read_text().split();owned=[int(pid)for pid in children if '.flowgate-initiation-'in os.readlink(f'/proc/{pid}/exe')];assert len(owned)==1;os.kill(owned[0],signal.SIGTERM)
  wait(lambda:api()['activity']['tcp_initiation']['state']=='failed');assert api()['enforcement']['state']=='stopped';assert api()['activity']['rows'];log('PASS helper crash leaves TCP observation/daemon/rules available; old event evidence withheld')
  (RUN/'overhead.json').write_text(json.dumps({'connections_per_family':8,'baseline_open_ns':before['duration_ns'],'event_open_ns':fresh['duration_ns'],'note':'short loopback sample, includes scheduling/socket setup; not a general benchmark'},indent=2))
 passed=True
finally:
 stop()
 if native and native.poll()is None:native.terminate();native.wait(5)
 if foreign_before is not None:
  after=json.loads(subprocess.check_output(['bpftool','-j','cgroup','show','/sys/fs/cgroup','effective'],text=True))
  (RUN/'foreign-programs-after.json').write_text(json.dumps(after,indent=2))
  assert sorted(foreign_before,key=lambda p:p['id'])==sorted(after,key=lambda p:p['id']),'Foreign cgroup program inventory changed'
  log('PASS foreign effective cgroup programs preserved exactly after own link/helper cleanup')
 log('CLEANED owned daemon/native helper links/maps; disposable namespace only')
 if passed:(RUN/'result.json').write_text(json.dumps({'result':'passed-refusal-fallback'if a.expect_failed else'passed-kernel-initiation','source':(RUN/'source.sha').read_text().strip()if(RUN/'source.sha').exists()else None,'shared_observation':a.observe_shared,'foreign_inventory_preserved':foreign_before is not None,'host_runtime_untouched':True},indent=2))

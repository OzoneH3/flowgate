#!/usr/bin/env python3
"""Real BPF acceptance, only inside a disposable privileged network namespace.
Fixtures/observer use the caller's unprivileged UID. The Wayland GUI runs outside.
"""
import argparse,hashlib,json,os,signal,socket,subprocess,time
from pathlib import Path
root=Path(__file__).resolve().parents[2]
p=argparse.ArgumentParser();p.add_argument('--run',required=True);p.add_argument('--uid',type=int,default=os.getuid());p.add_argument('--gid',type=int,default=os.getgid());p.add_argument('--gui',action='store_true');args=p.parse_args();run=Path(args.run).resolve()
assert run.is_relative_to(root/'.workspace')
assert os.environ['FLOWGATE_PARENT_NETNS']!=os.readlink('/proc/self/ns/net')
run.mkdir(mode=0o755,parents=True,exist_ok=True)
subprocess.run(['ip','link','set','lo','up'],check=True)
uid=args.uid;children=[];orphans=[];collector=None
signal.signal(signal.SIGTERM,lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
user=dict(user=uid,group=args.gid,extra_groups=[])
# All root-side evidence lives under the workspace; no host tracing configuration.
def log(s):print(s,flush=True)
def wait(f,seconds=12):
 end=time.monotonic()+seconds
 while time.monotonic()<end:
  v=f()
  if v:return v
  time.sleep(.08)
 raise AssertionError('timeout')
def snapshot(op='list',path=None):
 old=os.geteuid()
 try:
  os.seteuid(uid)
  s=socket.socket(socket.AF_UNIX);s.settimeout(2);s.connect(str(path or run/'api.sock'))
 finally:os.seteuid(old)
 with s:
  s.sendall(json.dumps({'version':1,'operation':op}).encode()+b'\n');data=b''
  while b'\n'not in data:
   b=s.recv(65536)
   if not b:raise RuntimeError('API closed without response')
   data+=b
  return json.loads(data)
def start():
 global collector
 collector=subprocess.Popen([str(root/'.workspace/udp-test-driver'),str(run/'api.sock'),str(root/'.workspace/udp-collector'),str(uid)],stdout=(run/'collector.log').open('a'),stderr=subprocess.STDOUT);children.append(collector)
 def ready():
  if collector.poll()is not None:raise RuntimeError((run/'collector.log').read_text())
  return (run/'api.sock').exists()
 wait(ready);wait(lambda:snapshot()['state']=='active')
def stop():
 snapshot('stop');collector.wait(5);wait(lambda:not(run/'api.sock').exists())
def fixture(family,mode='basic',app='alpha'):
 cmd=[str(root/f'.workspace/udp-fixtures/{app}'),family,mode]
 if mode=='shared':cmd+=[str(root/'.workspace/udp-fixtures/beta')]
 f=subprocess.Popen(cmd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True,**user);children.append(f)
 state=json.loads(f.stdout.readline());
 if state['child']>0:orphans.append(state['child'])
 wait(lambda:all(k in snapshot()['rows']for k in state['cookies']+state.get('peers',[])))
 return f,state
def command(f,cmd):f.stdin.write(cmd+'\n');f.stdin.flush();line=f.stdout.readline();assert line,'fixture exited';return json.loads(line)
def counts(state,prefix=None):
 def correct():
  rows=snapshot()['rows'];expected={}
  for i,k in enumerate(state['cookies']):
   up=state['uploaded'][i]+(prefix['uploaded'][i]if prefix else 0);down=state['downloaded'][i]+(prefix['downloaded'][i]if prefix else 0)
   r=rows.get(k)
   if not r or r['uploaded']!=up or r['downloaded']!=down:return False
   expected[k]=r
  return expected
 return wait(correct)
def activity():return snapshot(path=run/'observer.sock')['activity']
def row(cookie):return next((r for r in activity()['rows']if r['socket']['cookie']==cookie),None)
try:
 start()
 observer=subprocess.Popen([str(root/'.workspace/flowgate'),'observe','--socket',str(run/'observer.sock'),'--udp-socket',str(run/'api.sock'),'--interval','500ms'],stdout=(run/'observer.log').open('w'),stderr=subprocess.STDOUT,**user);children.append(observer)
 wait(lambda:(run/'observer.sock').exists());wait(lambda:not activity().get('error'))
 retained=[]
 for family in ['4','6']:
  f,initial=fixture(family);before=wait(lambda:row(initial['cookies'][0]));s=command(f,'transfer');counts(s);after=wait(lambda:row(s['cookies'][0])if row(s['cookies'][0])['traffic']['uploaded']==26 else None)
  assert before['id']==after['id'],'connect replaced UDP socket identity'
  s=command(f,'edges');counts(s)
  idle=wait(lambda:row(s['cookies'][0])if row(s['cookies'][0])['traffic'].get('upload_bps')==0 else None);assert idle['traffic']['uploaded']==26
  log('PASS kernel UDP'+family+' connected/unconnected/wildcard, multiple peers, loopback, PEEK/TRUNC/failed send; idle zero; stable connect row')
  old=s['cookies'][0];oldport=s['ports'][0];s=command(f,'rebind');assert s['ports'][0]==oldport and s['cookies'][0]!=old
  wait(lambda:s['cookies'][0]in snapshot()['rows'] and old not in snapshot()['rows']);counts(s)
  s=command(f,'transfer');counts(s);wait(lambda:row(old)is None)
  log('PASS UDP'+family+' same endpoint rebound to new cookie, no inherited totals; old observation removed')
  retained.append((f,s))
  f,shared=fixture(family,'shared');wait(lambda:len(row(shared['cookies'][0])['owners'])==2)
  shared=command(f,'transfer');counts(shared);prefix=shared
  before_shared=wait(lambda:row(shared['cookies'][0])if row(shared['cookies'][0])['traffic']['uploaded']==26 else None)
  handoff=command(f,'handoff');f.wait(3);assert handoff['cookies']==shared['cookies']
  wait(lambda:len(row(shared['cookies'][0])['owners'])==1)
  childstate=command(f,'transfer');counts(childstate,prefix)
  after_shared=wait(lambda:row(shared['cookies'][0])if row(shared['cookies'][0])['traffic']['uploaded']==52 else None)
  assert after_shared['traffic']['since']==before_shared['traffic']['since']
  assert any(p['executable'].endswith('/udp-fixtures/beta')for p in activity()['processes'].values()if p['id']in after_shared['owners'])
  log('PASS UDP'+family+' shared FD counted once; parent exits, beta retains/operates same cookie without resetting totals')
  f.stdin.write('quit\n');f.stdin.flush();wait(lambda:all(k not in snapshot()['rows']for k in shared['cookies']))
  os.waitpid(shared['child'],0);orphans.remove(shared['child'])
  log('PASS UDP'+family+' final shared reference closes and cookie state is removed')
  f2,rp=fixture(family,'reuseport','beta');rp=command(f2,'reuse');counts(rp)
  assert rp['downloaded'][1]>0 and rp['downloaded'][2]>0
  assert sum(rp['downloaded'])==sum(200+i for i in range(32))
  assert rp['cookies'][1]!=rp['cookies'][2] and rp['ports'][1]==rp['ports'][2]
  log('PASS UDP'+family+' SO_REUSEPORT actual receiver selection: distinct cookies, summed receive bytes exactly once')
 # Restart with existing sockets: no inherited interval, no spikes.
 generation=snapshot()['generation'];stop();wait(lambda:activity()['udp']['state']=='disconnected')
 assert all(not r['traffic']['available']for r in activity()['rows']if r['socket']['protocol']=='udp')
 start();assert snapshot()['generation']!=generation
 f,old=retained[0];wait(lambda:old['cookies'][0]in snapshot()['rows']);new=wait(lambda:row(old['cookies'][0])if row(old['cookies'][0])['traffic']['available']else None)
 assert new['traffic']['uploaded']==0 and new['traffic'].get('upload_bps')in (None,0)
 s=command(f,'transfer');baseline=old;delta=dict(s,uploaded=[s['uploaded'][i]-old['uploaded'][i]for i in range(3)],downloaded=[s['downloaded'][i]-old['downloaded'][i]for i in range(3)])
 counts(delta)
 log('PASS collector Stop/loss/restart: unavailable during gap, new generation/baseline, current sockets preserved without spike')
 # Intentional pre-registration gap, surfaced separately rather than hidden.
 fast=subprocess.run(['python3','-c','import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.sendto(b"gap",("127.88.0.1",9));s.close()'],check=True,**user)
 wait(lambda:snapshot()['missed_operations']>0)
 log('PASS pre-registration miss is reported as partial coverage; no tuple-based invented association')
 if args.gui:
  # Retain fresh shared ownership through the GUI journey.
  gui_shared,gs=fixture('4','shared');first,one=fixture('4','basic','alpha');second,two=fixture('6','basic','beta')
  wait(lambda:len(row(gs['cookies'][0])['owners'])==2)
  (run/'ready.json').write_text(json.dumps({'netns':os.readlink('/proc/self/ns/net'),'uid':uid,'observer':str(run/'observer.sock')}))
  wait(lambda:(run/'gui-start').exists(),30)
  def cost():
   ids=[collector.pid];ids+=list(map(int,Path(f'/proc/{collector.pid}/task/{collector.pid}/children').read_text().split()))
   cpu=rss=0
   for pid in ids:
    fields=Path(f'/proc/{pid}/stat').read_text().split();cpu+=int(fields[13])+int(fields[14]);status=Path(f'/proc/{pid}/status').read_text();rss+=int(next(x.split()[1]for x in status.splitlines()if x.startswith('VmRSS:')))
   return cpu/os.sysconf('SC_CLK_TCK'),rss
  cpu0,_=cost();at=time.monotonic();loss0=snapshot()['missed_operations'];maxrows=0
  while not(run/'gui-finished.json').exists() and time.monotonic()-at<25:
   command(first,'burst');command(second,'burst');command(gui_shared,'burst');maxrows=max(maxrows,len(snapshot()['rows']));time.sleep(.35)
  cpu1,rss=cost();elapsed=time.monotonic()-at
  assert (run/'gui-finished.json').exists(),'GUI did not finish'
  assert json.loads((run/'gui-finished.json').read_text())['passed']
  loss1=snapshot()['missed_operations'];assert loss1==loss0,'missed operations during registered transfer'
  log(f'OVERHEAD collector+helper {elapsed:.2f}s, CPU {cpu1-cpu0:.3f}s ({100*(cpu1-cpu0)/elapsed:.2f}% one CPU), RSS {rss}KiB, rows {maxrows}/2048, registered-transfer misses {loss1-loss0}')
  log('PASS actual unprivileged Wayland measured UDP rows, numeric sort, shared/Unidentified and stable selection')
 log('EVIDENCE '+str(run))
 (run/'result.json').write_text(json.dumps({'passed':True,'kernel':os.uname().release,'netns':os.readlink('/proc/self/ns/net'),'uid':uid,'missed_operations':snapshot()['missed_operations'],'binaries':{name:hashlib.sha256((root/name).read_bytes()).hexdigest()for name in ['.workspace/flowgate','.workspace/udp-collector','.workspace/udp-fixtures/alpha','.workspace/udp-fixtures/beta']}}))
finally:
 for f in children[::-1]:
  if f.poll()is None:f.terminate();f.wait(5)
 for pid in orphans:
  try:os.kill(pid,signal.SIGTERM);os.waitpid(pid,0)
  except (ProcessLookupError,ChildProcessError):pass

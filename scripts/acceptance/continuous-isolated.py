#!/usr/bin/env python3
"""Component verification with real TUN/IP/netfilter, generic disjoint mark rules.
No VPN enrollment, encryption or live-host forwarding is performed.
"""
import json,os,socket,struct,fcntl,select,subprocess,tempfile,time,threading,sys,uuid,signal
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];BIN=os.environ.get('FLOWGATE_TEST_BINARY',str(ROOT/'.workspace/flowgate-continuous'))
assert os.environ['FLOWGATE_PARENT_NETNS']!=os.readlink('/proc/self/ns/net')
RUN=Path(tempfile.mkdtemp(prefix='continuous-component-',dir=ROOT/'.workspace'))
def cmd(*args):return subprocess.check_output(args,text=True,stderr=subprocess.STDOUT)
left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_DGRAM)
peer=subprocess.Popen(['unshare','--net','python3',str(ROOT/'scripts/acceptance/tun-peer.py'),str(right.fileno()),str(RUN)],pass_fds=[right.fileno()],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True);right.close()
tun=os.open('/dev/net/tun',os.O_RDWR);fcntl.ioctl(tun,0x400454ca,struct.pack('16sH',b'fixturetun0',0x1001))
def pump():
 while True:
  r,_,_=select.select([tun,left],[],[])
  for s in r:
   if s==tun:left.send(os.read(tun,65535))
   else:
    b=left.recv(65535)
    try:os.write(tun,b)
    except OSError as e:
     if e.errno!=5:raise # startup control packet before link-up
threading.Thread(target=pump,daemon=True).start()
def remote(op,**kw):
 peer.stdin.write(json.dumps(dict(op=op,**kw))+'\n');peer.stdin.flush();r=json.loads(peer.stdout.readline());assert 'error'not in r,r;return r
def wait(fn,seconds=10):
 end=time.monotonic()+seconds
 while time.monotonic()<end:
  r=fn()
  if r:return r
  time.sleep(.04)
 raise AssertionError('timeout')
wait(lambda:os.readlink(f'/proc/{peer.pid}/ns/net')!=os.readlink('/proc/self/ns/net'))
cmd('ip','link','set','fixturetun0','up');cmd('ip','addr','add','10.79.0.1/32','dev','fixturetun0');cmd('ip','-6','addr','add','fd79::1/128','dev','fixturetun0','nodad')
remote('setup')
# Generic masked policy routing with arbitrary priorities/table.
cmd('ip','link','add','underlay0','type','dummy');cmd('ip','link','set','underlay0','up')
for family,prefix in [('-4','10.79.0.2/32'),('-6','fd79::/64')]:
 cmd('ip',family,'route','add',prefix,'dev','fixturetun0','table','107')
 cmd('ip',family,'route','add','default','dev','underlay0')
 for pr,table in [('6210','main'),('6230','default')]:cmd('ip',family,'rule','add','priority',pr,'fwmark','0x80000/0xff0000','lookup',table)
 cmd('ip',family,'rule','add','priority','6250','fwmark','0x80000/0xff0000','type','unreachable')
 cmd('ip',family,'rule','add','priority','6270','lookup','107')
for tool in ['iptables','ip6tables']:
 for chain in ['fixture-input','fixture-forward']:cmd(tool,'-N',chain)
 cmd(tool,'-A','INPUT','-j','fixture-input');cmd(tool,'-A','FORWARD','-j','fixture-forward')
 cmd(tool,'-A','fixture-input','-i','fixturetun0','-j','ACCEPT');cmd(tool,'-A','fixture-input','-p','udp','--dport','41641','-j','ACCEPT')
 cmd(tool,'-A','fixture-forward','-i','fixturetun0','-j','MARK','--set-xmark','0x40000/0xff0000');cmd(tool,'-A','fixture-forward','-m','mark','--mark','0x40000/0xff0000','-j','ACCEPT')
 cmd(tool,'-t','mangle','-A','PREROUTING','-m','conntrack','--ctstate','RELATED,ESTABLISHED','-m','connmark','!','--mark','0x0/0xff0000','-j','CONNMARK','--restore-mark','--nfmask','0xff0000','--ctmask','0xff0000')
 cmd(tool,'-t','mangle','-A','OUTPUT','-m','conntrack','--ctstate','NEW','-m','mark','!','--mark','0x0/0xff0000','-j','CONNMARK','--save-mark','--nfmask','0xff0000','--ctmask','0xff0000')
cmd('nft','add','table','inet','other_firewall');cmd('nft','add','chain','inet','other_firewall','late','{ type filter hook input priority 20; policy accept; }');cmd('nft','add','rule','inet','other_firewall','late','udp','dport','{ 44007, 44107 }','counter','drop')
API=RUN/'api';API.mkdir(mode=0o711);DATA=RUN/'data';DATA.mkdir(mode=0o700);STATE=RUN/'state';STATE.mkdir(mode=0o700)
# Private mount namespace only; root-owned ancestors must remain authoritative.
cmd('mount','-t','tmpfs','-o','mode=755','tmpfs','/run')
os.mkdir('/run/fg',0o700);cmd('mount','--bind',str(RUN),'/run/fg')
API=Path('/run/fg/api');DATA=Path('/run/fg/data');STATE=Path('/run/fg/state')
counts={};sockets=[];stopping=False;backend=None;monitor=None
print('EVIDENCE',RUN,flush=True)
def receive(s,port,tcp):
 while not stopping:
  try:
   if tcp:
    c,_=s.accept()
    def read(c):
     with c:
      while True:
       b=c.recv(1024)
       if not b:break
       counts[port]+=1;c.sendall(b)
    threading.Thread(target=read,args=(c,),daemon=True).start()
   else:b,a=s.recvfrom(1024);counts[port]+=1;s.sendto(b'reply',a)
  except OSError:break
for family,addr,base in [(socket.AF_INET,'10.79.0.1',44000),(socket.AF_INET6,'fd79::1',44100)]:
 for n in range(8):
  port=base+n;s=socket.socket(family,socket.SOCK_STREAM if n%2==0 else socket.SOCK_DGRAM);s.bind((addr,port));counts[port]=0;sockets.append(s)
  if n%2==0:s.listen()
  threading.Thread(target=receive,args=(s,port,n%2==0),daemon=True).start()
def call(op='list',name='control',**kw):
 with socket.socket(socket.AF_UNIX)as s:
  s.settimeout(5);s.connect(str(API/(name+'.sock')));s.sendall((json.dumps(dict(version=1,operation=op,**kw))+'\n').encode());b=b''
  while b'\n'not in b:b+=s.recv(65536)
  return json.loads(b)
def pending(port):return next((v for v in call().get('events',[]) if v['state']=='awaiting-decision' and v['flow']['local'].endswith(':'+str(port))),None)
def decide(port,action):
 e=wait(lambda:pending(port));assert counts[port]==0
 r=call('decide',id=e['id'],action=action,scope='once');assert 'error'not in r,r
 return e
def doctor(*flags):return json.loads(cmd(BIN,'doctor','--json','--administrator',*flags))
def markcheck(r):return next(c for c in r['checks']if c['id']=='firewall.mark_compatibility')
def nft():return json.loads(cmd('nft','-j','list','ruleset'))
result={'cases':[],'label':'real private TUN/conntrack/NFQUEUE with generic disjoint mark rules; not host or encrypted VPN proof'}
def passed(s):
 print('PASS',s,flush=True);result['cases'].append(s);(RUN/'result.json').write_text(json.dumps(result,indent=2))
def state():return call()['protection']
def launch():
 global backend
 args=[BIN,'serve','--socket',str(API/'control.sock'),'--database',str(DATA/'rules.db'),'--uid','0','--administrator','--allow-protection','--protection-state',str(DATA/'desired.json'),'--allow-evaluation','--evaluation-state',str(STATE),'--decision-timeout','3s']
 backend=subprocess.Popen(args,stdout=(RUN/'daemon.log').open('a'),stderr=subprocess.STDOUT)
 def ready():
  if backend.poll()is not None:raise RuntimeError((RUN/'daemon.log').read_text())
  try:return call()
  except(OSError,ValueError):return None
 return wait(ready)
def protect():
 s=call();r=call('protection-start',generation=s['generation'],protection_id=s['protection']['id'],request_id=uuid.uuid4().hex,profile='both');assert not r.get('error'),r
 v=wait(lambda:(lambda v:v if v['state']in('active','failed','degraded')else None)(state()));assert v['state']=='active',v
 return v
def stop():
 s=call();r=call('protection-stop',generation=s['generation'],protection_id=s['protection']['id']);assert not r.get('error'),r
 wait(lambda:state()['state']=='stopped');assert 'flowgate_host'not in cmd('nft','list','tables') and 'flowgate_guard'not in cmd('nft','list','tables')
def outgoing(v6,tcp,action,remember=False):
 addr='fd79::2'if v6 else'10.79.0.2';port=43000 if tcp else 43001
 before=(RUN/'peer-received.log').read_text().count(f"{port}") if (RUN/'peer-received.log').exists() else 0
 outcome={};s=socket.socket(socket.AF_INET6 if v6 else socket.AF_INET,socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM);s.settimeout(4);s.setsockopt(socket.SOL_SOCKET,socket.SO_MARK,0x40000)
 def transfer():
  try:s.connect((addr,port));s.sendall(b'continuous');outcome['reply']=s.recv(128)
  except OSError as e:outcome['error']=str(e)
  finally:s.close()
 t=threading.Thread(target=transfer);t.start()
 e=wait(lambda:next((v for v in call().get('events',[])if v['state']=='awaiting-decision'and v['flow']['direction']=='outgoing'and v['flow']['remote'].endswith(':'+str(port))and v['flow']['protocol']==('tcp'if tcp else'udp')),None))
 r=call('decide',id=e['id'],action=action,scope='persistent'if remember else'once');assert not r.get('error'),r
 t.join(5);assert not t.is_alive()
 after=(RUN/'peer-received.log').read_text().count(f"{port}") if (RUN/'peer-received.log').exists() else 0
 if action=='allow':assert outcome.get('reply')==b'continuous'and after==before+1,(outcome,before,after)
 else:assert 'reply'not in outcome and after==before,(outcome,before,after)
 return e
try:
 assert markcheck(doctor('--profile','both'))['status']=='ready'
 foreign=nft();routes={f:cmd('ip','-j',f,'rule','show')+cmd('ip','-j',f,'route','show','table','107')for f in ['-4','-6']}
 before=launch();assert state()['state']=='stopped'
 s=protect();assert s['desired_mode']=='both'and 'stops_at'not in s
 # Real incoming and outgoing TCP/UDP for both families, replies and masked marks.
 for v6,base in [(False,44000),(True,44100)]:
  for offset,action in [(2,'allow'),(4,'block'),(1,'allow'),(3,'block')]:
   port=base+offset;print('CHECK',v6,port,action,flush=True);remote('tcp'if offset%2==0 else'udp',port=port,v6=v6,wait_reply=bool(offset%2));decide(port,action)
   if action=='allow':wait(lambda:counts[port]==1)
   else:time.sleep(.2);assert counts[port]==0
   if action=='allow'and offset%2:assert remote('udp-reply',port=port,v6=v6)['reply']=='reply'
  for tcp in [True,False]:
   outgoing(v6,tcp,'allow');outgoing(v6,tcp,'block')
  passed('TUN IPv'+('6'if v6 else'4')+' incoming/outgoing TCP+UDP Allow delivered/replied and Deny receiver0; independent masks preserved')
 # No GUI/API decision: deadline denies and reconnect cannot act on expired request.
 remote('udp',port=44005);e=wait(lambda:pending(44005));time.sleep(3.4);assert counts[44005]==0
 r=call('decide',id=e['id'],action='allow',scope='once');assert r.get('error'),r
 passed('No GUI: unmatched held attempt expires/receiver0, expired decision rejected')
 # Deliberate Stop removes all own interception, retains daemon/policy.
 gen=call()['generation'];stop();assert call()['generation']==gen
 passed('Explicit Stop persists monitoring, removes own table/guard; same daemon survives')
 protect()
 # Crash leaves owned queue/drop, restart reclaims stale ownership behind guard.
 backend.kill();backend.wait(5)
 assert 'flowgate_host'in cmd('nft','list','tables')
 old=counts[44005];remote('udp',port=44005);time.sleep(.2);assert counts[44005]==old
 launch();wait(lambda:state()['state']=='active');assert call()['generation']!=gen
 passed('Actual SIGKILL leaves fail-closed table; fresh daemon restores desired both, stale socket/owned marks recovered')
 # More than five real minutes when requested; do not shorten the production clock.
 hold=int(os.environ.get('FLOWGATE_CONTINUOUS_HOLD_SECONDS','0'))
 if hold:
  start=time.monotonic()
  while time.monotonic()-start<hold:
   assert state()['state']=='active';time.sleep(2)
  assert hold>300
  passed(f'Continuous active without GUI for {hold}s, beyond prior five-minute expiry')
 # Candidate inspection omits only verified owned resources, without stopping.
 checks=json.loads(cmd(BIN,'doctor','--json','--upgrade-preflight','--state',str(STATE),'--profile','both'))['checks']
 assert all(c['status']=='ready' or (c['id']=='firewall.queue_census' and c['status']=='not_checked') for c in checks),checks
 assert state()['state']=='active'
 passed('Candidate upgrade preflight accepts verified owned active interception without mutations')
 # A later conflicting writer must be detected by the runtime audit.
 cmd('nft','add','table','inet','overlap_fixture');cmd('nft','add','chain','inet','overlap_fixture','late','{ type filter hook output priority 30; policy accept; }')
 cmd('nft','add','rule','inet','overlap_fixture','late','ct','mark','set','0x10000000')
 checks=json.loads(cmd(BIN,'doctor','--json','--upgrade-preflight','--state',str(STATE),'--profile','both'))['checks']
 assert any(c['status']=='blocked' for c in checks),checks
 wait(lambda:state()['state']=='degraded',seconds=20)
 assert 'flowgate_guard' in cmd('nft','list','tables')
 stop();cmd('nft','delete','table','inet','overlap_fixture')
 passed('Overlapping runtime writer detected; fail-closed guard retained; explicit Stop cleans owned interception')
 protect();stop();backend.terminate();assert backend.wait(8)==0
 def normalize(o):
  if isinstance(o,dict):return{k:normalize(v)for k,v in o.items()if k not in ['handle','counter','metainfo']}
  if isinstance(o,list):return[normalize(v)for v in o]
  return o
 assert normalize(foreign)==normalize(nft()),'foreign rules changed'
 assert routes=={f:cmd('ip','-j',f,'rule','show')+cmd('ip','-j',f,'route','show','table','107')for f in ['-4','-6']}
 passed('Foreign nft semantics and generic policy routing unchanged after Stop/recovery')
 result['passed']=True;(RUN/'result.json').write_text(json.dumps(result,indent=2))
except Exception:
 (RUN/'failure-counts.json').write_text(json.dumps(counts))
 if backend and backend.poll() is None:
  (RUN/'failure-state.json').write_text(json.dumps(call(),indent=2))
  (RUN/'failure-nft.json').write_text(json.dumps(nft(),indent=2))
 raise
finally:
 stopping=True
 if backend and backend.poll()is None:
  try:stop()
  except Exception:pass
  backend.terminate();backend.wait(8)
 try:remote('quit')
 except Exception:pass
 peer.wait(5)
 for s in sockets:s.close()

#!/usr/bin/env python3
"""Component verification with real TUN/IP/netfilter, emulated Tailscale metadata.
No tailnet enrollment, encryption or live-host forwarding is performed.
"""
import json,os,socket,struct,fcntl,select,subprocess,tempfile,time,threading
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];BIN=str(ROOT/'.workspace/flowgate')
assert os.environ['FLOWGATE_PARENT_NETNS']!=os.readlink('/proc/self/ns/net')
RUN=Path(tempfile.mkdtemp(prefix='tailscale-component-',dir=ROOT/'.workspace'))
TOOLS=RUN/'tools';TOOLS.mkdir(mode=0o700)
(TOOLS/'tailscale').write_text('#!/bin/sh\ncase "$1 $2" in\n"version --daemon") echo \'{"short":"1.104.1","daemonLong":"1.104.1"}\';;\n"debug prefs") echo \'{"WantRunning":true,"NetfilterMode":2,"RouteAll":false,"AdvertiseRoutes":[]}\';;\n*) exit 1;;\nesac\n');(TOOLS/'tailscale').chmod(0o700)
os.environ['PATH']=str(TOOLS)+':'+os.environ['PATH']
def cmd(*args):return subprocess.check_output(args,text=True,stderr=subprocess.STDOUT)
left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_DGRAM)
peer=subprocess.Popen(['unshare','--net','python3',str(ROOT/'scripts/tailscale-tun-peer.py'),str(right.fileno()),str(RUN)],pass_fds=[right.fileno()],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True);right.close()
tun=os.open('/dev/net/tun',os.O_RDWR);fcntl.ioctl(tun,0x400454ca,struct.pack('16sH',b'tailscale0',0x1001))
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
cmd('ip','link','set','tailscale0','up');cmd('ip','addr','add','10.79.0.1/32','dev','tailscale0');cmd('ip','-6','addr','add','fd79::1/128','dev','tailscale0','nodad')
remote('setup')
# Reproduce this host's routing selectors, while using only documentation addresses.
cmd('ip','link','add','underlay0','type','dummy');cmd('ip','link','set','underlay0','up')
for family,prefix in [('-4','10.79.0.2/32'),('-6','fd79::2/128')]:
 cmd('ip',family,'route','add',prefix,'dev','tailscale0','table','52')
 cmd('ip',family,'route','add','default','dev','underlay0')
 for pr,table in [('5210','main'),('5230','default')]:cmd('ip',family,'rule','add','priority',pr,'fwmark','0x80000/0xff0000','lookup',table)
 cmd('ip',family,'rule','add','priority','5250','fwmark','0x80000/0xff0000','type','unreachable')
 cmd('ip',family,'rule','add','priority','5270','lookup','52')
for tool in ['iptables','ip6tables']:
 for chain in ['ts-input','ts-forward']:cmd(tool,'-N',chain)
 cmd(tool,'-A','INPUT','-j','ts-input');cmd(tool,'-A','FORWARD','-j','ts-forward')
 cmd(tool,'-A','ts-input','-i','tailscale0','-j','ACCEPT');cmd(tool,'-A','ts-input','-p','udp','--dport','41641','-j','ACCEPT')
 cmd(tool,'-A','ts-forward','-i','tailscale0','-j','MARK','--set-xmark','0x40000/0xff0000');cmd(tool,'-A','ts-forward','-m','mark','--mark','0x40000/0xff0000','-j','ACCEPT')
 cmd(tool,'-t','mangle','-A','PREROUTING','-m','conntrack','--ctstate','RELATED,ESTABLISHED','-m','connmark','!','--mark','0x0/0xff0000','-j','CONNMARK','--restore-mark','--nfmask','0xff0000','--ctmask','0xff0000')
 cmd(tool,'-t','mangle','-A','OUTPUT','-m','conntrack','--ctstate','NEW','-m','mark','!','--mark','0x0/0xff0000','-j','CONNMARK','--save-mark','--nfmask','0xff0000','--ctmask','0xff0000')
cmd('nft','add','table','inet','other_firewall');cmd('nft','add','chain','inet','other_firewall','late','{ type filter hook input priority 20; policy accept; }');cmd('nft','add','rule','inet','other_firewall','late','udp','dport','{ 44007, 44107 }','counter','drop')
API=RUN/'api';API.mkdir(mode=0o711);DATA=RUN/'data';DATA.mkdir(mode=0o700);STATE=RUN/'state';STATE.mkdir(mode=0o700)
counts={};sockets=[];stopping=False;backend=None;monitor=None
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
def tailcheck(r):return next(c for c in r['checks']if c['id']=='firewall.tailscale')
def nft():return json.loads(cmd('nft','-j','list','ruleset'))
def marks():return json.loads(cmd(BIN,'tailscale-inspect'))['conntrack_marks']
try:
 assert tailcheck(doctor())['status']=='ready'
 assert tailcheck(doctor('--profile','both'))['code']=='tailscale_profile_unsupported'
 before=nft();routes={f:cmd('ip','-j',f,'rule','show')+cmd('ip','-j',f,'route','show','table','52')for f in ['-4','-6']}
 # A mask copy conflict is rejected despite its otherwise legitimate chain name.
 cmd('iptables','-t','mangle','-R','OUTPUT','1','-m','conntrack','--ctstate','NEW','-m','mark','!','--mark','0x0/0xff0000','-j','CONNMARK','--save-mark','--nfmask','0xffffffff','--ctmask','0xffffffff')
 assert tailcheck(doctor())['status']=='blocked'
 cmd('iptables','-t','mangle','-R','OUTPUT','1','-m','conntrack','--ctstate','NEW','-m','mark','!','--mark','0x0/0xff0000','-j','CONNMARK','--save-mark','--nfmask','0xff0000','--ctmask','0xff0000')
 for statement in ['ct mark set 0x80000','ct mark set meta mark','meta mark set ct mark','ct mark set ct mark | 0x10000000']:
  cmd('nft','add','chain','inet','other_firewall','conflict');cmd('nft','add','rule','inet','other_firewall','conflict',*statement.split())
  assert tailcheck(doctor())['status']=='blocked',statement
  cmd('nft','flush','chain','inet','other_firewall','conflict');cmd('nft','delete','chain','inet','other_firewall','conflict')
 assert tailcheck(doctor())['status']=='ready'
 print('PASS actual iptables-nft masks/copies; full assignments, unmasked cross-copy, overlapping CT writes and both profile refused',flush=True)
 monitor=subprocess.Popen([BIN,'serve','--socket',str(API/'monitor.sock'),'--database',str(DATA/'rules.db'),'--uid','0','--administrator'],stdout=(RUN/'monitor.log').open('w'),stderr=subprocess.STDOUT)
 wait(lambda:(API/'monitor.sock').exists())
 args=[BIN,'host-start','--state',str(STATE),'--socket',str(API/'control.sock'),'--database',str(DATA/'rules.db'),'--uid','0','--administrator','--duration','120s','--timeout','8s']
 failed=subprocess.run(args,capture_output=True,text=True,timeout=20)
 assert failed.returncode and 'policy_database_owned'in failed.stderr,failed.stderr
 assert monitor.poll()is None and not (API/'control.sock').exists()
 state=call(name='monitor');call('monitor-stop',name='monitor',generation=state['generation']);assert monitor.wait(6)==0
 # Existing connection before activation, tracked by the emulated firewall.
 remote('tcp',port=44000);wait(lambda:counts[44000]==1)
 backend=subprocess.Popen(args,stdout=(RUN/'controller.log').open('w'),stderr=subprocess.STDOUT)
 def ready():
  if backend.poll()is not None:raise RuntimeError((RUN/'controller.log').read_text())
  try:return call().get('enforcement',{}).get('state')=='active'
  except OSError:return False
 wait(ready)
 assert call()['generation']!=state['generation']
 stale=call('rule-delete',generation=state['generation'],id='absent',expected_version=1);assert stale['error_code']=='generation_conflict'
 with socket.socket(socket.AF_UNIX)as ro:
  ro.connect(str(API/'control.sock.monitor'));ro.sendall(b'{"version":1,"operation":"list"}\n');raw=b''
  while b'\n'not in raw:raw+=ro.recv(65536)
  observation=json.loads(raw);assert observation['mode']=='host-monitor' and observation['backend_mode']=='host-enforcement' and observation['read_only'] and 'activity'in observation
 remote('again',port=44000);wait(lambda:counts[44000]==2)
 for v6,base in [(False,44000),(True,44100)]:
  for n,action in [(2,'allow'),(4,'block'),(1,'allow'),(3,'block')]:
   port=base+n;remote('tcp'if n%2==0 else'udp',port=port,v6=v6,**({'wait_reply':True}if n%2 else{}));decide(port,action)
   if action=='allow':
    wait(lambda:counts[port]==1)
    if n%2:assert remote('udp-reply',port=port,v6=v6)['reply']=='reply'
   else:time.sleep(.25);assert counts[port]==0
  # A late independent drop is not bypassed by the resumed queue verdict.
  port=base+7
  remote('udp',port=port,v6=v6);decide(port,'allow');time.sleep(.15);assert counts[port]==0
  # Outbound marked sockets exercise save+restore, original routing and no reply prompt.
  family=socket.AF_INET6 if v6 else socket.AF_INET;addr='fd79::2'if v6 else'10.79.0.2'
  for typ,port,payload in [(socket.SOCK_STREAM,43000,b'tcp'),(socket.SOCK_DGRAM,43001,b'udp')]:
   s=socket.socket(family,typ);s.settimeout(4);s.setsockopt(socket.SOL_SOCKET,socket.SO_MARK,0x40000);s.connect((addr,port));s.sendall(payload);assert s.recv(128)==payload;s.close()
  assert all(e['flow']['direction']=='incoming'for e in call().get('events',[]))
  for mark,dev in [('0x80000','underlay0'),('0x40000','tailscale0')]:
   route=json.loads(cmd('ip','-j','-6'if v6 else'-4','route','get',addr,'mark',mark));assert route[0]['dev']==dev,route
  print('PASS TUN IPv'+('6'if v6 else'4')+' actual TCP/one-shot UDP Allow+Block, replies, marked outbound exchanges, routing bypass mask, later firewall drop',flush=True)
 marked=marks();assert any(int(k,16)&0x00ff0000==0x40000 and int(k,16)&0x30000000 for k in marked),marked
 # Controlled evidence counters observe packet marks without changing them. Added
 # only after admission preflight; this is test instrumentation, not a supported config.
 cmd('nft','add','chain','inet','other_firewall','mark_observation','{ type filter hook prerouting priority -140; policy accept; }')
 cmd('nft','add','rule','inet','other_firewall','mark_observation','meta','mark','&','0x30000000','!=','0','counter')
 cmd('nft','add','rule','inet','other_firewall','mark_observation','meta','mark','&','0xff0000','==','0x40000','counter')
 # Repeat on a fresh marked UDP socket: reply restore must affect only TS bits.
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.setsockopt(socket.SOL_SOCKET,socket.SO_MARK,0x40000);s.settimeout(4);s.connect(('10.79.0.2',43001));s.send(b'mask');assert s.recv(32)==b'mask';s.close()
 observed=json.loads(cmd('nft','-j','list','chain','inet','other_firewall','mark_observation'));packets=[next(e['counter']['packets']for e in o['rule']['expr']if'counter'in e)for o in observed['nftables']if'rule'in o]
 assert packets[0]==0 and packets[1]>0,packets
 cmd('nft','flush','chain','inet','other_firewall','mark_observation');cmd('nft','delete','chain','inet','other_firewall','mark_observation')
 cmd(BIN,'host-stop','--state',str(STATE));assert backend.wait(8)==0
 after=marks();assert any(int(k,16)&0xff0000==0x40000 for k in after) and all(int(k,16)&0x30000000==0 for k in after),after
 cmd(BIN,'host-recover','--state',str(STATE));cmd(BIN,'host-recover','--state',str(STATE))
 assert 'flowgate_host'not in cmd('nft','list','tables')
 # Ignore live counters/handles while comparing foreign rules; no semantic removal.
 def normalize(o):
  if isinstance(o,dict):return{k:normalize(v)for k,v in o.items()if k not in ['handle','counter','metainfo']}
  if isinstance(o,list):return[normalize(v)for v in o]
  return o
 assert normalize(before)==normalize(nft()),'foreign rules changed'
 assert routes=={f:cmd('ip','-j',f,'rule','show')+cmd('ip','-j',f,'route','show','table','52')for f in ['-4','-6']}
 print('PASS DB handoff has exclusive writer/fresh generation; startup TCP survives; masked conntrack save/restore preserves0x40000, no FlowGate bits leak to packet routing; Stop/repeated recovery retain TS bits, foreign rules and routes',flush=True)
 print('EVIDENCE',RUN,flush=True)
finally:
 stopping=True
 if backend and backend.poll()is None:
  subprocess.run([BIN,'host-stop','--state',str(STATE)],capture_output=True);backend.wait(8)
 if monitor and monitor.poll()is None:monitor.terminate();monitor.wait(6)
 try:remote('quit')
 except Exception:pass
 peer.wait(5)
 for s in sockets:s.close()

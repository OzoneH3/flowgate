#!/usr/bin/env python3
"""Actual serve daemon evaluation on disposable veth. --hold delegates commands
exclusively to the UI owner; --suite includes the real five-minute deadline.
Never opens host endpoints or reuses a database. Run only through scripts/lab.sh.
"""
import argparse,json,os,socket,subprocess,sys,time,threading,pathlib,uuid,fcntl,struct
ROOT=pathlib.Path(__file__).resolve().parents[2]
p=argparse.ArgumentParser();p.add_argument('--binary',required=True);p.add_argument('--run',required=True);p.add_argument('--hold',action='store_true');p.add_argument('--suite',action='store_true');p.add_argument('--tailscale',action='store_true');p.add_argument('--skip-expiry',action='store_true');p.add_argument('--docker-dnat',action='store_true',help='focused Tailscale-shaped Docker DNAT readiness/translation check; no evaluation')
p.add_argument('--tcp-once',action='store_true',help='focused retained TCP Allow identity check')
a=p.parse_args()
if a.tcp_once and (a.suite or a.hold or a.docker_dnat):p.error('--tcp-once is a separate focused case')
if a.docker_dnat and (not a.tailscale or a.suite or a.hold):p.error('--docker-dnat requires --tailscale and no --suite/--hold')
assert os.environ['FLOWGATE_PARENT_NETNS']!=os.readlink('/proc/self/ns/net')
RUN=pathlib.Path(a.run).resolve();assert RUN.is_relative_to(ROOT/'.workspace');RUN.mkdir(mode=0o700,parents=True,exist_ok=True)
for n,mode in [('api',0o711),('data',0o700)]: (RUN/n).mkdir(mode=mode,exist_ok=True);os.chmod(RUN/n,mode)
API=str(RUN/'api/daemon.sock');BIN=str(pathlib.Path(a.binary).resolve());assert BIN!=str(ROOT/'.workspace/flowgate')
counts={};socks=[];backend=None;peer=None;stopping=False

def cmd(*args):return subprocess.check_output(args,text=True,stderr=subprocess.STDOUT)
def wait(fn,seconds=15):
 end=time.monotonic()+seconds
 while time.monotonic()<end:
  value=fn()
  if value:return value
  time.sleep(.05)
 raise AssertionError('timeout')
def api(op='list',readonly=False,**fields):
 with socket.socket(socket.AF_UNIX)as s:
  s.settimeout(5);s.connect(API+('.monitor'if readonly else ''));s.sendall((json.dumps(dict(version=1,operation=op,**fields))+'\n').encode());b=b''
  while b'\n'not in b:
   d=s.recv(65536)
   if not d:raise RuntimeError('lost response')
   b+=d
  return json.loads(b)
def log(text):
 print(text,flush=True)
 with (RUN/'verification.log').open('a')as f:f.write(text+'\n')
def remote(op,**kw):
 peer.stdin.write(json.dumps(dict(op=op,**kw))+'\n');peer.stdin.flush();r=json.loads(peer.stdout.readline());assert 'error'not in r,r;return r
def receive(s,port,tcp):
 while not stopping:
  try:
   if tcp:
    c,_=s.accept()
    def read(c):
     with c:
      while True:
       try:b=c.recv(1024)
       except OSError:break
       if not b:break
       counts[port]+=1;c.sendall(b)
    threading.Thread(target=read,args=(c,),daemon=True).start()
   else:
    b,address=s.recvfrom(1024);counts[port]+=1;s.sendto(b'reply',address)
  except OSError:break
def session():return api()['evaluation']
def start(drop_ack=False):
 old=session();nonce=uuid.uuid4().hex;fields=dict(generation=api()['generation'],evaluation_id=old['id'],request_id=nonce,profile='incoming')
 if drop_ack:
  with socket.socket(socket.AF_UNIX)as client:
   client.connect(API);client.sendall((json.dumps(dict(version=1,operation='evaluation-start',**fields))+'\n').encode());client.shutdown(socket.SHUT_WR)
 else:
  r=api('evaluation-start',**fields);assert not r.get('error'),r
 v=wait(lambda:(lambda s:s if s['request_id']==nonce and s['state']in('active','failed','degraded')else None)(session()));assert v['state']=='active',v;return v,old,nonce
def stop():
 v=session();r=api('evaluation-stop',generation=api()['generation'],evaluation_id=v['id']);assert not r.get('error'),r
 v=wait(lambda:(lambda s:s if s['state']in('stopped','failed','degraded')else None)(session()));assert v['state']=='stopped'and v['cleanup']=='confirmed',v;return v
def pending(port):return next((v for v in api().get('events',[])if v['state']=='awaiting-decision'and v['flow']['local'].endswith(':'+str(port))),None)
def send(port=44001,v6=False):return remote('udp'if port%2 else 'tcp',port=port,v6=v6,wait_reply=bool(port%2))
def decide(port,action,scope='once'):
 v=wait(lambda:pending(port));r=api('decide',id=v['id'],action=action,scope=scope);assert not r.get('error'),r;return v
try:
 peer=subprocess.Popen(['unshare','--net','python3',str(ROOT/'scripts/acceptance/host-peer.py'),str(RUN)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
 wait(lambda:os.readlink(f'/proc/{peer.pid}/ns/net')!=os.readlink('/proc/self/ns/net'))
 cmd('ip','link','add','fghost','type','veth','peer','name','fgpeer');cmd('ip','link','set','fgpeer','netns',str(peer.pid));cmd('ip','link','set','fghost','up')
 cmd('ip','addr','add','10.79.0.1/24','dev','fghost');cmd('ip','-6','addr','add','fd79::1/64','dev','fghost','nodad');remote('setup')
 cmd('nft','add','table','inet','unrelated_fixture');cmd('nft','add','chain','inet','unrelated_fixture','track','{ type filter hook input priority 0; policy accept; }');cmd('nft','add','rule','inet','unrelated_fixture','track','ct','state','established','counter')
 if a.tailscale:
  tools=RUN/'tools';tools.mkdir(mode=0o700);f=tools/'tailscale';f.write_text('#!/bin/sh\ncase "$1 $2" in\n"version --daemon") echo \'{"short":"1.104.1","daemonLong":"1.104.1"}\';;\n"debug prefs") echo \'{"WantRunning":true,"NetfilterMode":2,"RouteAll":false,"AdvertiseRoutes":[]}\';;\n*) exit 1;;\nesac\n');f.chmod(0o700);os.environ['PATH']=str(tools)+':'+os.environ['PATH']
  tun=os.open('/dev/net/tun',os.O_RDWR);fcntl.ioctl(tun,0x400454ca,struct.pack('16sH',b'tailscale0',0x1001));cmd('ip','link','set','tailscale0','up')
  for family,prefix in [('-4','10.80.0.2/32'),('-6','fd80::2/128')]:
   cmd('ip',family,'route','add',prefix,'dev','tailscale0','table','52')
   for pr,table in [('5210','main'),('5230','default')]:cmd('ip',family,'rule','add','priority',pr,'fwmark','0x80000/0xff0000','lookup',table)
   cmd('ip',family,'rule','add','priority','5250','fwmark','0x80000/0xff0000','type','unreachable');cmd('ip',family,'rule','add','priority','5270','lookup','52')
  for tool in ['iptables','ip6tables']:
   for chain in ['ts-input','ts-forward']:cmd(tool,'-N',chain)
   cmd(tool,'-A','INPUT','-j','ts-input');cmd(tool,'-A','FORWARD','-j','ts-forward');cmd(tool,'-A','ts-input','-i','tailscale0','-j','ACCEPT');cmd(tool,'-A','ts-input','-p','udp','--dport','41641','-j','ACCEPT');cmd(tool,'-A','ts-forward','-i','tailscale0','-j','MARK','--set-xmark','0x40000/0xff0000');cmd(tool,'-A','ts-forward','-m','mark','--mark','0x40000/0xff0000','-j','ACCEPT')
   cmd(tool,'-t','mangle','-A','PREROUTING','-m','conntrack','--ctstate','RELATED,ESTABLISHED','-m','connmark','!','--mark','0x0/0xff0000','-j','CONNMARK','--restore-mark','--nfmask','0xff0000','--ctmask','0xff0000');cmd(tool,'-t','mangle','-A','OUTPUT','-m','conntrack','--ctstate','NEW','-m','mark','!','--mark','0x0/0xff0000','-j','CONNMARK','--save-mark','--nfmask','0xff0000','--ctmask','0xff0000')
 if a.docker_dnat:
  for tool,dest,port in [('iptables','10.79.0.1:44001',49999),('ip6tables','[fd79::1]:44101',49999)]:
   cmd(tool,'-t','nat','-N','DOCKER')
   cmd(tool,'-t','nat','-A','PREROUTING','-p','udp','--dport',str(port),'-j','DOCKER')
   cmd(tool,'-t','nat','-A','DOCKER','-p','udp','--dport',str(port),'-j','DNAT','--to-destination',dest)
 for v6,base in [(False,44000),(True,44100)]:
  for n in range(8):
   port=base+n;s=socket.socket(socket.AF_INET6 if v6 else socket.AF_INET,socket.SOCK_STREAM if n%2==0 else socket.SOCK_DGRAM);s.bind(('fd79::1'if v6 else'10.79.0.1',port));socks.append(s);counts[port]=0
   if n%2==0:s.listen()
   threading.Thread(target=receive,args=(s,port,n%2==0),daemon=True).start()
 with (RUN/'daemon.log').open('a')as f:
  backend=subprocess.Popen([BIN,'serve','--socket',API,'--database',str(RUN/'data/rules.db'),'--uid','0','--administrator','--allow-evaluation','--evaluation-state',str(RUN/'evaluation')],stdout=f,stderr=f)
 def ready():
  if backend.poll()is not None:raise RuntimeError((RUN/'daemon.log').read_text())
  try:return api()
  except(OSError,ValueError):return None
 before=wait(ready);assert before['enforcement']['state']=='stopped';generation=before['generation']
 api('evaluation-readiness',generation=generation,profile='incoming');v=wait(lambda:(lambda s:s if s['readiness']['state']!='checking'else None)(session()));assert v['readiness']['state']=='ready',v
 if a.tcp_once:
  start();send(44002);event=wait(lambda:pending(44002))
  (RUN/'pending.json').write_text(json.dumps(event,indent=2))
  result=api('decide',id=event['id'],action='allow',scope='once');assert not result.get('error'),result
  try:wait(lambda:counts[44002]==1,3)
  finally:
   (RUN/'post-once.json').write_text(json.dumps(api(),indent=2))
   (RUN/'fresh-attribution.json').write_text(cmd(BIN,'attribute','--protocol','tcp','--direction','incoming','--local',event['flow']['local'],'--remote',event['flow']['remote']))
   stop()
  log('PASS focused retained TCP Allow Once receiver delivery')
 if a.docker_dnat:
  nft_before=cmd('nft','-s','-j','list','ruleset')
  for v6,port in [(False,44001),(True,44101)]:
   remote('udp',port=49999,v6=v6,wait_reply=True)
   wait(lambda:counts[port]==1)
  assert api()['enforcement']['state']=='stopped'
  assert cmd('nft','-s','-j','list','ruleset')==nft_before
  assert 'flowgate_host'not in nft_before
  log('PASS real IPv4/IPv6 Docker-chain DNAT receiver delivery; supported Tailscale-shaped readiness; no interception or ruleset mutation by readiness (not live Tailscale evidence)')
 if a.suite:
  assert api('evaluation-start',generation=generation,evaluation_id='',request_id=uuid.uuid4().hex,profile='incoming',readonly=True)['error_code']=='forbidden'
  send(44000);wait(lambda:counts[44000]==1)
  v,old,nonce=start(drop_ack=True);assert api('evaluation-start',generation=generation,evaluation_id=old['id'],request_id=nonce,profile='incoming')['evaluation']['id']==v['id']
  remote('again',port=44000);wait(lambda:counts[44000]==2)
  for v6,base in [(False,44000),(True,44100)]:
   for offset,action in [(1,'allow'),(2,'block')]:
    port=base+offset;send(port,v6);wait(lambda:pending(port));assert counts[port]==0;decide(port,action,'application');time.sleep(.3)
    if action=='allow':wait(lambda:counts[port]==1);assert remote('udp-reply',port=port,v6=v6)['reply']=='reply'
    else:assert counts[port]==0
  rule_before=api().get('rules',[]);assert rule_before
  stop();assert api()['generation']==generation and api().get('rules',[])==rule_before and before['traffic_monitor'].get('generation')==api()['traffic_monitor'].get('generation')
  assert 'flowgate_host'not in cmd('nft','list','tables')and'unrelated_fixture'in cmd('nft','list','tables')
  log('PASS lost Start acknowledgement reconciled without replay; monitor->Start->UDP4/6 retained Allow+replies, TCP4/6 Block; pre-existing TCP survives; Stop preserves daemon/rules/collector generation and unrelated rules')
  logpage=wait(lambda:(lambda r:r if len(r['decision_log']['records'])>=8 else None)(api('decision-log',decision_query=dict(limit=100))))
  assert any(x.get('decision',{}).get('source')=='user'for x in logpage['decision_log']['records']);assert not logpage['decision_log']['health']['recording']
  assert api('evaluation-start',generation='old',evaluation_id=v['id'],request_id=uuid.uuid4().hex,profile='incoming')['error_code']=='generation_conflict'
  cmd('nft','add','rule','inet','unrelated_fixture','track','ct','mark','set','0x1')
  old=session();r=api('evaluation-start',generation=generation,evaluation_id=old['id'],request_id=uuid.uuid4().hex,profile='incoming');failed=wait(lambda:(lambda s:s if s['state']=='failed'else None)(session()));assert failed['cleanup']=='confirmed'and'flowgate_host'not in cmd('nft','list','tables')
  log('PASS Decision Log real decisions; read-only/stale denial; conflicting full mark-write refuses without activation or unrelated cleanup')
  # Flush only this fixture's foreign chain to remove its injected conflict.
  cmd('nft','flush','chain','inet','unrelated_fixture','track');cmd('nft','add','rule','inet','unrelated_fixture','track','ct','state','established','counter')
  if not a.skip_expiry:
   v,_,_=start();log('WAIT actual fixed five-minute expiry; no GUI/API connection is held; deadline '+v['stops_at'])
   time.sleep(301)
   v=wait(lambda:(lambda s:s if s['state']=='stopped'else None)(session()));assert v['cleanup']=='confirmed'and backend.poll()is None and api()['generation']==generation
   assert 'flowgate_host'not in cmd('nft','list','tables');log('PASS actual five-minute expiry returns same daemon to monitoring, rules and Activity remain, no client required')
 if a.hold:
  (RUN/'ready.json').write_text(json.dumps(dict(socket=API,monitor_socket=API+'.monitor',generation=generation,control=str(RUN/'command'),rule_count=len(api().get('rules',[])))))
  log('READY '+API+'; UI alone owns API lifecycle and command file until DONE; commands send PORT [v6], counts, quit')
  while True:
   f=RUN/'command'
   if not f.exists():time.sleep(.1);continue
   line=f.read_text().strip();f.unlink();parts=line.split()
   if parts[0]=='quit':break
   if parts[0]=='send':send(int(parts[1]),len(parts)>2);log('DONE send '+str(parts[1]))
   elif parts[0]=='counts':(RUN/'counts.json').write_text(json.dumps(counts));log('DONE counts')
   else:log('FAILED unknown command '+line)
except Exception:
 if (RUN/'daemon.log').exists():print((RUN/'daemon.log').read_text(),file=sys.stderr)
 raise
finally:
 stopping=True
 if backend and backend.poll()is None:backend.terminate();backend.wait(25)
 if peer and peer.poll()is None:
  try:remote('quit')
  except Exception:peer.terminate()
  peer.wait(5)
 for s in socks:s.close()
 log('CLEANED owned daemon/peer/namespace; no host changes')

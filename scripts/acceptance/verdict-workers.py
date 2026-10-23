#!/usr/bin/env python3
"""Native NFQUEUE receiver and polling load; run through scripts/lab.sh.
Writes evidence only under .workspace. Does not exercise native Qt or Wine.
"""
import argparse,json,os,pathlib,socket,subprocess,threading,time
from lablib import localhost_ask_rules
p=argparse.ArgumentParser();p.add_argument('--binary',required=True);p.add_argument('--run',required=True);a=p.parse_args()
root=pathlib.Path.cwd();run=pathlib.Path(a.run).resolve();assert run.is_relative_to(root/'.workspace')
assert os.environ['FLOWGATE_PARENT_NETNS']!=os.readlink('/proc/self/ns/net')
run.mkdir(parents=True,exist_ok=True,mode=0o700)
api_path=str(run/'api.sock');received={};sent={};clients=[];poll_errors=[];poll_count=0;stop=threading.Event();poll_stop=threading.Event()
server=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);server.bind(('127.0.0.1',0));server.settimeout(.1)
def receiver():
 while not stop.is_set():
  try: data,_=server.recvfrom(1024);received[data.decode()]=time.monotonic()
  except socket.timeout:pass
threading.Thread(target=receiver,daemon=True).start()
def api(op='list',**kw):
 with socket.socket(socket.AF_UNIX) as s:
  s.settimeout(5);s.connect(api_path);s.sendall((json.dumps(dict(version=1,operation=op,**kw))+'\n').encode());return json.loads(s.makefile('rb').readline())
def wait(fn,seconds=10):
 end=time.monotonic()+seconds
 while time.monotonic()<end:
  v=fn()
  if v:return v
  time.sleep(.005)
 raise AssertionError('receiver/API deadline')
def client():
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('127.0.0.1',0));clients.append(s);return s
def send(s,label):
 sent[label]=time.monotonic();s.sendto(label.encode(),server.getsockname())
def pending(s):
 return next((e for e in api().get('events',[]) if e['state']=='awaiting-decision' and e['flow']['local'].endswith(':'+str(s.getsockname()[1]))),None)
def decide(e,action,scope):
 r=api('decide',id=e['id'],action=action,scope=scope);assert r.get('decision',{}).get('state')==('allowed' if action=='allow' else 'blocked'),r
log=(run/'daemon.log').open('w')
daemon=subprocess.Popen([str(pathlib.Path(a.binary).resolve()),'serve-lab','--rules',localhost_ask_rules('outgoing'),'--parent-netns',os.environ['FLOWGATE_PARENT_NETNS'],'--direction','outgoing','--socket',api_path,'--timeout','30s'],stdout=log,stderr=log)
def poll():
 global poll_count
 while not poll_stop.is_set():
  try:api();poll_count+=1
  except Exception as e:poll_errors.append(str(e))
  poll_stop.wait(.02)
try:
 wait(lambda:pathlib.Path(api_path).exists() and 'READY:' in (run/'daemon.log').read_text())
 first=client();send(first,'once');e=wait(lambda:pending(first));decide(e,'allow','once');wait(lambda:'once' in received)
 for i in range(16):
  label='once-'+str(i);send(first,label);wait(lambda:label in received)
 assert pending(first) is None,'ordinary Allow repeated prompt'
 blocked=client();send(blocked,'blocked');e=wait(lambda:pending(blocked));decide(e,'block','once');time.sleep(.15);assert 'blocked' not in received
 allowed=client();send(allowed,'remember');e=wait(lambda:pending(allowed));decide(e,'allow','application');wait(lambda:'remember' in received)
 for i in range(16):send(allowed,'burst-'+str(i))
 wait(lambda:all('burst-'+str(i) in received for i in range(16)))
 thread=threading.Thread(target=poll);thread.start()
 start=time.monotonic()
 for i in range(1000):send(allowed,'load-'+str(i));time.sleep(.002)
 time.sleep(1)
 poll_stop.set();thread.join(6)
 labels=[k for k in received if k.startswith('load-')];latencies=sorted((received[k]-sent[k])*1000 for k in labels)
 assert labels,'no load delivery'
 assert not poll_errors,poll_errors
 try:nfqueue=pathlib.Path('/proc/net/netfilter/nfnetlink_queue').read_text()
 except OSError as e:nfqueue='unavailable: '+str(e)
 result=dict(attempted=1000,delivered=len(labels),elapsed=time.monotonic()-start,p50_ms=latencies[len(latencies)//2],p99_ms=latencies[min(len(latencies)-1,int(len(latencies)*.99))],poll_count=poll_count,ordinary_allow_no_repeat=True,blocked_not_delivered=True,burst_delivered=16,nfqueue=nfqueue,scope='native UDP IPv4; API polling; no Qt/Wine',passed=True)
 daemon.kill();daemon.wait(timeout=5)
 send(allowed,'consumer-gone');time.sleep(.2);assert 'consumer-gone' not in received,'consumer loss allowed UDP'
 result['consumer_loss_blocked']=True
 (run/'result.json').write_text(json.dumps(result,indent=2));print(json.dumps(result))
finally:
 stop.set();poll_stop.set()
 daemon.terminate()
 try:daemon.wait(timeout=10)
 except subprocess.TimeoutExpired:daemon.kill();daemon.wait()
 for s in clients:s.close()
 server.close();log.close()

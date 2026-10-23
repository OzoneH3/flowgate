#!/usr/bin/env python3
"""Private-namespace receiver regression: prompt history cannot override rules."""
import json,os,pathlib,socket,subprocess,sys,threading,time
from lablib import localhost_ask_rules
root=pathlib.Path.cwd();run=pathlib.Path(sys.argv[1]).resolve()
assert run.is_relative_to(root/'.workspace')
assert os.environ['FLOWGATE_PARENT_NETNS']!=os.readlink('/proc/self/ns/net')
run.mkdir(mode=0o700,parents=True,exist_ok=True)
api_path=str(run/'api.sock');received=[];clients=[]
server=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);server.bind(('127.0.0.1',0))
def receiver():
 while True:
  try:received.append(server.recvfrom(1024)[0].decode())
  except OSError:return
threading.Thread(target=receiver,daemon=True).start()
def api(op='list',**kw):
 with socket.socket(socket.AF_UNIX) as s:
  s.settimeout(5);s.connect(api_path);s.sendall((json.dumps(dict(version=1,operation=op,**kw))+'\n').encode());return json.loads(s.makefile('rb').readline())
def wait(fn,seconds=5):
 end=time.monotonic()+seconds
 while time.monotonic()<end:
  value=fn()
  if value:return value
  time.sleep(.002)
 raise AssertionError('receiver/API deadline')
log=(run/'daemon.log').open('w')
daemon=subprocess.Popen([str(root/'.workspace/flowgate-capacity'),'serve-lab','--rules',localhost_ask_rules('outgoing'),'--parent-netns',os.environ['FLOWGATE_PARENT_NETNS'],'--direction','outgoing','--socket',api_path,'--timeout','60s'],stdout=log,stderr=log)
try:
 wait(lambda:pathlib.Path(api_path).exists() and 'READY:' in (run/'daemon.log').read_text())
 def send(i):
  s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);clients.append(s);s.sendto(str(i).encode(),server.getsockname())
 send(0)
 e=wait(lambda:next((e for e in api().get('events',[]) if e['state']=='awaiting-decision'),None))
 r=api('decide',id=e['id'],action='allow',scope='application');assert r.get('decision',{}).get('state')=='allowed',r
 wait(lambda:'0' in received)
 start=time.monotonic()
 for i in range(1,301):
  send(i);wait(lambda:str(i) in received)
 state=api();assert not any(e['state']=='awaiting-decision' for e in state['events'])
 assert len(state['events'])<=256,len(state['events'])
 result=dict(received=len(received),attempts=301,elapsed=time.monotonic()-start,events=len(state['events']),host_changed=False,passed=True)
 (run/'result.json').write_text(json.dumps(result,indent=2));print(json.dumps(result))
finally:
 try:(run/'last-state.json').write_text(json.dumps(api()))
 except (OSError,ValueError):pass
 daemon.terminate()
 try:daemon.wait(timeout=10)
 except subprocess.TimeoutExpired:daemon.kill();daemon.wait()
 for s in clients:s.close()
 server.close();log.close()

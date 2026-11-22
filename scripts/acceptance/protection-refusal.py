#!/usr/bin/env python3
"""Real activation refusal: keep the guarded control API alive until explicit Stop."""
import socket,subprocess,pathlib,time,json,os,tempfile
from lablib import start_receiver_daemon
if not os.environ.get('FLOWGATE_PARENT_NETNS') or os.readlink('/proc/self/ns/net') == os.environ['FLOWGATE_PARENT_NETNS']:
 raise SystemExit('requires scripts/lab.sh private namespace')
r=pathlib.Path(tempfile.mkdtemp(prefix='protection-refusal-',dir=pathlib.Path('.workspace').resolve()));api=r/'api'/'daemon.sock'
print('EVIDENCE',r,flush=True)
(r/'api').mkdir(exist_ok=True);(r/'api').chmod(0o711)
(r/'desired.json').write_text(json.dumps({'schema':1,'mode':'both'}))
listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen()
client=socket.create_connection(listener.getsockname());server,_=listener.accept()
log=(r/'daemon.log').open('w')
p=start_receiver_daemon('protection-refusal','serve','--socket',str(api),'--database',str(r/'rules.db'),'--uid','0','--administrator','--allow-protection','--evaluation-state',str(r/'api'/'enforcement'),'--protection-state',str(r/'desired.json'),stdout=log,stderr=log)
def request(operation='list',**kw):
 with socket.socket(socket.AF_UNIX) as s:
  s.settimeout(5);s.connect(str(api));s.sendall((json.dumps(dict(version=1,operation=operation,**kw))+'\n').encode());return json.loads(s.makefile('rb').readline())
def wait(state):
 for _ in range(200):
  if p.poll() is not None:raise RuntimeError('daemon exited '+str(p.returncode))
  try:
   x=request()
   if x.get('protection',{}).get('state')==state:return x
  except FileNotFoundError:pass
  time.sleep(.05)
 raise RuntimeError('state never reached '+state+': '+str(x.get('protection')))
try:
 x=wait('degraded');print('REFUSAL',x['protection']['reason'],flush=True)
 assert 'lacks a pre-existing conntrack entry' in x['protection']['reason'],x['protection']
 time.sleep(1);assert p.poll() is None;assert request()['protection']['state']=='degraded'
 rules=subprocess.check_output(['nft','list','ruleset'],text=True);(r/'guard-rules.txt').write_text(rules);assert 'flowgate' in rules and 'drop' in rules
 request('protection-stop',generation=x['generation'],protection_id=x['protection']['id']);x=wait('stopped')
 print('PASS API remains alive; explicit Stop confirms cleanup',flush=True)
 client.close();server.close();listener.close()
 request('protection-start',generation=x['generation'],protection_id=x['protection']['id'],request_id='b'*32,profile='both');x=wait('active')
 print('PASS activation after untracked socket closed',flush=True)
 request('protection-stop',generation=x['generation'],protection_id=x['protection']['id']);wait('stopped')
finally:
 p.terminate();p.wait(timeout=10);log.close()

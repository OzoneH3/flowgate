#!/usr/bin/env python3
"""Synthetic helper protocol and actual authenticated API; NO BPF metrics claimed.
Run with scripts/lab.sh. No firewall calls or root outside the user namespace.
"""
import json,os,socket,subprocess,tempfile,time
from pathlib import Path
root=Path(__file__).resolve().parents[2]
assert os.environ['FLOWGATE_PARENT_NETNS']!=os.readlink('/proc/self/ns/net')
run=Path(tempfile.mkdtemp(prefix='udp-api-',dir=root/'.workspace'))
helper=run/'synthetic-helper.py'
helper.write_text('''#!/usr/bin/python3
import json,sys
print('READY',flush=True)
for line in sys.stdin:
 keys=line.split()
 print(json.dumps({'rows':[{'cookie':format(int(k),'016x'),'uploaded':0,'downloaded':0,'new':False}for k in keys],'missed_operations':0}),flush=True)
''');helper.chmod(0o700)
def call(op):
 with socket.socket(socket.AF_UNIX)as s:
  s.connect(str(run/'api.sock'));s.sendall(json.dumps({'version':1,'operation':op}).encode()+b'\n');data=b''
  while b'\n'not in data:
   b=s.recv(65536)
   if not b:raise AssertionError('premature close')
   data+=b
  return json.loads(data)
def wait(fn):
 end=time.monotonic()+8
 while time.monotonic()<end:
  v=fn()
  if v:return v
  time.sleep(.05)
 raise AssertionError('timeout')
p=subprocess.Popen([str(root/'.workspace/udp-test-driver'),str(run/'api.sock'),str(helper),str(os.getuid())],stdout=(run/'server.log').open('w'),stderr=subprocess.STDOUT)
try:
 wait(lambda:(run/'api.sock').exists());wait(lambda:call('list')['state']=='active')
 first=call('list');assert first['netns']==os.readlink('/proc/self/ns/net') and first['uid']==os.getuid()
 assert (run/'api.sock').stat().st_mode&0o777==0o600
 assert call('decide')['state']=='error' and call('rule-save')['state']=='error'
 assert call('stop')['state']=='stopped';p.wait(5);assert not (run/'api.sock').exists()
 print('PASS synthetic helper + actual private API, generation/namespace, mutation refusal, selected-user Stop and owned socket cleanup; no BPF counting evidence')
 print('EVIDENCE',run)
finally:
 if p.poll()is None:p.terminate();p.wait(5)

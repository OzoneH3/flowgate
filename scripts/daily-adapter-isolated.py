#!/usr/bin/env python3
"""Run production host acceptance in a disposable namespace with a simulated
systemd restart adapter. Real kernel network/rules/policies; not real systemd/boot.
"""
import json,os,pathlib,shutil,socket,subprocess,sys,tempfile,threading,time
root=pathlib.Path(__file__).resolve().parents[1];assert os.environ['FLOWGATE_PARENT_NETNS']!=os.readlink('/proc/self/ns/net')
run=pathlib.Path(tempfile.mkdtemp(prefix='daily-adapter-',dir=root/'.workspace'));print('EVIDENCE',run,flush=True)
def cmd(*a):return subprocess.check_output(a,text=True,stderr=subprocess.STDOUT)
for path in ['/run','/etc','/var/lib']:cmd('mount','-t','tmpfs','-o','mode=755','tmpfs',path)
for path,mode in [('/run/flowgate-api',0o711),('/var/lib/flowgate',0o700),('/etc/flowgate',0o755)]:os.mkdir(path,mode)
pathlib.Path('/etc/flowgate/zones.json').write_text('{"local":[],"internet":[]}')
release=run/'release';release.mkdir();shutil.copy2(os.environ.get('FLOWGATE_TEST_BINARY',str(root/'.workspace/flowgate-daily-peer')),release/'flowgate');shutil.copy2(root/'.workspace/daily-native',release/'native');shutil.copy2(root/'.workspace/daily-native',release/'native-other')
tools=run/'tools';tools.mkdir()
(tools/'tailscale').write_text('#!/bin/sh\necho \'{"BackendState":"Running"}\'\n');(tools/'tailscale').chmod(0o700)
(rpc:=run/'restart.sock').unlink(missing_ok=True);server=socket.socket(socket.AF_UNIX);server.bind(str(rpc));server.listen()
(tools/'systemctl').write_text('#!/usr/bin/python3\nimport socket,sys\ns=socket.socket(socket.AF_UNIX);s.connect('+repr(str(rpc))+');s.sendall((" ".join(sys.argv[1:])+"\\n").encode());r=s.recv(4096).decode();print(r);sys.exit(0 if r.startswith("OK")else 1)\n');(tools/'systemctl').chmod(0o700)
os.environ['PATH']=str(tools)+':'+os.environ['PATH'];backend=None

def api():
 s=socket.socket(socket.AF_UNIX);s.settimeout(3);s.connect('/run/flowgate-api/daemon.sock');s.sendall(b'{"version":1,"operation":"list"}\n');r=json.loads(s.makefile('rb').readline());s.close();return r

def restart():
 global backend
 if backend is not None:backend.terminate();backend.wait(20)
 zones=json.loads(pathlib.Path('/etc/flowgate/zones.json').read_text());args=[str(release/'flowgate'),'serve','--socket','/run/flowgate-api/daemon.sock','--database','/var/lib/flowgate/rules.db','--uid','0','--administrator','--allow-protection','--protection-state','/var/lib/flowgate/protection.json','--allow-evaluation','--evaluation-state','/run/flowgate-enforcement']
 for key,flag in [('local','--zone-local'),('internet','--zone-internet')]:
  for prefix in zones[key]:args.extend([flag,prefix])
 backend=subprocess.Popen(args,stdout=(run/'daemon.log').open('a'),stderr=subprocess.STDOUT)
 for _ in range(200):
  if backend.poll()is not None:raise RuntimeError((run/'daemon.log').read_text())
  try:
   r=api()
   if r['protection']['state']in ['active','stopped']:return
  except(OSError,ValueError):pass
  time.sleep(.05)
 raise RuntimeError('adapter startup timeout')
def serve():
 while True:
  c,_=server.accept()
  with c:
   request=c.recv(1024).decode().strip()
   try:
    assert request=='restart flowgate.service';restart();c.sendall(b'OK restart')
   except Exception as e:c.sendall(('FAILED '+str(e)).encode())
restart();threading.Thread(target=serve,daemon=True).start()
try:
 if '--failure-only'in sys.argv:
  import fcntl,struct
  pathlib.Path('/var/lib/flowgate/protection.json').write_text('{"schema":1,"mode":"both"}')
  cmd(str(release/'flowgate'),'protection-guard','--state','/run/flowgate-enforcement')
  receiver=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);receiver.bind(('127.0.0.1',0));receiver.settimeout(.3)
  sender=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
  try:sender.sendto(b'guard-test',receiver.getsockname())
  except PermissionError:pass
  try:receiver.recv(128);raise AssertionError('Guard delivered new UDP')
  except TimeoutError:pass
  tun=os.open('/dev/net/tun',os.O_RDWR);fcntl.ioctl(tun,0x400454ca,struct.pack('16sH',b'unreviewed0',0x1001));cmd('ip','link','set','unreviewed0','up')
  try:restart();raise AssertionError('unsupported tunnel accepted')
  except RuntimeError as e:assert 'VPN/tunnel'in str(e),str(e)
  assert backend.poll()is not None
  assert 'flowgate_guard'in cmd('nft','list','tables')and'flowgate_host'not in cmd('nft','list','tables')
  try:sender.sendto(b'guard-test',receiver.getsockname())
  except PermissionError:pass
  try:receiver.recv(128);raise AssertionError('Failed startup bypassed')
  except TimeoutError:pass
  os.close(tun)
  cmd(str(release/'flowgate'),'protection-recover','--state','/run/flowgate-enforcement')
  sender.sendto(b'recovered',receiver.getsockname());assert receiver.recv(128)==b'recovered'
  print('PASS startup readiness refusal leaves real fail-closed guard; local exact-owned recovery restores delivery',flush=True)
  receiver.close();sender.close()
  (run/'failure-result.json').write_text(json.dumps({'passed':True,'label':'real isolated guard/refusal/recovery; not boot proof'}))
  sys.exit(0)
 result=subprocess.run([sys.executable,str(root/'scripts/host-daily-acceptance.py'),'--release',str(release),'--evidence',str(run/'acceptance'),'--isolated'])
 assert result.returncode==0,result.returncode
 print('PASS isolated production acceptance with simulated restart adapter; NOT real systemd/host proof',flush=True)
finally:
 if backend and backend.poll()is None:
  # Namespace is disposable; intentional monitoring before closing avoids orphan work.
  s=socket.socket(socket.AF_UNIX);s.connect('/run/flowgate-api/daemon.sock');r=api();s.sendall((json.dumps(dict(version=1,operation='protection-stop',generation=r['generation'],protection_id=r['protection']['id']))+'\n').encode());s.makefile('rb').readline();s.close();time.sleep(.5);backend.terminate();backend.wait(20)

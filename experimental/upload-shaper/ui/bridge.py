# Private fixture bridge; poisoned on any shared-wire failure, never replayed.
import socket,threading,pathlib,json,time,os
P=pathlib.Path(__file__).resolve().parent
os.umask(0o077)
channel=socket.socket(socket.AF_UNIX)
for _ in range(600):
 try:channel.connect(str(P/'channel.sock'));break
 except (FileNotFoundError,ConnectionRefusedError):time.sleep(.1)
else:raise RuntimeError('guest channel unavailable')
channel.settimeout(12);wire=channel.makefile('rb');lock=threading.Lock();poisoned=False;slots=threading.BoundedSemaphore(8)
def serve(c,endpoint):
 global poisoned
 try:
  with c:
   c.settimeout(15);f=c.makefile('rb')
   while True:
    line=f.readline(2*1024*1024+1)
    if not line:return
    if len(line)>2*1024*1024 or not line.endswith(b'\n'):return
    req=json.loads(line)
    with lock:
     if poisoned:return
     try:
      channel.sendall(json.dumps({'endpoint':endpoint,'request':req}).encode()+b'\n')
      response=wire.readline(4*1024*1024+1)
      if not response.endswith(b'\n') or len(response)>4*1024*1024:raise RuntimeError('bad guest frame')
      json.loads(response)
     except BaseException:
      poisoned=True;channel.close();return
    c.sendall(response)
 except Exception:pass
 finally:slots.release()
def accept(endpoint,name):
 s=socket.socket(socket.AF_UNIX);s.bind(str(P/name));os.chmod(P/name,0o600);s.listen(8)
 while True:
  c,_=s.accept()
  if not slots.acquire(blocking=False):c.close();continue
  threading.Thread(target=serve,args=(c,endpoint),daemon=True).start()
for endpoint,name in [('control','api.sock'),('monitor','monitor.sock'),('fixture','fixture.sock')]:threading.Thread(target=accept,args=(endpoint,name),daemon=True).start()
threading.Event().wait()

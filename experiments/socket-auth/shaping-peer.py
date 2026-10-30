import socket,threading,time,json,sys,subprocess,struct
stats={};lock=threading.Lock();socks=[]
def record(b):
 if len(b)!=1200:return
 tag,seq,ts=struct.unpack('<16sQQ',b[:32]);tag=tag.split(b'\0')[0].decode();now=time.monotonic_ns()
 with lock:
  row=stats.setdefault(tag,{'seen':set(),'latency':[],'first':now,'last':now,'bytes':0})
  if seq not in row['seen']:row['seen'].add(seq);row['bytes']+=len(b);row['latency'].append((now-ts)/1e6);row['last']=now

def udp(s):
 while True:record(s.recvfrom(2048)[0])
def conn(s):
 b=b''
 try:
  while True:
   x=s.recv(1200-len(b))
   if not x:return
   b+=x
   if len(b)==1200:record(b);b=b''
 finally:s.close()
def tcp(s):
 while True:threading.Thread(target=conn,args=(s.accept()[0],),daemon=True).start()
# Bulk flows (ports 43003 TCP / 43004 UDP): bytes per source flow, no record parsing.
bulk={}
def account(key,n):
 now=time.monotonic_ns()
 with lock:
  row=bulk.setdefault(key,{'bytes':0,'messages':0,'first':now,'last':now})
  row['bytes']+=n;row['messages']+=1;row['last']=now
def bulkudp(s):
 while True:
  b,a=s.recvfrom(65535);account('udp:%s:%d'%(a[0],a[1]),len(b))
def bulkconn(s):
 a=s.getpeername();key='tcp:%s:%d'%(a[0],a[1])
 try:
  while True:
   x=s.recv(262144)
   if not x:return
   account(key,len(x))
 finally:s.close()
def bulktcp(s):
 while True:threading.Thread(target=bulkconn,args=(s.accept()[0],),daemon=True).start()
# Connected UDP reply stream; offered load is intentionally above the DL cap.
pushes=set()
def pushudp(s):
 while True:
  b,a=s.recvfrom(65535)
  if a in pushes: continue
  pushes.add(a)
  def send(peer):
   until=time.monotonic()+90
   payload=b'x'*1200
   while time.monotonic()<until:
    try: s.sendto(payload,peer)
    except OSError: return
    time.sleep(.001)
  threading.Thread(target=send,args=(a,),daemon=True).start()
def pushconn(s):
 try:
  block=b'x'*65536
  while True:s.sendall(block)
 except OSError:pass
 finally:s.close()
def pushtcp(s):
 while True:threading.Thread(target=pushconn,args=(s.accept()[0],),daemon=True).start()
for line in sys.stdin:
 op=json.loads(line)['op']
 if op=='setup':
  for args in [['link','set','lo','up'],['link','set','dev','fgpeer','addrgenmode','none'],['link','set','fgpeer','up'],['addr','add','10.79.0.2/24','dev','fgpeer'],['-6','addr','add','fd79::2/64','dev','fgpeer','nodad']]:subprocess.run(['ip',*args],check=True)
  for fam,addr in [(socket.AF_INET,'10.79.0.2'),(socket.AF_INET6,'fd79::2')]:
   for port in [43001,43002]:
    for typ,fn in [(socket.SOCK_DGRAM,udp),(socket.SOCK_STREAM,tcp)]:
     s=socket.socket(fam,typ);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind((addr,port));socks.append(s)
     if typ==socket.SOCK_STREAM:s.listen(16)
     threading.Thread(target=fn,args=(s,),daemon=True).start()
   for port,typ,fn in [(43003,socket.SOCK_STREAM,bulktcp),(43004,socket.SOCK_DGRAM,bulkudp),(43005,socket.SOCK_STREAM,pushtcp),(43006,socket.SOCK_DGRAM,pushudp)]:
    s=socket.socket(fam,typ);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,4*1024*1024);s.bind((addr,port));socks.append(s)
    if typ==socket.SOCK_STREAM:s.listen(16)
    threading.Thread(target=fn,args=(s,),daemon=True).start()
 with lock:
  out={k:{'received':len(v['seen']),'bytes':v['bytes'],'first_ns':v['first'],'last_ns':v['last'],'max_ms':max(v['latency']),'p99_ms':sorted(v['latency'])[min(len(v['latency'])-1,int(len(v['latency'])*.99))],'p50_ms':sorted(v['latency'])[len(v['latency'])//2],'p95_ms':sorted(v['latency'])[min(len(v['latency'])-1,int(len(v['latency'])*.95))]} for k,v in stats.items()}
  if op=='bulk':out={k:dict(v) for k,v in bulk.items()}
 print(json.dumps(out),flush=True)

import socket,threading,time,json,sys,subprocess,struct,fcntl,select,array
stats={};lock=threading.Lock();socks=[]
def record(b):
 if len(b)<32:return
 tag,seq,ts=struct.unpack('<16sQQ',b[:32]);tag=tag.split(b'\0')[0].decode();now=time.monotonic_ns()
 with lock:
  row=stats.setdefault(tag,{'seen':set(),'latency':[],'first':now,'last':now,'bytes':0,'reordered':0,'duplicates':0,'highest':-1})
  if seq in row['seen']:row['duplicates']+=1
  if seq<row['highest']:row['reordered']+=1
  row['highest']=max(seq,row['highest'])
  if seq not in row['seen']:row['seen'].add(seq);row['bytes']+=len(b);row['latency'].append((now-ts)/1e6);row['last']=now

def udp(s):
 while True:
  b,a=s.recvfrom(2048);record(b)
  if b.startswith(b'rtt'):s.sendto(b,a)
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
bulk={};bulk_sockets={}
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
 with lock:bulk_sockets[key]=s
 try:
  while True:
   if not select.select([s],[],[],.5)[0]:continue
   with lock:
    try:x=s.recv(262144,socket.MSG_DONTWAIT)
    except BlockingIOError:continue
    if not x:return
    now=time.monotonic_ns();row=bulk.setdefault(key,{'bytes':0,'messages':0,'first':now,'last':now})
    row['bytes']+=len(x);row['messages']+=1;row['last']=now
 except OSError:pass
 finally:
  with lock:bulk_sockets.pop(key,None)
  s.close()
def bulktcp(s):
 while True:threading.Thread(target=bulkconn,args=(s.accept()[0],),daemon=True).start()
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
   for port,typ,fn in [(43003,socket.SOCK_STREAM,bulktcp),(43004,socket.SOCK_DGRAM,bulkudp),(43005,socket.SOCK_STREAM,pushtcp)]:
    s=socket.socket(fam,typ);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,4*1024*1024);s.bind((addr,port));socks.append(s)
    if typ==socket.SOCK_STREAM:s.listen(16)
    threading.Thread(target=fn,args=(s,),daemon=True).start()
 with lock:
  out={k:{'received':len(v['seen']),'bytes':v['bytes'],'first_ns':v['first'],'last_ns':v['last'],'duplicates':v['duplicates'],'reordered':v['reordered'],'late_10ms':sum(x>10 for x in v['latency']),'p99_ms':sorted(v['latency'])[min(len(v['latency'])-1,int(len(v['latency'])*.99))],'max_ms':max(v['latency']),'p50_ms':sorted(v['latency'])[len(v['latency'])//2],'p95_ms':sorted(v['latency'])[min(len(v['latency'])-1,int(len(v['latency'])*.95))]} for k,v in stats.items()}
  if op=='bulk':
   out={k:dict(v) for k,v in bulk.items()}
   for k,sk in bulk_sockets.items():
    val=array.array('i',[0]);fcntl.ioctl(sk.fileno(),0x541B,val,True)
    out.setdefault(k,{'bytes':0})['recvq_bytes']=val[0]
 print(json.dumps(out),flush=True)

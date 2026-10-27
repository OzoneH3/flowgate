import resource
resource.setrlimit(resource.RLIMIT_NOFILE,(8192,8192))
import socket,threading,time,json,sys,subprocess,struct
idle=[]
def idle_accept(s):
 while True: idle.append(s.accept()[0])
trace=False;low_sockets=[]
stats={};lock=threading.Lock();socks=[]
def record(b,meta=None):
 if len(b)!=1200:return
 tag,seq,ts=struct.unpack('<16sQQ',b[:32]);tag=tag.split(b'\0')[0].decode();now=time.monotonic_ns()
 with lock:
  row=stats.setdefault(tag,{'seen':set(),'latency':[],'first':now,'last':now,'bytes':0,'events':[]})
  if seq not in row['seen']:row['seen'].add(seq);row['bytes']+=len(b);row['latency'].append((now-ts)/1e6);row['last']=now;row['events'].append({'seq':seq,'send_ns':ts,'receive_ns':now,'meta':meta})

def udp(s):
 while True:record(s.recvfrom(2048)[0])
def conn(s):
 low_sockets.append(s);b=b'';parts=[]
 try:
  while True:
   meta=None
   if trace:
    x,anc,flags,addr=s.recvmsg(1200-len(b),128)
    real=time.time_ns();mono=time.monotonic_ns()
    stamps=[struct.unpack('qq',v[:16]) for level,typ,v in anc if level==socket.SOL_SOCKET and typ==35 and len(v)>=16]
    meta={'read_bytes':len(x),'offset':len(b),'flags':flags,'clock_offset_ns':real-mono,'kernel_realtime_ns':stamps[-1][0]*1000000000+stamps[-1][1] if stamps else None,'calibrated_at_ns':mono,'semantics':'last-skb ancillary, not exact record arrival'}
   else:x=s.recv(1200-len(b))
   if not x:return
   b+=x
   if meta:parts.append(meta)
   if len(b)==1200:record(b,parts or None);b=b'';parts=[]
 finally:
  low_sockets.remove(s);s.close()
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
for line in sys.stdin:
 op=json.loads(line)['op']
 if op in ('traceon','traceoff'):
  trace=op=='traceon'
  for low in low_sockets:low.setsockopt(socket.SOL_SOCKET,35,int(trace))
  print(json.dumps({'trace':trace}),flush=True);continue
 if op=='reset':
  with lock:stats.clear()
  print('{}',flush=True);continue
 if op=='bulk':
  with lock:out={k:dict(v) for k,v in bulk.items()}
  print(json.dumps(out),flush=True);continue
 if op=='setup':
  z=socket.socket();z.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);z.bind(('0.0.0.0',43005));z.listen(256);socks.append(z);threading.Thread(target=idle_accept,args=(z,),daemon=True).start()
  for args in [['link','set','lo','up'],['link','set','dev','fgpeer','addrgenmode','none'],['link','set','fgpeer','up'],['addr','add','10.79.0.2/24','dev','fgpeer'],['-6','addr','add','fd79::2/64','dev','fgpeer','nodad']]:subprocess.run(['ip',*args],check=True)
  for fam,addr in [(socket.AF_INET,'10.79.0.2'),(socket.AF_INET6,'fd79::2')]:
   for port in [43001,43002]:
    for typ,fn in [(socket.SOCK_DGRAM,udp),(socket.SOCK_STREAM,tcp)]:
     s=socket.socket(fam,typ);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind((addr,port));socks.append(s)
     if typ==socket.SOCK_STREAM:s.listen(16)
     threading.Thread(target=fn,args=(s,),daemon=True).start()
   for port,typ,fn in [(43003,socket.SOCK_STREAM,bulktcp),(43004,socket.SOCK_DGRAM,bulkudp)]:
    s=socket.socket(fam,typ);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,4*1024*1024);s.bind((addr,port));socks.append(s)
    if typ==socket.SOCK_STREAM:s.listen(16)
    threading.Thread(target=fn,args=(s,),daemon=True).start()
 with lock:
  out={k:{'received':len(v['seen']),'bytes':v['bytes'],'first_ns':v['first'],'last_ns':v['last'],'events':v['events'],'p99_ms':sorted(v['latency'])[min(len(v['latency'])-1,int(len(v['latency'])*.99))],'max_ms':max(v['latency']),'over_50ms':sum(x>50 for x in v['latency']),'over_100ms':sum(x>100 for x in v['latency']),'over_250ms':sum(x>250 for x in v['latency']),'p50_ms':sorted(v['latency'])[len(v['latency'])//2],'p95_ms':sorted(v['latency'])[min(len(v['latency'])-1,int(len(v['latency'])*.95))]} for k,v in stats.items()}
  if op=='bulk':out={k:dict(v) for k,v in bulk.items()}
 print(json.dumps(out),flush=True)

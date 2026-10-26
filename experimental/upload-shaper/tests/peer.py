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
 with lock:
  out={k:{'received':len(v['seen']),'bytes':v['bytes'],'first_ns':v['first'],'last_ns':v['last'],'p50_ms':sorted(v['latency'])[len(v['latency'])//2],'p95_ms':sorted(v['latency'])[min(len(v['latency'])-1,int(len(v['latency'])*.95))]} for k,v in stats.items()}
 print(json.dumps(out),flush=True)

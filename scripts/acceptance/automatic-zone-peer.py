#!/usr/bin/env python3
"""Bounded receiver launched only in the nested private automatic-zone lab."""
import socket,threading,sys,pathlib,time,os
assert os.environ['FLOWGATE_PARENT_NETNS']!=os.readlink('/proc/self/ns/net')
p=pathlib.Path(sys.argv[1]);assert p.is_relative_to(pathlib.Path(__file__).resolve().parents[2]/'.workspace')
def record(proto,s):
 with (p/'automatic-received.log').open('a')as f:f.write(proto+' '+str(s.getsockname())+'\n')
def udp(s):
 while True:
  try:b,a=s.recvfrom(4096);record('udp',s);s.sendto(b,a)
  except OSError:return
def tcp(s):
 while True:
  try:
   c,_=s.accept();c.settimeout(3)
   try:
    b=c.recv(4096)
    if b:record('tcp',c);c.sendall(b)
   except OSError:pass
   finally:c.close()
  except OSError:return
for fam,addr in [(socket.AF_INET,'0.0.0.0'),(socket.AF_INET6,'::')]:
 for typ,port,fn in [(socket.SOCK_DGRAM,45051,udp),(socket.SOCK_STREAM,45050,tcp)]:
  s=socket.socket(fam,typ)
  if fam==socket.AF_INET6:s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
  s.bind((addr,port))
  if typ==socket.SOCK_STREAM:s.listen()
  threading.Thread(target=fn,args=(s,),daemon=True).start()
print('READY',flush=True);time.sleep(180)

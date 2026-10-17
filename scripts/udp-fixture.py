#!/usr/bin/env python3
"""Controlled UDP operations: expected API byte counts, no payload logging."""
import json,socket,sys
family=socket.AF_INET6 if sys.argv[1]=='6' else socket.AF_INET
host='::1'if family==socket.AF_INET6 else'127.88.0.1'
a=socket.socket(family,socket.SOCK_DGRAM);a.bind((host,0))
b=socket.socket(family,socket.SOCK_DGRAM);b.bind((host,0))
c=socket.socket(family,socket.SOCK_DGRAM);c.bind((host,0))
for s in (a,b,c):s.settimeout(2)
print(json.dumps({'a':a.getsockname()[1],'b':b.getsockname()[1],'c':c.getsockname()[1]}),flush=True)
up=down=0
for line in sys.stdin:
 command=line.strip()
 if command=='transfer':
  # a is connected, b is unconnected and contacts two peers (a and c).
  a.connect(b.getsockname());up+=a.send(b'a'*1200);assert len(b.recv(65536))==1200
  down+=b.sendto(b'b'*800,a.getsockname());assert len(a.recv(65536))==800
  assert b.sendto(b'c'*600,c.getsockname())==600;assert len(c.recv(65536))==600
  print(json.dumps({'a_up':up,'a_down':down,'b_up':1400,'b_down':1200,'c_up':0,'c_down':600}),flush=True)
 elif command=='edges':
  # PEEK must not count; ordinary truncation reports copied length; MSG_TRUNC
  # explicitly reports full datagram size even though the user buffer is small.
  assert b.sendto(b'x'*100,a.getsockname())==100
  assert len(a.recv(10,socket.MSG_PEEK))==10
  assert len(a.recv(10,socket.MSG_PEEK))==10
  assert len(a.recv(10))==10;down+=10
  assert b.sendto(b'y'*100,a.getsockname())==100
  buf=bytearray(10);n,anc,flags,addr=a.recvmsg_into([buf],0,socket.MSG_TRUNC);assert n==100;down+=100
  try:a.send(b'z'*100000);raise AssertionError('oversized send accepted')
  except OSError:pass
  print(json.dumps({'a_up':up,'a_down':down,'b_up':1600,'b_down':1200}),flush=True)
 elif command=='close':a.close();print('{}',flush=True)

#!/usr/bin/env python3
"""Raw L3 TUN relay to a second disposable namespace; NOT a Tailscale instance."""
import os,socket,fcntl,struct,select,threading,runpy,sys
wire=socket.socket(fileno=int(sys.argv[1]));run=sys.argv[2]
tun=os.open('/dev/net/tun',os.O_RDWR)
fcntl.ioctl(tun,0x400454ca,struct.pack('16sH',b'fgpeer',0x1001))
def pump():
 while True:
  readable,_,_=select.select([tun,wire],[],[])
  for source in readable:
   if source==tun:wire.send(os.read(tun,65535))
   else:
    b=wire.recv(65535)
    try:os.write(tun,b)
    except OSError as e:
     if e.errno!=5:raise # link not up during initial IPv6 configuration
threading.Thread(target=pump,daemon=True).start()
sys.argv=[str(__file__).replace('tailscale-tun-peer.py','host-peer.py'),run]
runpy.run_path(sys.argv[0],run_name='__main__')

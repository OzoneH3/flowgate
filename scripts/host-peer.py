#!/usr/bin/env python3
"""Remote endpoint, started only inside host-lab's nested network namespace."""
import json, socket, subprocess, sys, threading
connections={}
def exchange(s):
    try:
        while True:
            b=s.recv(1024)
            if not b:break
            s.sendall(b)
    except OSError:pass
    finally:s.close()
def listen(s):
    while True:
        try:c,_=s.accept();threading.Thread(target=exchange,args=(c,),daemon=True).start()
        except OSError:break
for raw in sys.stdin:
    try:
        q=json.loads(raw);op=q['op'];v6=q.get('v6',False);family=socket.AF_INET6 if v6 else socket.AF_INET
        if op=='setup':
            for args in [['link','set','lo','up'],['link','set','fgpeer','up'],['addr','add','10.79.0.2/24','dev','fgpeer'],['-6','addr','add','fd79::2/64','dev','fgpeer','nodad'],['-6','addr','add','fe80::2/64','dev','fgpeer','nodad']]:subprocess.run(['ip',*args],check=True)
            for fam,addr in [(socket.AF_INET,'10.79.0.2'),(socket.AF_INET6,'fd79::2')]:
                s=socket.socket(fam,socket.SOCK_STREAM);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind((addr,43000));s.listen();threading.Thread(target=listen,args=(s,),daemon=True).start()
                        
            def udp_echo(s):
                while True:
                    try:b,addr=s.recvfrom(1024);s.sendto(b,addr)
                    except OSError:break
            for fam,addr in [(socket.AF_INET,'10.79.0.2'),(socket.AF_INET6,'fd79::2')]:
                u=socket.socket(fam,socket.SOCK_DGRAM);u.bind((addr,43001));threading.Thread(target=udp_echo,args=(u,),daemon=True).start()
            answer={'ok':True}
        elif op=='ping':
            subprocess.run(['ping','-6' if v6 else '-4','-c','1','-W','2','fd79::1' if v6 else '10.79.0.1'],check=True,stdout=subprocess.DEVNULL);answer={'ok':True}
        elif op=='udp':
            s=socket.socket(family,socket.SOCK_DGRAM)
            if q.get('source_port'):s.bind(('fd79::2' if v6 else '10.79.0.2',q['source_port']))
            if q.get('dhcp'):s.bind(('fe80::2',547,0,socket.if_nametoindex('fgpeer')) if v6 else ('10.79.0.2',67))
            s.sendto(b'fixture',('fd79::1' if v6 else '10.79.0.1',q['port']));s.close();answer={'ok':True}
        elif op=='tcp':
            s=socket.socket(family,socket.SOCK_STREAM);s.settimeout(10);key=str(q['port'])+str(v6);connections[key]=s
            def send(s=s,q=q,v6=v6):
                try:s.connect(('fd79::1' if v6 else '10.79.0.1',q['port']));s.sendall(b'fixture')
                except OSError:pass
            threading.Thread(target=send,daemon=True).start();answer={'ok':True}
        elif op=='again':connections[str(q['port'])+str(v6)].sendall(b'fixture');answer={'ok':True}
        elif op=='quit':break
        else:raise ValueError(op)
    except Exception as e:answer={'error':str(e)}
    print(json.dumps(answer),flush=True)

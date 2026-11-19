#!/usr/bin/env python3
"""Remote endpoint, started only inside host-lab's nested network namespace."""
import json, socket, subprocess, sys, threading
from pathlib import Path
LOG=Path(sys.argv[1]) if len(sys.argv)>1 else None
def record(proto,s):
    if LOG:
        with (LOG/"peer-received.log").open("a") as f:f.write(proto+" "+str(s.getsockname())+"\n")
connections={}
def exchange(s):
    try:
        while True:
            b=s.recv(1024)
            if not b:break
            record("tcp",s);s.sendall(b)
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
            for args in [['link','set','lo','up'],['link','set','fgpeer','up'],['addr','add','10.79.0.2/24','dev','fgpeer'],['addr','add','10.79.0.3/24','dev','fgpeer'],['-6','addr','add','fd79::2/64','dev','fgpeer','nodad'],['-6','addr','add','fd79::3/64','dev','fgpeer','nodad'],['-6','addr','add','fe80::2/64','dev','fgpeer','nodad']]:subprocess.run(['ip',*args],check=True)
            # Each destination also has a third TCP port for the queued port-rule control.
            DESTS=[(socket.AF_INET,'10.79.0.2'),(socket.AF_INET6,'fd79::2'),(socket.AF_INET,'10.79.0.3'),(socket.AF_INET6,'fd79::3')]
            for fam,addr in DESTS:
                for tcp_port in (43000,44000,44002):
                    s=socket.socket(fam,socket.SOCK_STREAM);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind((addr,tcp_port));s.listen();threading.Thread(target=listen,args=(s,),daemon=True).start()
                        
            def udp_echo(s):
                while True:
                    try:b,addr=s.recvfrom(1024);record("udp",s);s.sendto(b,addr)
                    except OSError:break
            for fam,addr in DESTS:
                for udp_port in (43001,44001):
                    u=socket.socket(fam,socket.SOCK_DGRAM);u.bind((addr,udp_port));threading.Thread(target=udp_echo,args=(u,),daemon=True).start()
            answer={'ok':True}
        elif op=='ping':
            subprocess.run(['ping','-6' if v6 else '-4','-c','1','-W','2','fd79::1' if v6 else '10.79.0.1'],check=True,stdout=subprocess.DEVNULL);answer={'ok':True}
        elif op=='udp':
            s=socket.socket(family,socket.SOCK_DGRAM)
            if q.get('source_port') or q.get('source_address'):s.bind((q.get('source_address','fd79::2' if v6 else '10.79.0.2'),q.get('source_port',0)))
            if q.get('dhcp'):s.bind(('fe80::2',547,0,socket.if_nametoindex('fgpeer')) if v6 else ('10.79.0.2',67))
            s.sendto(b'fixture',('fd79::1' if v6 else '10.79.0.1',q['port']));
            if q.get('wait_reply'):connections['udp'+str(q['port'])+str(v6)]=s
            else:s.close()
            answer={'ok':True}
        elif op=='udp-reply':
            s=connections['udp'+str(q['port'])+str(v6)];s.settimeout(2);answer={'reply':s.recv(128).decode()};s.close()
        elif op=='tcp':
            s=socket.socket(family,socket.SOCK_STREAM);s.settimeout(10);key=str(q['port'])+str(v6);connections[key]=s
            def send(s=s,q=q,v6=v6):
                try:s.connect(('fd79::1' if v6 else '10.79.0.1',q['port']));s.sendall(b'fixture')
                except OSError:pass
            threading.Thread(target=send,daemon=True).start();answer={'ok':True}
        elif op=='close':
            connections.pop(str(q['port'])+str(v6)).close();answer={'ok':True}
        elif op=='again':connections[str(q['port'])+str(v6)].sendall(b'fixture');answer={'ok':True}
        elif op=='quit':break
        else:raise ValueError(op)
    except Exception as e:answer={'error':str(e)}
    print(json.dumps(answer),flush=True)

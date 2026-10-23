#!/usr/bin/env python3
from lablib import *
for p in (SOCK,SOCK+'.monitor'):
    if os.path.exists(p):os.unlink(p)
log=(RUN/'outgoing.log').open('w')
d=subprocess.Popen([BIN,'serve-lab','--parent-netns',os.environ['FLOWGATE_PARENT_NETNS'],'--socket',SOCK,'--rules',localhost_ask_rules('outgoing'),'--direction','outgoing'],stdout=log,stderr=log);children.append(d)
try:
    wait(lambda:'READY' in (RUN/'outgoing.log').read_text())
    for port,udp in [(24301,False),(24302,True)]:
        srv,path=server(port,udp)
        c=socket.socket(socket.AF_INET,socket.SOCK_DGRAM if udp else socket.SOCK_STREAM);c.setblocking(False)
        try:c.connect(('127.0.0.1',port))
        except BlockingIOError:pass
        if udp:c.send(b'before')
        v=wait(lambda:next((e for e in events() if e['flow']['remote'].endswith(':'+str(port)) and e['state']=='awaiting-decision'),None))
        assert not delivered(path);assert v['flow']['direction']=='outgoing'
        decide(v,'allow');c.setblocking(True);c.settimeout(4)
        if not udp:
            import select
            assert select.select([], [c], [], 4)[1]
        c.send(b'after');wait(lambda:delivered(path));c.close();print('PASS outgoing approval',port,flush=True)
finally:
    for p in children:
        if p.poll() is None:p.terminate()
    for p in children:p.wait(timeout=3)

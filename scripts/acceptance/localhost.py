#!/usr/bin/env python3
"""Real localhost payloads and explicit blocking, private lab namespace only."""
from lablib import *

try:
    for direction in ('incoming','outgoing'):
        for action in ('default','block','ask'):
            rules=[]
            for i,address in enumerate(('127.0.0.0/8','::1/128')):
                rules.append({'schema':4,'id':f'local-{i}','action':'block' if action=='default' else action,
                    'filter':{'all_programs':True,'all_uids':True,'uid':0,'network_zone':'local',
                    'direction':direction,'protocol':'*',**({} if action=='default' else {'remote_address':address})}})
            rp=RUN/'localhost-rules.json';rp.write_text(json.dumps(rules))
            for p in (SOCK,SOCK+'.monitor'):
                if os.path.exists(p):os.unlink(p)
            logpath=RUN/f'localhost-{direction}-{action}.log'
            with logpath.open('w') as log:
                d=subprocess.Popen([BIN,'serve-lab','--parent-netns',os.environ['FLOWGATE_PARENT_NETNS'],
                    '--socket',SOCK,'--direction',direction,'--rules',str(rp)],stdout=log,stderr=log)
            children.append(d)
            wait(lambda:logpath.exists() and 'READY' in logpath.read_text())
            for j,(udp,v6) in enumerate(((False,False),(True,False),(False,True),(True,True))):
                port=24500+j
                srv,path=server(port,udp,v6)
                c=socket.socket(socket.AF_INET6 if v6 else socket.AF_INET,socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
                c.setblocking(False)
                try:c.connect(('::1' if v6 else '127.0.0.1',port))
                except BlockingIOError:pass
                if udp:c.send(b'localhost-default')
                if action=='default':
                    if not udp:
                        import select
                        assert select.select([], [c], [], 3)[1]
                        c.send(b'localhost-default')
                    wait(lambda:delivered(path))
                    assert not any(e['state']=='awaiting-decision' for e in events())
                else:
                    key='local' if direction=='incoming' else 'remote'
                    v=wait(lambda:next((e for e in events() if e['flow'][key].endswith(':'+str(port))),None))
                    assert v['state']==('blocked' if action=='block' else 'awaiting-decision'),v
                    assert not delivered(path)
                    if action=='ask':
                        decide(v,'allow')
                        c.setblocking(True);c.settimeout(3)
                        c.send(b'explicit-allow')
                        wait(lambda:delivered(path))
                c.close();srv.terminate();srv.wait()
            d.terminate();d.wait(timeout=3)
            print('PASS localhost',direction,action,'TCP/UDP IPv4/IPv6',flush=True)
finally:
    for p in children:
        if p.poll() is None:p.terminate()
    for p in children:
        try:p.wait(timeout=3)
        except subprocess.TimeoutExpired:p.kill();p.wait()

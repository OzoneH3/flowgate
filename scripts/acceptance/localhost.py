#!/usr/bin/env python3
"""Real localhost payloads and explicit blocking, private lab namespace only."""
from lablib import *

try:
    # Assigned host addresses exercise local routing without requiring veth.
    subprocess.run(['ip','addr','add','192.0.2.10/32','dev','lo'],check=True)
    subprocess.run(['ip','-6','addr','add','2001:db8::10/128','dev','lo','nodad'],check=True)
    for direction in ('incoming','outgoing'):
        for action in ('default','block','ask'):
            rules=[]
            for i,address in enumerate(('127.0.0.0/8','::1/128','192.0.2.10/32','2001:db8::10/128')):
                rules.append({'schema':4,'id':f'local-{i}','action':'block' if action=='default' else action,
                    'filter':{'all_programs':True,'all_uids':True,'uid':0,'network_zone':'local',
                    'direction':direction,'protocol':'*',**({} if action=='default' else {'remote_address':address})}})
            rp=RUN/'localhost-rules.json';rp.write_text(json.dumps(rules))
            for p in (SOCK,SOCK+'.monitor'):
                if os.path.exists(p):os.unlink(p)
            logpath=RUN/f'localhost-{direction}-{action}.log'
            with logpath.open('w') as log:
                d=start_receiver_daemon('localhost','serve-lab','--parent-netns',os.environ['FLOWGATE_PARENT_NETNS'],
                    '--socket',SOCK,'--direction',direction,'--rules',str(rp), '--zone-local','192.0.2.10/32','--zone-local','2001:db8::10/128',stdout=log,stderr=log)
            children.append(d)
            wait(lambda:logpath.exists() and 'READY' in logpath.read_text())
            for j,(udp,v6,address) in enumerate(( (u,v,a) for a,v in [('127.0.0.1',False),('::1',True),('192.0.2.10',False),('2001:db8::10',True)] for u in (False,True))):
                port=24500+j
                srv,path=server(port,udp,v6,address)
                c=socket.socket(socket.AF_INET6 if v6 else socket.AF_INET,socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
                c.setblocking(False)
                try:c.connect((address,port))
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
            print('PASS localhost',direction,action,'TCP/UDP IPv4/IPv6 loopback and assigned host addresses',flush=True)
finally:
    for p in children:
        if p.poll() is None:p.terminate()
    for p in children:
        try:p.wait(timeout=3)
        except subprocess.TimeoutExpired:p.kill();p.wait()

#!/usr/bin/env python3
from lablib import *
def send(port,source='127.0.0.1',data=b'ONCE'):
    c=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);c.bind((source,0));c.sendto(data,('127.0.0.1',port));return c
try:
    for p in (SOCK,SOCK+'.monitor'):
        if os.path.exists(p):os.unlink(p)
    log=(RUN/'scope-retention-daemon.log').open('w');d=subprocess.Popen([BIN,'serve-lab','--parent-netns',os.environ['FLOWGATE_PARENT_NETNS'],'--socket',SOCK,'--timeout','2s'],stdout=log,stderr=log);children.append(d);wait(lambda:'READY' in (RUN/'scope-retention-daemon.log').read_text())
    # One-shot datagrams: approval, block, expiry, and stale listener replacement.
    for port,action in [(24501,'allow'),(24502,'block'),(24503,'timeout'),(24504,'replacement')]:
        p,path=server(port,True);c=send(port);c.close();v=wait(lambda:pending(port));assert not delivered(path)
        if action=='replacement':
            p.terminate();p.wait();p,path=server(port,True)
            q=subprocess.run([BIN,'decide','--id',v['id'],'--action','allow'],capture_output=True);assert q.returncode!=0
        elif action=='timeout':time.sleep(2.3)
        else:decide(v,action)
        if action=='allow':wait(lambda:delivered(path))
        else:time.sleep(.2);assert not delivered(path)
        c.close();print('PASS native one-shot UDP',action,flush=True)
    p,path=server(24510);c=client(24510);v=wait(lambda:pending(24510));r=decide(v,'allow','application')['decision'];assert r['remembered_filter']['local_port']==24510 and r['remembered_filter']['remote_address']=='127.0.0.1';wait(lambda:delivered(path));c.wait()
    before=path.read_text().count('RECEIVED');c=client(24510);c.wait();wait(lambda:path.read_text().count('RECEIVED')>before)
    assert not pending(24510);print('PASS new TCP connection with changed source port uses remembered permission',flush=True)
    p2,path2=server(24511);client(24511);v=wait(lambda:pending(24511));assert not delivered(path2);decide(v,'block')
    # Same app and port, different remote IP is still controlled.
    code="import socket;s=socket.socket();s.settimeout(3);s.bind(('127.0.0.2',0));s.connect(('127.0.0.1',24510));s.send(b'x')"
    c=subprocess.Popen([sys.executable,'-c',code],stderr=subprocess.DEVNULL);children.append(c);v=wait(lambda:pending(24510));assert v['flow']['remote'].startswith('127.0.0.2:');decide(v,'block');assert path.read_text().count('RECEIVED')==before+1
    print('PASS other local ports and remote addresses remain controlled',flush=True)
    # Original UDP packet held before replacement cannot be released by a later answer.
    p,path=server(24520,True);c=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);c.connect(('127.0.0.1',24520))
    for _ in range(8):c.send(b'bounded')
    v=wait(lambda:pending(24520));time.sleep(.2);assert not delivered(path);decide(v,'allow');wait(lambda:path.read_text().count('RECEIVED')==4);time.sleep(.1);assert path.read_text().count('RECEIVED')==4
    print('PASS UDP per-flow retention delivers four and drops excess datagrams',flush=True)
    p,path=server(24521,True);c=send(24521);wait(lambda:pending(24521));d.terminate();d.wait();time.sleep(.2);assert not delivered(path)
    print('PASS shutdown drops retained one-shot datagram',flush=True)
    print('PASS explicit incoming scope and retained packet receiver checks',flush=True)
finally:
    for p in children:
        if p.poll() is None:p.terminate()
    for p in children:
        try:p.wait(timeout=3)
        except subprocess.TimeoutExpired:p.kill()

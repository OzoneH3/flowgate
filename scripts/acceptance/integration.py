#!/usr/bin/env python3
from lablib import *
for p in (SOCK,SOCK+'.monitor'):
    if os.path.exists(p):os.unlink(p)
log=(RUN/'daemon.log').open('w')
d=start_receiver_daemon('integration','serve-lab','--parent-netns',os.environ['FLOWGATE_PARENT_NETNS'],'--socket',SOCK,'--rules',localhost_ask_rules('incoming'),'--timeout','2s',stdout=log,stderr=log);children.append(d)
try:
    wait(lambda:os.path.exists(SOCK) and 'READY' in (RUN/'daemon.log').read_text())
    for port,udp,v6 in [(24101,False,False),(24102,True,False),(24103,False,True),(24104,True,True)]:
        srv,path=server(port,udp,v6)
        if udp:
            c=socket.socket(socket.AF_INET6 if v6 else socket.AF_INET,socket.SOCK_DGRAM);c.connect(('::1' if v6 else '127.0.0.1',port));c.send(b'before')
        else:c=client(port,udp,v6)
        v=wait(lambda:pending(port));assert v['attribution'].get('application'),v
        assert not delivered(path),'data arrived before approval'
        decide(v,'allow')
        if udp:c.send(b'after');c.close()
        wait(lambda:delivered(path));print('PASS approval before receiver delivery',port,flush=True)
    srv,path=server(24105);client(24105);v=wait(lambda:pending(24105));decide(v,'block');time.sleep(1.2);assert not delivered(path);print('PASS block at receiver',flush=True)
    srv,path=server(24106,True);c=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);c.connect(('127.0.0.1',24106));c.send(b'x');v=wait(lambda:pending(24106));time.sleep(2.1)
    result=subprocess.run([BIN,'decide','--socket',SOCK,'--id',v['id'],'--action','allow'],capture_output=True);assert result.returncode!=0;assert not delivered(path)
    c.send(b'y');v2=wait(lambda:pending(24106));assert v['id']!=v2['id'];decide(v2,'allow');c.send(b'z');wait(lambda:delivered(path));print('PASS timeout, stale rejection and retry',flush=True)
    srv,path=server(24107,True);c=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);c.connect(('127.0.0.1',24107));c.send(b'x');v=wait(lambda:pending(24107));decide(v,'allow');c.send(b'y');wait(lambda:delivered(path));srv.terminate();srv.wait();srv,path=server(24107,True);c.send(b'z');v=wait(lambda:pending(24107));assert not delivered(path);print('PASS listener replacement invalidates once grant',flush=True)
    # Actual distinct native executables; application rules must not become port grants.
    def native(name,port):
        path=RUN/f'{name}-{port}.log';f=path.open('w');p=subprocess.Popen([str(ROOT/'.workspace'/name),f'127.0.0.1:{port}'],stdout=f,stderr=f);children.append(p);wait(lambda:'READY' in path.read_text());return p,path
    a,ap=native('native-a',24109);b,bp=native('native-b',24110)
    ca=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);ca.connect(('127.0.0.1',24109));ca.send(b'first');av=wait(lambda:pending(24109));decide(av,'allow','application')
    cb=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);cb.connect(('127.0.0.1',24110));cb.send(b'first');bv=wait(lambda:pending(24110));assert av['attribution']['application']['key']!=bv['attribution']['application']['key'];decide(bv,'block','application')
    ca.send(b'allowed');cb.send(b'blocked');wait(lambda:delivered(ap));assert not delivered(bp)
    # Saved program permission survives an atomic executable update. Both the
    # still-running unlinked image and a fresh process must deliver without a
    # second prompt; a different executable still cannot reuse that permission.
    original=av['attribution']['application']
    previous=ap.read_text().count('RECEIVED')
    executable=ROOT/'.workspace/native-a'
    replacement=RUN/'native-update'
    replacement.write_bytes(executable.read_bytes()+b'\0program-update-fixture')
    replacement.chmod(0o755)
    os.replace(replacement,executable)
    ca.send(b'old-image-after-update')
    wait(lambda:ap.read_text().count('RECEIVED')>previous)
    assert not pending(24109),'unlinked running program reprompted'
    a.terminate();a.wait();a,ap=native('native-a',24109)
    ca.send(b'updated-program')
    wait(lambda:delivered(ap))
    updated=wait(lambda:next((e for e in events() if e['flow']['local'].endswith(':24109') and e['state']=='allowed' and e['attribution'].get('application',{}).get('revision')!=original['revision']),None))
    assert updated['attribution']['application']['key']==original['key'],'program identity changed during update'
    assert not pending(24109),'updated program required another decision'
    print('PASS saved program update delivers for old unlinked and new images without another prompt',flush=True)
    a.terminate();a.wait();a,ap=native('native-b',24109);ca.send(b'not-port-wide');wait(lambda:pending(24109));assert not delivered(ap)
    print('PASS distinct native app rules and cross-application port reuse',flush=True)
    # Kernel SO_REUSEPORT candidates must remain ambiguous, even under one PID.
    shared=[]
    for _ in range(2):
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEPORT,1);s.bind(('127.0.0.1',24111));s.setblocking(False);shared.append(s)
    probe=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);probe.sendto(b'ambiguous',('127.0.0.1',24111))
    v=wait(lambda:next((e for e in events() if e['flow']['local'].endswith(':24111')),None));assert v['state']=='blocked' and v['attribution']['status']=='multiple-candidates'
    for s in shared:
        try:s.recv(100);raise AssertionError('shared listener received blocked data')
        except BlockingIOError:pass
        s.close()
    print('PASS SO_REUSEPORT ambiguity denied at receivers',flush=True)
    srv,path=server(24112,True)
    for _ in range(50):
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.sendto(b'scan',('127.0.0.1',24112));s.close()
    time.sleep(.3);assert not delivered(path);assert len(events())<=256
    print('PASS repeated attempts remain bounded with no receiver delivery',flush=True)
    d.kill();d.wait();srv,path=server(24108,True);c=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);c.sendto(b'fail-closed',('127.0.0.1',24108));time.sleep(.2);assert not delivered(path);print('PASS absent queue consumer fails closed',flush=True)
finally:
    for p in children:
        if p.poll() is None:p.terminate()
    for p in children:
        try:p.wait(timeout=2)
        except subprocess.TimeoutExpired:p.kill()

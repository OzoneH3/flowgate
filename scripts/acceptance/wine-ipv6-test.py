#!/usr/bin/env python3
from lablib import *
proton=os.environ.get('FLOWGATE_TEST_PROTON');label='proton' if proton else 'wine'
runner=str(ROOT/'scripts/acceptance/proton-fixture.sh') if proton else '/usr/bin/wine'
prefix=str(ROOT/'.workspace/proton-prefix/pfx') if proton else str(ROOT/'.workspace/wine-prefix')
bins=str(pathlib.Path(proton)/'files/bin') if proton else '/usr/bin'
env=os.environ.copy();env.update(WINEPREFIX=prefix,TMPDIR=str(ROOT/'.workspace/tmp'),XDG_CACHE_HOME=str(ROOT/'.workspace/cache'),XDG_CONFIG_HOME=str(ROOT/'.workspace/config'),WINEDEBUG='-all',WINEDLLOVERRIDES='mscoree,mshtml=',DISPLAY='',WAYLAND_DISPLAY='')
for k in ['FLOWGATE_WINE_TABLE_RUNNER','FLOWGATE_WINE_BROKER']:env.pop(k,None)
def start(name,mode,port):
    path=RUN/f'{label}-v6-{name}-{mode}-{port}.log';f=path.open('w');p=subprocess.Popen([runner,str(ROOT/'.workspace/windows'/name),mode,str(port)],env=env,stdout=f,stderr=f);children.append(p);wait(lambda:'READY' in path.read_text(),60);return path

def checked_pending(port,family=None):
    v=next((e for e in events() if e['flow']['local'].endswith(':'+str(port)) and e['state'] in ['blocked','awaiting-decision'] and (family is None or e['flow']['local'].startswith('[')==(family==6))),None)
    if v and v['state']=='blocked':raise AssertionError(v)
    return v
evidence=[]
try:
    # Runtime is listening before discovery/attachment.
    start('alpha.exe','U',25100)
    for p in (SOCK,SOCK+'.monitor'):
        if os.path.exists(p):os.unlink(p)
    logpath=RUN/f'{label}-v6-daemon.log';log=logpath.open('w');d=subprocess.Popen([BIN,'serve-lab','--rules',localhost_ask_rules('incoming'),'--parent-netns',os.environ['FLOWGATE_PARENT_NETNS'],'--socket',SOCK,'--attach-prefixes',prefix,'--runtime-bins',bins],env=env,stdout=log,stderr=log);children.append(d);wait(lambda:'READY' in logpath.read_text() or d.poll() is not None,15);assert d.poll() is None,logpath.read_text()
    port=25101
    for udp in [False,True]:
        for reverse in [False,True]:
            for name,allow in [('alpha.exe',not reverse),('beta.exe',reverse)]:
                path=start(name,'U' if udp else 'T',port)
                if udp:
                    c=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM);c.sendto(b'once',('::1',port))
                else:c=client(port,v6=True)
                v=wait(lambda:checked_pending(port));assert not delivered(path);assert v['attribution']['runtime_table']['windows_handle_holders'][0]['family']==6;evidence.append(v);decide(v,'allow' if allow else 'block','application')
                if allow:wait(lambda:delivered(path))
                else:time.sleep(.1);assert not delivered(path)
                if udp:c.close()
                print('PASS',label,'IPv6','UDP one-shot' if udp else 'ordinary TCP',name,'allow' if allow else 'block',flush=True);port+=1
    # Dual-stack wildcard: test both wire families on a single listener.
    for mode,udp in [('D',False),('E',True),('M',False),('N',True)]:
        path=start('alpha.exe',mode,port)
        for v6 in ([False,True] if mode in ['D','E'] else [False]):
            before=path.read_text().count('RECEIVED')
            if udp:
                c=socket.socket(socket.AF_INET6 if v6 else socket.AF_INET,socket.SOCK_DGRAM);c.sendto(b'once',('::1' if v6 else '127.0.0.1',port))
            else:c=client(port,v6=v6)
            v=wait(lambda:checked_pending(port));assert path.read_text().count('RECEIVED')==before
            assert v['attribution']['sockets'][0]['family']==10 and not v['attribution']['sockets'][0]['v6_only'];evidence.append(v);decide(v,'allow');wait(lambda:path.read_text().count('RECEIVED')>before)
            if udp:c.close()
        print('PASS',label,'dual wildcard' if mode in ['D','E'] else 'IPv4-mapped IPv6 bind',mode,flush=True);port+=1
    # Two plausible listeners must stay ambiguous; a v6-only listener does not
    # claim an IPv4 flow when a separate IPv4 fixture owns the same service port.
    path6=start('alpha.exe','V',port);path4=start('beta.exe','t',port)
    c=client(port);v=wait(lambda:checked_pending(port));assert v['attribution']['application']['name']=='beta.exe';decide(v,'block');assert not delivered(path4)
    c=client(port,v6=True);v=wait(lambda:checked_pending(port,6));assert v['attribution']['application']['name']=='alpha.exe';decide(v,'allow');wait(lambda:delivered(path6));assert not delivered(path4)
    print('PASS',label,'IPv6-only wildcard and separate IPv4 application stay distinct',flush=True)
    (RUN/f'{label}-ipv6.json').write_text(json.dumps(evidence,indent=2))
finally:
    for p in children:
        if p.poll() is None:p.terminate()
    for p in children:
        try:p.wait(timeout=3)
        except subprocess.TimeoutExpired:p.kill()

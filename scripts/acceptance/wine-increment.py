#!/usr/bin/env python3
"""Receiver evidence for explicitly enabled Wine 11.19 non-sharing model."""
from lablib import *
os.environ['FLOWGATE_WINE_BROKER']='/usr/bin/wineserver'
env=os.environ.copy();env.update(WINEPREFIX=str(ROOT/'.workspace/wine-prefix'),TMPDIR=str(ROOT/'.workspace/tmp'),XDG_CACHE_HOME=str(ROOT/'.workspace/cache'),XDG_CONFIG_HOME=str(ROOT/'.workspace/config'),WINEDEBUG='-all',WINEDLLOVERRIDES='mscoree,mshtml=',DISPLAY='',WAYLAND_DISPLAY='')
def start(name,proto,port):
    path=RUN/f'{name}-{port}.log';f=path.open('w');p=subprocess.Popen(['wine',str(ROOT/'.workspace/windows'/name),proto,str(port)],env=env,stdout=f,stderr=f);children.append(p);wait(lambda:'READY' in path.read_text(),40);return p,path
try:
    for p in (SOCK,SOCK+'.monitor'):
        if os.path.exists(p):os.unlink(p)
    log=(RUN/'wine-increment-daemon.log').open('w');d=subprocess.Popen([BIN,'serve-lab','--rules',localhost_ask_rules('incoming'),'--parent-netns',os.environ['FLOWGATE_PARENT_NETNS'],'--socket',SOCK,'--timeout','5s'],stdout=log,stderr=log);children.append(d);wait(lambda:'READY' in (RUN/'wine-increment-daemon.log').read_text())
    evidence=[]
    for udp,base in [(True,24400),(False,24410)]:
        for reverse in [False,True]:
            # Different service ports create independent remembered-rule scopes for reversal.
            pairs=[('alpha.exe',base+int(reverse)*2+1,not reverse),('beta.exe',base+int(reverse)*2+2,reverse)]
            running={name:start(name,'u' if udp else 'p',port) for name,port,_ in pairs}
            for name,port,allow in pairs:
                p,path=running[name]
                if udp:
                    c=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);c.sendto(b'ONE-SHOT',('127.0.0.1',port))
                else:c=client(port)
                v=wait(lambda:pending(port));evidence.append(v);assert v['attribution']['status']=='corroborated-broker-client',v
                assert len(v['attribution']['owners'])==2 and not delivered(path)
                result=decide(v,'allow' if allow else 'block','application');assert result['decision']['remembered_filter']['local_port']==port
                if allow:wait(lambda:delivered(path))
                else:time.sleep(.25);assert not delivered(path)
                if udp:c.close()
                print('PASS Wine', 'UDP one-shot' if udp else 'TCP (FIONREAD client FD)',name,'allow' if allow else 'block',flush=True)
            aa,bb=[v['attribution'] for v in evidence[-2:]]
            assert aa['association']['broker_pid']==bb['association']['broker_pid']
            assert aa['application']['runtime']==bb['application']['runtime'] and aa['application']['prefix']==bb['application']['prefix']
            for p,path in running.values():p.terminate();p.wait()
    (RUN/'wine-increment-evidence.json').write_text(json.dumps(evidence,indent=2))
    keys={v['attribution']['application']['name']:v['attribution']['application']['key'] for v in evidence};assert keys['alpha.exe']!=keys['beta.exe']
    print('PASS permissions use distinct application keys; both decision directions tested',flush=True)
finally:
    for p in children:
        if p.poll() is None:p.terminate()
    for p in children:
        try:p.wait(timeout=3)
        except subprocess.TimeoutExpired:p.kill()

#!/usr/bin/env python3
"""Receiver tests for the opt-in runtime census. Run sequentially via lab.sh."""
from lablib import *
proton=os.environ.get('FLOWGATE_TEST_PROTON')
runner=str(ROOT/'scripts/acceptance/proton-fixture.sh') if proton else '/usr/bin/wine'
prefix=str(ROOT/'.workspace/proton-prefix/pfx') if proton else str(ROOT/'.workspace/wine-prefix')
broker=str(pathlib.Path(proton)/'files/bin/wineserver') if proton else '/usr/bin/wineserver'
os.environ.update(FLOWGATE_WINE_BROKER=broker,FLOWGATE_WINE_TABLE_RUNNER=runner,FLOWGATE_WINE_TABLE_HELPER=str(ROOT/'.workspace/windows/table-probe.exe'),FLOWGATE_WINE_TABLE_VERSION='11.0' if proton else '11.19',WINEPREFIX=prefix)
label='proton' if proton else 'wine' 
env=os.environ.copy();env.update(WINEPREFIX=prefix,TMPDIR=str(ROOT/'.workspace/tmp'),XDG_CACHE_HOME=str(ROOT/'.workspace/cache'),XDG_CONFIG_HOME=str(ROOT/'.workspace/config'),WINEDEBUG='-all',WINEDLLOVERRIDES='mscoree,mshtml=',DISPLAY='',WAYLAND_DISPLAY='')
os.environ.update(env)
def start(name,proto,port):
    path=RUN/f'{name}-{port}.log';f=path.open('w');p=subprocess.Popen([runner,str(ROOT/'.workspace/windows'/name),proto,str(port)],env=env,stdout=f,stderr=f);children.append(p);wait(lambda:'READY' in path.read_text(),40);return p,path
try:
    for p in (SOCK,SOCK+'.monitor'):
        if os.path.exists(p):os.unlink(p)
    log=(RUN/'wine-increment-daemon.log').open('w');d=subprocess.Popen([BIN,'serve-lab','--rules',localhost_ask_rules('incoming'),'--parent-netns',os.environ['FLOWGATE_PARENT_NETNS'],'--socket',SOCK,'--timeout','5s'],stdout=log,stderr=log);children.append(d);wait(lambda:'READY' in (RUN/'wine-increment-daemon.log').read_text())
    evidence=[]
    for udp,base in [(True,24400),(False,24410)]:
        for reverse in [False,True]:
            # Different service ports create independent remembered-rule scopes for reversal.
            pairs=[('alpha.exe',base+int(reverse)*2+1,not reverse),('beta.exe',base+int(reverse)*2+2,reverse)]
            running={name:start(name,'u' if udp else 't',port) for name,port,_ in pairs}
            for name,port,allow in pairs:
                p,path=running[name]
                if udp:
                    c=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);c.sendto(b'ONE-SHOT',('127.0.0.1',port))
                else:c=client(port)
                v=wait(lambda:pending(port));evidence.append(v);assert v['attribution']['status']=='corroborated-runtime-table',v
                assert not delivered(path)
                result=decide(v,'allow' if allow else 'block','application');assert result['decision']['remembered_filter']['local_port']==port
                if allow:wait(lambda:delivered(path))
                else:time.sleep(.25);assert not delivered(path)
                if udp:c.close()
                print('PASS',label, 'UDP one-shot' if udp else 'plain TCP',name,'allow' if allow else 'block',flush=True)
            aa,bb=[v['attribution'] for v in evidence[-2:]]
            assert aa['runtime_table']['broker_pid']==bb['runtime_table']['broker_pid']
            assert aa['application']['runtime']==bb['application']['runtime'] and aa['application']['prefix']==bb['application']['prefix']
            # Ports differ for reversal. Namespace teardown cleans all runtime descendants.
            if not proton:
                for p,path in running.values():p.terminate();p.wait()
    (RUN/(label+'-table-enforcement.json')).write_text(json.dumps(evidence,indent=2))
    keys={v['attribution']['application']['name']:v['attribution']['application']['key'] for v in evidence};assert keys['alpha.exe']!=keys['beta.exe']
    print('PASS permissions use distinct application keys; both decision directions tested',flush=True)
finally:
    for p in children:
        if p.poll() is None:p.terminate()
    for p in children:
        try:p.wait(timeout=3)
        except subprocess.TimeoutExpired:p.kill()

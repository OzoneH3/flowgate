#!/usr/bin/env python3
"""Actual PE fixtures. Shared wineserver ownership is an expected limitation, not a passed Allow test."""
from lablib import *
env=os.environ.copy();env.update(WINEPREFIX=str(ROOT/'.workspace/wine-prefix'),TMPDIR=str(ROOT/'.workspace/tmp'),XDG_CACHE_HOME=str(ROOT/'.workspace/cache'),XDG_CONFIG_HOME=str(ROOT/'.workspace/config'),WINEDEBUG='-all',WINEDLLOVERRIDES='mscoree,mshtml=',DISPLAY='',WAYLAND_DISPLAY='')
try:
    for name,port in [('alpha.exe',24201),('beta.exe',24202)]:
        path=RUN/(name+'.log');f=path.open('w');p=subprocess.Popen(['wine',str(ROOT/'.workspace/windows'/name),'u',str(port)],env=env,stdout=f,stderr=f);children.append(p)
    wait(lambda:all('READY' in (RUN/(name+'.log')).read_text() for name in ['alpha.exe','beta.exe']),40)
    attrs=[cli('attribute','--protocol','udp','--local',f'127.0.0.1:{port}','--remote','127.0.0.1:50000') for port in [24201,24202]]
    apps=[[o['application'] for o in a['owners'] if o['application']['kind']=='wine'][0] for a in attrs]
    assert apps[0]['key']!=apps[1]['key'];assert apps[0]['runtime']==apps[1]['runtime'];assert apps[0]['prefix']==apps[1]['prefix']
    assert all(a['status']=='multiple-candidates' and not a.get('application') for a in attrs)
    (RUN/'wine-attribution.json').write_text(json.dumps(attrs,indent=2))
    print('PASS observed distinct PE identities, same runtime and prefix; shared wineserver retained',flush=True)
    for p in (SOCK,SOCK+'.monitor'):
        if os.path.exists(p):os.unlink(p)
    log=(RUN/'wine-daemon.log').open('w');d=subprocess.Popen([BIN,'serve-lab','--rules',localhost_ask_rules('incoming'),'--parent-netns',os.environ['FLOWGATE_PARENT_NETNS'],'--socket',SOCK],stdout=log,stderr=log);children.append(d)
    wait(lambda:'READY' in (RUN/'wine-daemon.log').read_text())
    for port in [24201,24202]:
        c=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);c.sendto(b'test',('127.0.0.1',port));c.close()
    wait(lambda:len(events())==2)
    assert all(e['state']=='blocked' and e['rule']=='unsafe-attribution' for e in events())
    assert not any(delivered(RUN/(name+'.log')) for name in ['alpha.exe','beta.exe'])
    print('PASS ambiguous Wine traffic denied at receivers; per-application Allow/Block acceptance remains UNVERIFIED',flush=True)
finally:
    for p in children:
        if p.poll() is None:p.terminate()
    for p in children:
        try:p.wait(timeout=3)
        except subprocess.TimeoutExpired:p.kill()

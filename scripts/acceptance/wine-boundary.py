#!/usr/bin/env python3
"""Demonstrate visible sharing, dormant handles and broker-only TCP boundaries."""
from lablib import *
os.environ['FLOWGATE_WINE_BROKER']='/usr/bin/wineserver'
release=RUN/'release-inherited';release.unlink(missing_ok=True)
env=os.environ.copy();env.update(WINEPREFIX=str(ROOT/'.workspace/wine-prefix'),TMPDIR=str(ROOT/'.workspace/tmp'),XDG_CACHE_HOME=str(ROOT/'.workspace/cache'),XDG_CONFIG_HOME=str(ROOT/'.workspace/config'),WINEDEBUG='-all',WINEDLLOVERRIDES='mscoree,mshtml=',DISPLAY='',WAYLAND_DISPLAY='',FLOWGATE_FIXTURE_RELEASE='Z:'+str(release))
def start(mode,port):
    path=RUN/f'boundary-{port}.log';f=path.open('w');p=subprocess.Popen(['wine',str(ROOT/'.workspace/windows/alpha.exe'),mode,str(port)],env=env,stdout=f,stderr=f);children.append(p);wait(lambda:'READY' in path.read_text(),40);return p,path
def attr(port,proto='udp'):
    return cli('attribute','--protocol',proto,'--local',f'127.0.0.1:{port}','--remote','127.0.0.1:50000')
evidence={}
try:
    p,path=start('t',24600);a=attr(24600,'tcp');assert not a.get('application') and len(a['owners'])==1;a['observation']='plain listener has only broker FD';evidence['plain_tcp']=a
    print('PASS boundary: plain TCP listener has no visible client socket FD',flush=True)
    p,path=start('s',24601);wait(lambda:'MATERIALIZED' in path.read_text());a=attr(24601);assert a['status']=='multiple-candidates' and len(a['owners'])==3;evidence['visible_shared']=a
    print('PASS inherited socket with two visible Windows clients remains ambiguous',flush=True)
    p,path=start('d',24602);wait(lambda:'DORMANT' in path.read_text());a=attr(24602);assert a['status']=='corroborated-broker-client' and len(a['owners'])==2;evidence['dormant_handle_invisible']=a
    # The child already has a Windows handle, but its Unix descriptor has not been cached.
    p.terminate();p.wait();a=wait(lambda:(a if len((a:=attr(24602))['owners'])==1 else None));assert not a.get('application');evidence['server_only_after_exit']=a
    print('PASS boundary: dormant inherited handle is invisible; parent exit leaves broker-only socket, denied',flush=True)
    release.touch();wait(lambda:'MATERIALIZED' in path.read_text());a=attr(24602);assert a['status']=='corroborated-broker-client' and a['application']['name']=='beta.exe';evidence['child_materialized']=a
    assert a['fingerprint']!=evidence['dormant_handle_invisible']['fingerprint']
    print('PASS materialized child gets its own identity and a changed ownership fingerprint',flush=True)
    # Missing broker evidence must not be replaced with a process-name exception.
    old=os.environ['FLOWGATE_WINE_BROKER'];os.environ['FLOWGATE_WINE_BROKER']='/usr/bin/false';a=attr(24602);assert not a.get('application');os.environ['FLOWGATE_WINE_BROKER']=old
    for pth in (SOCK,SOCK+'.monitor'):
        if os.path.exists(pth):os.unlink(pth)
    log=(RUN/'wine-boundary-daemon.log').open('w');d=subprocess.Popen([BIN,'serve-lab','--parent-netns',os.environ['FLOWGATE_PARENT_NETNS'],'--socket',SOCK,'--timeout','5s'],stdout=log,stderr=log);children.append(d);wait(lambda:'READY' in (RUN/'wine-boundary-daemon.log').read_text())
    c=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);c.sendto(b'shared',('127.0.0.1',24601))
    wait(lambda:any(e['flow']['local'].endswith(':24601') and e['state']=='blocked' for e in events()));assert not delivered(RUN/'boundary-24601.log')
    release.unlink();p,path=start('d',24603);wait(lambda:'DORMANT' in path.read_text());c.sendto(b'stale',('127.0.0.1',24603));v=wait(lambda:pending(24603));release.touch();wait(lambda:'MATERIALIZED' in path.read_text())
    q=subprocess.run([BIN,'decide','--socket',SOCK,'--id',v['id'],'--action','allow'],capture_output=True);assert q.returncode!=0;time.sleep(.15);assert not delivered(path)
    print('PASS shared clients denied at receiver; newly materialized inherited client invalidates pending approval',flush=True)
    (RUN/'wine-boundary.json').write_text(json.dumps(evidence,indent=2))
finally:
    for p in children:
        if p.poll() is None:p.terminate()
    for p in children:
        try:p.wait(timeout=3)
        except subprocess.TimeoutExpired:p.kill()

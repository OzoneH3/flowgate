#!/usr/bin/env python3
"""Read-only discovery, two prefixes, loss/restart, explicit reattachment."""
from lablib import *
import shutil
proton=os.environ.get('FLOWGATE_TEST_PROTON');label='proton' if proton else 'wine'
binpath=str(pathlib.Path(proton)/'files/bin') if proton else '/usr/bin'
runner=str(ROOT/'scripts/acceptance/proton-fixture.sh') if proton else '/usr/bin/wine'
first=ROOT/('.workspace/proton-prefix/pfx' if proton else '.workspace/wine-prefix')
second=ROOT/('.workspace/proton-session-second/pfx' if proton else '.workspace/wine-session-second')
# Initialized workspace template; do not follow user-directory symlinks.
if not second.exists():shutil.copytree(first,second,symlinks=True)
prefixes=[first.resolve(),second.resolve()]
envs=[]
for prefix in prefixes:
    env=os.environ.copy();env.update(WINEPREFIX=str(prefix),TMPDIR=str(ROOT/'.workspace/proton-tmp' if proton else ROOT/'.workspace/tmp'),XDG_CACHE_HOME=str(ROOT/'.workspace/cache'),XDG_CONFIG_HOME=str(ROOT/'.workspace/config'),WINEDEBUG='-all',WINEDLLOVERRIDES='mscoree,mshtml=',DISPLAY='',WAYLAND_DISPLAY='')
    if proton:env['FLOWGATE_TEST_PREFIX']=str(prefix.parent)
    for k in ['FLOWGATE_WINE_BROKER','FLOWGATE_WINE_TABLE_RUNNER','FLOWGATE_WINE_TABLE_VERSION','FLOWGATE_WINE_TABLE_HELPER']:env.pop(k,None)
    envs.append(env)
def start(i,port):
    path=RUN/f'{label}-attach-{i}-{port}.log';f=path.open('w');p=subprocess.Popen([runner,str(ROOT/'.workspace/windows/alpha.exe'),'u',str(port)],env=envs[i],stdout=f,stderr=f);children.append(p);wait(lambda:'READY' in path.read_text(),60);return path

def discovery():return cli('runtime-discover','--runtime-bins',binpath)
def daemon():
    for p in (SOCK,SOCK+'.monitor'):
        if os.path.exists(p):os.unlink(p)
    path=RUN/f'{label}-attach-daemon.log';f=path.open('w');p=subprocess.Popen([BIN,'serve-lab','--parent-netns',os.environ['FLOWGATE_PARENT_NETNS'],'--socket',SOCK,'--attach-prefixes',','.join(map(str,prefixes)),'--runtime-bins',binpath],env=envs[0],stdout=f,stderr=f);children.append(p)
    wait(lambda:'READY' in path.read_text() or p.poll() is not None,15);assert p.poll() is None,path.read_text();return p

evidence={}
try:
    paths=[start(i,25001+i) for i in range(2)]
    sessions=discovery();selected=[s for s in sessions if s['broker']['application']['prefix'] in list(map(str,prefixes))];assert len(selected)==2 and all(not s['helper_peer_detected'] and s['supported'] for s in selected),sessions;evidence['before']=selected
    d=daemon();sessions=discovery();assert sum(s['helper_peer_detected'] for s in sessions)==2;evidence['attached']=sessions
    c=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    decisions=[]
    for i in range(2):
        c.sendto(b'initial',('127.0.0.1',25001+i));v=wait(lambda:pending(25001+i));decisions.append(v);decide(v,'allow' if i==0 else 'block','application')
    wait(lambda:delivered(paths[0]));assert not delivered(paths[1]);assert decisions[0]['attribution']['application']['key']!=decisions[1]['attribution']['application']['key'];evidence['independent']=decisions
    print('PASS read-only discovery, late attachment, two same-runtime/executable prefixes isolated',flush=True)
    # Move the service port to the same executable in the other prefix: an
    # application rule must not follow the runtime or port across sessions.
    for proc in pathlib.Path('/proc').iterdir():
        try:
            args=[v for v in (proc/'cmdline').read_bytes().split(b'\0') if v]
            if args[-2:]==[b'u',b'25001'] and str(ROOT/'.workspace/windows/alpha.exe') in (proc/'maps').read_text():os.kill(int(proc.name),signal.SIGKILL)
        except OSError:pass
    wait(lambda:not any(s['protocol']=='udp' and s['local'].endswith(':25001') for s in cli('sockets')))
    moved=start(1,25001);c.sendto(b'no-inheritance',('127.0.0.1',25001));v=wait(lambda:pending(25001));assert v['attribution']['application']['key']==decisions[1]['attribution']['application']['key'];assert not delivered(moved);decide(v,'block');evidence['cross_prefix_port_reuse']=v
    print('PASS same executable/service port in second prefix does not inherit first prefix permission',flush=True)

    helperpath=start(0,25004);c.sendto(b'helper-loss',('127.0.0.1',25004));lost=wait(lambda:pending(25004))
    helperids=[]
    for proc in pathlib.Path('/proc').iterdir():
        try:
            env=dict(v.split(b'=',1) for v in (proc/'environ').read_bytes().split(b'\0') if b'=' in v)
            if pathlib.Path(os.fsdecode(env.get(b'WINEPREFIX',b'/'))).resolve()==prefixes[0] and str(ROOT/'.workspace/windows/table-probe.exe') in (proc/'maps').read_text():helperids.append(int(proc.name))
        except (OSError,ValueError):pass
    assert len(helperids)==1,helperids;os.kill(helperids[0],signal.SIGKILL)
    q=subprocess.run([BIN,'decide','--socket',SOCK,'--id',lost['id'],'--action','allow'],capture_output=True);assert q.returncode and not delivered(helperpath);evidence['helper_exit']=lost
    d.terminate();d.wait(timeout=5);d=daemon()
    q=subprocess.run([BIN,'decide','--socket',SOCK,'--id',lost['id'],'--action','allow'],capture_output=True);assert q.returncode
    print('PASS attached helper exit rejects retained approval; explicit recovery rejects old ID',flush=True)
    # A pending datagram in the first runtime must not survive its server death.
    pendingpath=start(0,25003);c.sendto(b'held',('127.0.0.1',25003));old=wait(lambda:pending(25003));s=next(s for s in selected if s['broker']['application']['prefix']==str(prefixes[0]));os.kill(s['broker']['pid'],signal.SIGKILL)
    q=subprocess.run([BIN,'decide','--socket',SOCK,'--id',old['id'],'--action','allow'],capture_output=True);assert q.returncode and not delivered(pendingpath)
    # ntsync clients can remain alive after SIGKILL of wineserver. Clean up
    # only the disposable test runtime's PE processes before reusing its port.
    for proc in pathlib.Path('/proc').iterdir():
        try:
            env=dict(v.split(b'=',1) for v in (proc/'environ').read_bytes().split(b'\0') if b'=' in v);maps=(proc/'maps').read_text()
            if pathlib.Path(os.fsdecode(env.get(b'WINEPREFIX',b'/'))).resolve()==prefixes[0] and ('/ntdll.dll' in maps or '/ntdll.so' in maps):os.kill(int(proc.name),signal.SIGKILL)
        except (OSError,ValueError):pass
    replacement=start(0,25003);newsession=next(s for s in discovery() if s['broker']['application']['prefix']==str(prefixes[0]));assert newsession['id']!=s['id'];c.sendto(b'new-server',('127.0.0.1',25003));time.sleep(.2);assert not delivered(replacement)
    assert not pending(25003);evidence['replaced']={'old':s,'new':newsession,'pending':old}
    print('PASS server exit/restart invalidates pending and cached session; no automatic fallback',flush=True)
    d.terminate();d.wait(timeout=5)
    # New observer generation is an explicit recovery, with a new policy engine.
    d=daemon();c.sendto(b'recovered',('127.0.0.1',25003));fresh=wait(lambda:pending(25003));assert fresh['id']!=old['id'] and fresh['attribution']['fingerprint']!=old['attribution']['fingerprint'];decide(fresh,'allow');wait(lambda:delivered(replacement));evidence['recovered']=fresh
    q=subprocess.run([BIN,'decide','--socket',SOCK,'--id',old['id'],'--action','allow'],capture_output=True);assert q.returncode
    print('PASS explicit reattachment recovers with a new generation; old answer rejected',flush=True)
    (RUN/f'{label}-attachment.json').write_text(json.dumps(evidence,indent=2))
finally:
    for p in children:
        if p.poll() is None:p.terminate()
    for p in children:
        try:p.wait(timeout=3)
        except subprocess.TimeoutExpired:p.kill()

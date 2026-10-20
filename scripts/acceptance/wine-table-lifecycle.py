#!/usr/bin/env python3
"""Actual handle-holder census, late startup, parent exit, replacement and loss."""
from lablib import *
import select
proton=os.environ.get('FLOWGATE_TEST_PROTON')
label='proton' if proton else 'wine'
runner=str(ROOT/'scripts/acceptance/proton-fixture.sh') if proton else '/usr/bin/wine'
prefix=str(ROOT/'.workspace/proton-prefix/pfx') if proton else str(ROOT/'.workspace/wine-prefix')
broker=str(pathlib.Path(proton)/'files/bin/wineserver') if proton else '/usr/bin/wineserver'
release=RUN/'table-release';release.unlink(missing_ok=True)
os.environ.update(WINEPREFIX=prefix,TMPDIR=str(ROOT/'.workspace/tmp'),XDG_CACHE_HOME=str(ROOT/'.workspace/cache'),XDG_CONFIG_HOME=str(ROOT/'.workspace/config'),WINEDEBUG='-all',WINEDLLOVERRIDES='mscoree,mshtml=',DISPLAY='',WAYLAND_DISPLAY='',FLOWGATE_FIXTURE_RELEASE='Z:'+str(release),FLOWGATE_WINE_BROKER=broker,FLOWGATE_WINE_TABLE_RUNNER=runner,FLOWGATE_WINE_TABLE_HELPER=str(ROOT/'.workspace/windows/table-probe.exe'),FLOWGATE_WINE_TABLE_VERSION='11.0' if proton else '11.19')
def start(name,mode,port):
    path=RUN/f'{label}-table-life-{port}.log'
    f=path.open('w');p=subprocess.Popen([runner,str(ROOT/'.workspace/windows'/name),mode,str(port)],stdout=f,stderr=f);children.append(p)
    wait(lambda:'READY' in path.read_text(),60)
    return p,path

def pe_pids(image,tail=None):
    out=[]
    for proc in pathlib.Path('/proc').iterdir():
        if not proc.name.isdigit():continue
        try:
            args=[a for a in (proc/'cmdline').read_bytes().split(b'\0') if a];maps=(proc/'maps').read_text()
            if str(ROOT/'.workspace/windows'/image) not in maps:continue
            if tail and args[-2:]!=[str(x).encode() for x in tail]:continue
            out.append(int(proc.name))
        except (OSError,UnicodeError):pass
    return out

def stop_parent(mode,port):
    ids=pe_pids('alpha.exe',[mode,port]);assert len(ids)==1,ids
    os.kill(ids[0],signal.SIGTERM)

evidence={}
try:
    a,al=start('alpha.exe','t',24801);b,bl=start('beta.exe','t',24802)
    d,dl=start('alpha.exe','i',24803);u,ul=start('alpha.exe','d',24804)
    wait(lambda:'DORMANT' in dl.read_text() and 'DORMANT' in ul.read_text())
    # Start the observer after creation and inheritance: no event history needed.
    helper=subprocess.Popen([runner,str(ROOT/'.workspace/windows/table-probe.exe')],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=open(RUN/f'{label}-table-helper.log','w'),text=True);children.append(helper)
    def scan(proto):
        helper.stdin.write(proto+'\n');helper.stdin.flush()
        assert select.select([helper.stdout],[],[],10)[0],'snapshot deadline'
        s=json.loads(helper.stdout.readline());assert s['complete'],s;return s
    def holders(s,port):return {(r['pid'],r['created'],pathlib.PureWindowsPath(r['image']).name) for r in s['rows'] if r['port']==port}
    t=scan('t');v=scan('u');evidence.update(initial_tcp=t,initial_udp=v)
    assert len(holders(t,24801))==len(holders(t,24802))==1
    assert {r[2] for r in holders(t,24803)}=={'alpha.exe','beta.exe'}
    assert {r[2] for r in holders(v,24804)}=={'alpha.exe','beta.exe'}
    for port,proto in [(24803,'tcp'),(24804,'udp')]:
        raw=cli('attribute','--protocol',proto,'--local',f'127.0.0.1:{port}','--remote','127.0.0.1:50000');evidence[f'raw_{proto}']=raw
        assert all(o['application'].get('name')!='beta.exe' for o in raw['owners'])
    print('PASS late census sees dormant inherited TCP/UDP holders absent from Unix FD owners',flush=True)
    stop_parent('i',24803);stop_parent('d',24804)
    t=wait(lambda:(s if len(holders(s:=scan('t'),24803))==1 else None));v=scan('u')
    assert {r[2] for r in holders(t,24803)}=={'beta.exe'}
    assert {r[2] for r in holders(v,24804)}=={'beta.exe'}
    evidence.update(parent_exit_tcp=t,parent_exit_udp=v)
    release.touch();wait(lambda:dl.read_text().count('READY')==2 and ul.read_text().count('READY')==2)
    for port,udp in [(24801,False),(24802,False),(24803,False),(24804,True)]:
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM if udp else socket.SOCK_STREAM) as c:
            c.settimeout(3);c.connect(('127.0.0.1',port));c.send(b'fixture')
    for path in [al,bl,dl,ul]:wait(lambda:delivered(path))
    print('PASS ordinary TCP/UDP receivers and dormant children receive after parent exit/release',flush=True)
    # Stop diagnostic helper before starting the adapter (unique observer peer).
    for pid in pe_pids('table-probe.exe'):os.kill(pid,signal.SIGTERM)
    helper.wait(timeout=5)
    for p in (SOCK,SOCK+'.monitor'):
        if os.path.exists(p):os.unlink(p)
    log=(RUN/f'{label}-table-life-daemon.log').open('w')
    daemon=subprocess.Popen([BIN,'serve-lab','--parent-netns',os.environ['FLOWGATE_PARENT_NETNS'],'--socket',SOCK,'--timeout','5s'],stdout=log,stderr=log);children.append(daemon)
    wait(lambda:'READY' in (RUN/f'{label}-table-life-daemon.log').read_text())
    # Replacement while a packet is held cannot inherit the pending approval.
    p,path=start('alpha.exe','t',24805);c=client(24805);old=wait(lambda:pending(24805));stop_parent('t',24805)
    p,path=start('beta.exe','t',24805)
    result=subprocess.run([BIN,'decide','--socket',SOCK,'--id',old['id'],'--action','allow'],capture_output=True)
    assert result.returncode and not delivered(path)
    evidence['stale_listener']=old
    print('PASS replaced listener rejects stale approval, receiver empty',flush=True)
    # A dormant second holder is sufficient to deny, without materializing an FD.
    release.unlink();p,path=start('alpha.exe','i',24806);wait(lambda:'DORMANT' in path.read_text());c=client(24806)
    e=wait(lambda:next((e for e in events() if e['flow']['local'].endswith(':24806')),None))
    assert e['state']=='blocked' and len(e['attribution']['runtime_table']['windows_handle_holders'])==2 and not delivered(path)
    evidence['shared_denied']=e
    print('PASS dormant shared listener denied before receiver delivery',flush=True)
    # Lose the observer while an undecided UDP datagram is retained.
    p,path=start('alpha.exe','u',24807);c=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);c.sendto(b'once',('127.0.0.1',24807));old=wait(lambda:pending(24807))
    ids=pe_pids('table-probe.exe');assert len(ids)==1,ids;os.kill(ids[0],signal.SIGKILL)
    result=subprocess.run([BIN,'decide','--socket',SOCK,'--id',old['id'],'--action','allow'],capture_output=True)
    assert result.returncode;time.sleep(.2);assert not delivered(path)
    evidence['observer_loss']=old
    print('PASS observer loss prevents retained UDP approval; no retry/restart fallback',flush=True)
    (RUN/f'{label}-table-lifecycle.json').write_text(json.dumps(evidence,indent=2))
finally:
    for p in children:
        if p.poll() is None:p.terminate()
    for p in children:
        try:p.wait(timeout=3)
        except subprocess.TimeoutExpired:p.kill()

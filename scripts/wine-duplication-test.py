#!/usr/bin/env python3
from lablib import *
import select
proton=os.environ.get('FLOWGATE_TEST_PROTON');label='proton' if proton else 'wine'
runner=str(ROOT/'scripts/proton-fixture.sh') if proton else '/usr/bin/wine'
prefix=str(ROOT/'.workspace/proton-prefix/pfx') if proton else str(ROOT/'.workspace/wine-prefix')
broker=str(pathlib.Path(proton)/'files/bin/wineserver') if proton else '/usr/bin/wineserver'
os.environ.update(WINEPREFIX=prefix,TMPDIR=str(ROOT/'.workspace/tmp'),XDG_CACHE_HOME=str(ROOT/'.workspace/cache'),XDG_CONFIG_HOME=str(ROOT/'.workspace/config'),WINEDEBUG='-all',WINEDLLOVERRIDES='mscoree,mshtml=',DISPLAY='',WAYLAND_DISPLAY='',FLOWGATE_WINE_BROKER=broker,FLOWGATE_WINE_TABLE_RUNNER=runner,FLOWGATE_WINE_TABLE_HELPER=str(ROOT/'.workspace/windows/table-probe.exe'),FLOWGATE_WINE_TABLE_VERSION='11.0' if proton else '11.19')
def checked_pending(port):
    v=next((e for e in events() if e['flow']['local'].endswith(':'+str(port)) and e['state'] in ['blocked','awaiting-decision']),None)
    if v and v['state']=='blocked':raise AssertionError(v)
    return v
evidence={}
def start(mode,port):
    folder=RUN/f'{label}-dup-{port}';folder.mkdir(exist_ok=True)
    for p in folder.iterdir():p.unlink()
    env=os.environ.copy();env['FLOWGATE_FIXTURE_DIR']='Z:'+str(folder)
    path=folder/'receiver.log';f=path.open('w');p=subprocess.Popen([runner,str(ROOT/'.workspace/windows/alpha-dup.exe'),mode,str(port)],env=env,stdout=f,stderr=f);children.append(p);wait(lambda:'READY' in path.read_text(),60);return folder,path
try:
    folder,path=start('d',24901)
    helper=subprocess.Popen([runner,str(ROOT/'.workspace/windows/table-probe.exe')],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True,stderr=open(RUN/f'{label}-dup-helper.log','w'));children.append(helper)
    def scan(port):
        helper.stdin.write('u\n');helper.stdin.flush();assert select.select([helper.stdout],[],[],10)[0]
        s=json.loads(helper.stdout.readline());assert s['complete'],s
        return [r for r in s['rows'] if r['port']==port]
    evidence['original']=scan(24901);assert len(evidence['original'])==1
    (folder/'prepare').touch();wait(lambda:'PREPARED' in path.read_text());evidence['prepared']=scan(24901)
    (folder/'materialize').touch();wait(lambda:'CONSTRUCTED' in path.read_text());evidence['constructed']=scan(24901);assert len({r['pid'] for r in evidence['constructed']})==2
    (folder/'close-parent').touch();wait(lambda:'PARENT_CLOSED' in path.read_text());evidence['parent_closed']=scan(24901);assert len(evidence['parent_closed'])==1 and evidence['parent_closed'][0]['image'].endswith('beta-dup.exe')
    (folder/'receive').touch();c=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);c.sendto(b'child',('127.0.0.1',24901));wait(lambda:delivered(path));(folder/'close-child').touch();wait(lambda:'FINAL_CLOSED' in path.read_text());assert not scan(24901)
    print('PASS actual WSADuplicateSocket stages; prepared holders:',len(evidence['prepared']),'constructed holders:',len(evidence['constructed']),'final close empty',flush=True)
    # Stop only our helper process, including Proton's direct Wine child.
    for proc in pathlib.Path('/proc').iterdir():
        try:
            if proc.name.isdigit() and str(ROOT/'.workspace/windows/table-probe.exe') in (proc/'maps').read_text():os.kill(int(proc.name),signal.SIGTERM)
        except OSError:pass
    helper.wait(timeout=5)
    for p in (SOCK,SOCK+'.monitor'):
        if os.path.exists(p):os.unlink(p)
    log=(RUN/f'{label}-dup-daemon.log').open('w');d=subprocess.Popen([BIN,'serve-lab','--parent-netns',os.environ['FLOWGATE_PARENT_NETNS'],'--socket',SOCK],stdout=log,stderr=log);children.append(d);wait(lambda:'READY' in (RUN/f'{label}-dup-daemon.log').read_text())
    folder,path=start('d',24902);c.sendto(b'pending',('127.0.0.1',24902));v=wait(lambda:checked_pending(24902));(folder/'prepare').touch();wait(lambda:'PREPARED' in path.read_text())
    q=subprocess.run([BIN,'decide','--socket',SOCK,'--id',v['id'],'--action','allow'],capture_output=True);assert q.returncode;assert not delivered(path);evidence['stale_duplication']=v
    (folder/'materialize').touch();wait(lambda:'CONSTRUCTED' in path.read_text());(folder/'receive').touch();c.sendto(b'shared',('127.0.0.1',24902));blocked=wait(lambda:next((e for e in events() if e['flow']['local'].endswith(':24902') and e['state']=='blocked'),None));assert blocked['attribution'].get('application') is None,blocked;time.sleep(.15);assert not delivered(path);evidence['shared_transition_denied']=blocked
    c.sendto(b'stable-shared',('127.0.0.1',24902));blocked=wait(lambda:next((e for e in events() if e['flow']['local'].endswith(':24902') and len(e['attribution'].get('runtime_table',{}).get('windows_handle_holders',[]))==2),None));assert blocked['state']=='blocked';time.sleep(.1);assert not delivered(path);evidence['shared_denied']=blocked
    print('PASS prepared duplication invalidates retained UDP; constructed shared receiver gets nothing',flush=True)
    folder,path=start('r',24903);c.sendto(b'old',('127.0.0.1',24903));v=wait(lambda:checked_pending(24903));(folder/'close-parent').touch();wait(lambda:'REBOUND' in path.read_text());lines=path.read_text().splitlines();old=next(x.split()[1] for x in lines if x.startswith('ORIGINAL '));new=next(x.split()[1] for x in lines if x.startswith('REUSED '));assert old==new
    q=subprocess.run([BIN,'decide','--socket',SOCK,'--id',v['id'],'--action','allow'],capture_output=True);assert q.returncode and not delivered(path)
    c.sendto(b'new',('127.0.0.1',24903));v2=wait(lambda:checked_pending(24903));assert v2['attribution']['fingerprint']!=v['attribution']['fingerprint'];decide(v2,'allow');wait(lambda:delivered(path));evidence['reuse']={'numeric_handle':old,'old':v,'new':v2}
    print('PASS actual numeric handle reuse',old,'new socket generation rejects stale packet',flush=True)
    # Accepted socket transfer: approval authorizes this connection, not a permanent owner.
    folder,path=start('a',24904);tcp=socket.socket();tcp.settimeout(5)
    import threading
    thread=threading.Thread(target=lambda:tcp.connect(('127.0.0.1',24904)));thread.start();v=wait(lambda:checked_pending(24904));decide(v,'allow');thread.join();wait(lambda:'ACCEPTED' in path.read_text());(folder/'prepare').touch();wait(lambda:'PREPARED' in path.read_text());(folder/'materialize').touch();wait(lambda:'CONSTRUCTED' in path.read_text());(folder/'close-parent').touch();wait(lambda:'PARENT_CLOSED' in path.read_text());(folder/'receive').touch();tcp.send(b'approved-connection');wait(lambda:delivered(path));tcp.close();evidence['accepted_transfer']=v
    print('PASS approved TCP continues after accepted-socket transfer to beta',flush=True)
    (RUN/f'{label}-duplication.json').write_text(json.dumps(evidence,indent=2))
finally:
    for p in children:
        if p.poll() is None:p.terminate()
    for p in children:
        try:p.wait(timeout=3)
        except subprocess.TimeoutExpired:p.kill()

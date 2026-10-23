#!/usr/bin/env python3
"""Real lwp -> Python/UMU -> pressure-vessel -> Proton -> PE regression.

Runs either the preserved failure reproduction or verified connection control. Only copied prefixes,
runtime data and private network/PID namespaces are used. The Python preflight
is labelled synthetic; UMU, Proton and the container launcher are unmodified.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import shlex
import sqlite3
import socket
import subprocess
import sys
import threading
import time
from lablib import localhost_ask_rules

ROOT = Path(__file__).resolve().parents[2]
p = argparse.ArgumentParser()
p.add_argument('--verify', action='store_true')
p.add_argument('--burst',action='store_true')
p.add_argument('--protocol',choices=['tcp','udp'],default='tcp')
p.add_argument('--helper')
p.add_argument('--binary', required=True)
p.add_argument('--run', required=True)
p.add_argument('--proton', required=True, help='workspace copy of installed Proton')
p.add_argument('--data', required=True, help='workspace data containing the copied umu/steamrt3 or steamrt4')
p.add_argument('--prefix-source', required=True, help='initialized workspace Proton compat directory')
p.add_argument('--pe', required=True)
p.add_argument('--lwp', required=True, help='actual installed lwp script (read-only)')
a = p.parse_args()
assert os.environ['FLOWGATE_PARENT_NETNS'] != os.readlink('/proc/self/ns/net')
assert os.geteuid() != 0, 'real UMU refuses root; use map-current-user, not lab.sh'
for value in [a.run,a.proton,a.data,a.prefix_source,a.pe]:
    assert Path(value).resolve().is_relative_to(ROOT/'.workspace'), value
RUN=Path(a.run).resolve(); RUN.mkdir(mode=0o700,parents=True)
BIN=str(Path(a.binary).resolve()); API=str(RUN/'api.sock')
for d in ['home','tmp','cache','config','runtime','games with spaces','steam']:(RUN/d).mkdir(mode=0o700)
prefixes=[]
for name in ['prefix-a','prefix-b']:
    dst=RUN/name
    subprocess.run(['cp','-a','--reflink=auto',a.prefix_source,str(dst)],check=True)
    for link in dst.rglob('*'):
        if link.is_symlink() and 'drive_c/users/' in str(link) and str(link.readlink()).startswith('/home/'):
            link.unlink(); link.symlink_to(RUN/'home',target_is_directory=True)
    prefixes.append(dst/'pfx')
for name in ['SyntheticAlpha.exe','SyntheticBeta.exe']:
    subprocess.run(['cp',a.pe,str(RUN/'games with spaces'/name)],check=True)
children=[]; received=[]; evidence=[]
server=socket.socket();server.bind(('127.0.0.1',0));server.listen();port=server.getsockname()[1]
preflight_port=port
udp_server=None
def receive():
    while True:
        try:
            c,_=server.accept()
            def handle(conn):
                with conn:
                    received.append(conn.recv(1024).decode())
                    try: conn.settimeout(20);conn.recv(1)
                    except OSError: pass
            threading.Thread(target=handle,args=(c,),daemon=True).start()
        except OSError:return
threading.Thread(target=receive,daemon=True).start()
if a.protocol=='udp':
    udp_server=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    udp_server.bind(('127.0.0.1',0));port=udp_server.getsockname()[1]
    def receive_udp():
        while True:
            try: received.append(udp_server.recvfrom(1024)[0].decode())
            except OSError:return
    threading.Thread(target=receive_udp,daemon=True).start()

def wait(fn,seconds=30):
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        v=fn()
        if v:return v
        time.sleep(.08)
    raise AssertionError('timeout: '+str(fn))
def call(op='list',**kw):
    with socket.socket(socket.AF_UNIX) as s:
        s.settimeout(10);s.connect(API)
        s.sendall((json.dumps(dict(version=1,operation=op,**kw))+'\n').encode())
        return json.loads(s.makefile('rb').readline())
def cli(*args):
    r=subprocess.run([BIN,*map(str,args)],capture_output=True,text=True,timeout=10)
    if r.returncode:raise RuntimeError(r.stderr)
    return json.loads(r.stdout)
def records():
    db=RUN/'decisions.db'
    if not db.exists():return []
    with sqlite3.connect('file:'+str(db)+'?mode=ro',uri=True) as c:
        return [json.loads(row[0]) for row in c.execute('select document from decisions order by seq')]
def proc_context(pid):
    root=Path('/proc')/str(pid)
    return dict(namespaces={n:os.readlink(root/'ns'/n) for n in ['mnt','net','user','pid']},uid_map=(root/'uid_map').read_text(),gid_map=(root/'gid_map').read_text())
def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def save(name,obj): (RUN/name).write_text(json.dumps(obj,indent=2))
def stop_prefix(prefix):
    victims=[]
    for d in Path('/proc').iterdir():
        if not d.name.isdigit() or int(d.name)==1:continue
        try:
            env=(d/'environ').read_bytes().split(b'\0')
            if any(x.startswith(b'WINEPREFIX=') and Path(x.split(b'=',1)[1].decode()).resolve()==prefix.resolve() for x in env):victims.append(int(d.name))
        except OSError:pass
    for pid in victims:
        try:os.kill(pid,signal.SIGKILL)
        except ProcessLookupError:pass

def find_pe(name,prefix):
    for d in Path('/proc').iterdir():
        if not d.name.isdigit():continue
        try:
            cmd=(d/'cmdline').read_bytes().split(b'\0')[0].decode(errors='replace')
            env=(d/'environ').read_bytes().split(b'\0')
            if cmd.replace('\\','/').endswith('/'+name) and any(x.startswith(b'WINEPREFIX=') and Path(x.split(b'=',1)[1].decode()).resolve()==prefix.resolve() for x in env):return int(d.name)
        except OSError:pass
    return None
steam=RUN/'home/.steam/steam/compatibilitytools.d'
steam.mkdir(parents=True)
subprocess.run(['cp','-a','--reflink=auto',a.proton,str(steam/'dwproton-fixture')],check=True)
base=dict(FLOWGATE_TEST_PROTOCOL=a.protocol,FLOWGATE_TEST_PREFLIGHT_PORT=str(preflight_port),FLOWGATE_TEST_CONNECTIONS='3' if a.burst else '1',PATH='/usr/bin:/bin',LANG='C.UTF-8',USER=os.environ.get('USER','flowgate-user'),LOGNAME=os.environ.get('LOGNAME','flowgate-user'),HOME=str(RUN/'home'),TMPDIR=str(RUN/'tmp'),XDG_RUNTIME_DIR=str(RUN/'runtime'),XDG_DATA_HOME=str(Path(a.data).resolve()),XDG_CACHE_HOME=str(RUN/'cache'),XDG_CONFIG_HOME=str(RUN/'config'),PROTONPATH=str(Path(a.proton).resolve()),UMU_RUNTIME_UPDATE='0',UMU_LOG='1',PROTONFIXES_DISABLE='1',PYTHONDONTWRITEBYTECODE='1',WINEDEBUG='-all',WINEDLLOVERRIDES='mscoree,mshtml=',DISPLAY='',WAYLAND_DISPLAY='',STEAM_COMPAT_CLIENT_INSTALL_PATH=str(RUN/'steam'),FLOWGATE_TEST_PORT=str(port))
# The extra preflight models a launcher's own network request; the rest of the
# launch uses the installed Python UMU entrypoint and copied unmodified runtime.
wrapper=RUN/'python-preflight.py'
wrapper.write_text('import os,socket,sys\ns=socket.create_connection(("127.0.0.1",int(os.environ["FLOWGATE_TEST_PREFLIGHT_PORT"])),20)\ns.sendall(b"SYNTHETIC_PYTHON_PREFLIGHT")\ns.close()\nos.execv(sys.argv[1],sys.argv[1:])\n')
def launch(name,prefix,token,preflight):
    env=dict(base,WINEPREFIX=str(prefix),GAMEID='umu-0',FLOWGATE_TEST_TOKEN=token,FLOWGATE_TEST_TRACE='Z:'+str(RUN/(token+'.trace')).replace('/','\\'))
    log=RUN/(token+'.log')
    lwp=[str(Path(a.lwp).resolve()),str(RUN/'games with spaces'/name),'%command%',str(prefix)]
    shell_launch=['/bin/bash','-c',shlex.join(lwp)]
    cmd=[sys.executable,str(wrapper)]+shell_launch if preflight else shell_launch
    cmd=['/usr/bin/setpriv','--inh-caps=-all','--ambient-caps=-all','--']+cmd
    f=log.open('w');c=subprocess.Popen(cmd,env=env,stdout=f,stderr=f);children.append(c);f.close()
    return c,log
try:
    log=(RUN/'daemon.log').open('w')
    observer_args=[]
    if a.verify:
        (RUN/'observer').mkdir(mode=0o700)
        observer_args=['--policy-store',str(RUN/'rules.db'),'--discover-wine','--observer-scratch',str(RUN/'observer'),'--wine-helper',a.helper]
    daemon=subprocess.Popen([BIN,'serve-lab','--rules',localhost_ask_rules('outgoing'),'--parent-netns',os.environ['FLOWGATE_PARENT_NETNS'],'--direction','outgoing','--socket',API,'--timeout','30s','--decision-log',str(RUN/'decisions.db')]+observer_args,stdout=log,stderr=log);children.append(daemon);log.close()
    wait(lambda:Path(API).exists())
    python_key=None
    for index,(name,prefix) in enumerate([('SyntheticAlpha.exe',prefixes[0]),('SyntheticBeta.exe',prefixes[0]),('SyntheticAlpha.exe',prefixes[1])]):
        token='PE_ENFORCED_'+str(index)
        before={e['id'] for e in records()}
        child,log=launch(name,prefix,token,True)
        if index==0:
            e=wait(lambda:next((e for e in call().get('events',[]) if e['state']=='awaiting-decision'),None))
            assert e['attribution']['application']['kind']=='native',e
            python_key=e['attribution']['application']['key'];save('python-prompt.json',e)
            ack=call('decide',id=e['id'],action='allow',scope='application');assert ack.get('decision',{}).get('state')=='allowed',ack
            save('python-decision.json',ack)
        wait(lambda:received.count('SYNTHETIC_PYTHON_PREFLIGHT')==index+1)
        def ready():
            if child.poll() is not None:raise AssertionError('real launcher exited: '+str(log))
            trace=RUN/(token+'.trace')
            return trace.exists() and 'SYNTHETIC_CLIENT_READY' in trace.read_text()
        wait(ready,70)
        pid=wait(lambda:find_pe(name,prefix))
        process=cli('process',pid);save(token+'-process.json',process)
        if a.verify:
            e=wait(lambda:next((e for e in call().get('events',[]) if e['state']=='awaiting-decision' and e.get('attribution',{}).get('application',{}).get('kind')=='wine'),None),15)
            if a.burst:
                pending=wait(lambda: (lambda es:es if len(es)==3 else None)([x for x in call().get('events',[]) if x['state']=='awaiting-decision' and x.get('attribution',{}).get('application',{}).get('key')==process['application']['key']]),5)
                assert len({x['request_group'] for x in pending})==1
                save(token+'-pending-group.json',pending)
            save(token+'-prompt.json',e)
            def live_row():
                state=call()
                return next((r for r in state.get('activity',{}).get('rows',[]) if r.get('runtime_application',{}).get('application',{}).get('key')==process['application']['key']),None)
            # Runtime association is separate from the original Unix FD holder.
            row=None
            if a.protocol=='tcp':
                row=wait(live_row,5); save(token+'-activity.json',row)
                assert row['runtime_application']['evidence']['socket_cookie']==row['socket']['cookie']

            assert e['attribution']['application']['key']==process['application']['key'],e
            if a.burst and index == 0:
                # Exercise the default popup action, not just remembered decisions.
                once = call('decide', id=e['id'], action='allow', scope='once')
                assert once.get('decision', {}).get('state') == 'allowed', once
                wait(lambda: received.count(token) == 1, 10)
                remaining = [x for x in call().get('events', []) if x['state'] == 'awaiting-decision' and x.get('attribution', {}).get('application', {}).get('key') == process['application']['key']]
                assert len(remaining) == 2, remaining
                assert {x['request_group'] for x in remaining} == {e['request_group']}
                save('once-burst-prompt-result.json', dict(decision=once, received=1, remaining=remaining))
                print('ONCE BURST: one payload received; two same-group requests still awaiting', flush=True)
                e = remaining[0]
            action='block' if index==1 else 'allow'
            ack=call('decide',id=e['id'],action=action,scope='application')
            save(token+'-decision.json',ack)
            assert ack.get('decision',{}).get('state')==('blocked' if action=='block' else 'allowed'),ack
            if action=='allow':wait(lambda:received.count(token)==(3 if a.burst else 1),15)
            else:
                time.sleep(3);assert token not in received
            policy_view=call('policy-view',generation=call()['generation']).get('policy_view',{})
            if a.protocol=='tcp':
                # Activity enrichment and its policy projection are asynchronous.
                # Wait for the same assertion, without weakening receiver checks.
                def projected_policy():
                    view=call('policy-view',generation=call()['generation']).get('policy_view',{})
                    return view if any(p['identity']['key']==process['application']['key'] and p['outgoing']['active_rules'] for p in view.get('applications',[])) else None
                policy_view=wait(projected_policy,10)
            else:
                assert any(r['filter']['application']==process['application']['key'] and r['filter']['direction']=='outgoing' and r['action']==action for r in call().get('rules',[])), 'UDP decision did not save the exact application rule'
            save(token+'-policy.json',policy_view)
            save(token+'-state.json',call())
            if index==2 and a.protocol=='tcp':
                draft=dict(direction='outgoing',protocol='*',action='allow',remote_address='*',local_port=0,remote_port=0,expires='0001-01-01T00:00:00Z',disabled=False,application_policy=True)
                target=dict(row_id=row['id'],process_id=row['owners'][0])
                def preview_when_enriched():
                    preview=call('observed-rule-preview',generation=call()['generation'],observed_target=target,observed_draft=draft)
                    # Nonblocking Activity enrichment can omit the runtime
                    # association while another census owns the session.
                    if preview.get('error_code')=='unsupported_target':return None
                    assert not preview.get('error'),preview
                    return preview
                preview=wait(preview_when_enriched,10)
                rule_preview=preview['observed_preview']
                assert rule_preview['rule']['filter']['application']==process['application']['key']
                saved=call('observed-rule-save',generation=call()['generation'],preview_token=rule_preview['token'],observed_draft=draft)
                assert not saved.get('error'),saved
                save('runtime-activity-rule-save.json',saved)
            print('RECEIVER DECISION',action,name,prefix,flush=True)
            evidence.append(dict(name=name,prefix=str(prefix),process=process,decision=e))
            stop_prefix(prefix);child.wait(timeout=10)
            continue
        dropped=wait(lambda:next((e for e in records() if e['id'] not in before and e.get('flow',{}).get('remote','').endswith(':'+str(port)) and e.get('verdict',{}).get('state')=='drop_submitted'),None),15)
        raw=cli('attribute','--protocol',a.protocol,'--direction','outgoing','--local',dropped['flow']['local'],'--remote',dropped['flow']['remote'])
        timeline=[raw]
        for delay in [.1,.3]:
            time.sleep(delay)
            timeline.append(cli('attribute','--protocol',a.protocol,'--direction','outgoing','--local',dropped['flow']['local'],'--remote',dropped['flow']['remote']))
        assert token not in received
        assert raw['visibility_complete'] and len(raw['owners'])==1,raw
        assert Path(raw['owners'][0]['executable']).name=='wineserver',raw
        assert not raw.get('application'),raw
        assert process['netns']==os.readlink('/proc/self/ns/net')
        assert process['mountns']!=os.readlink('/proc/self/ns/mnt')
        assert process.get('provenance',{}).get('evidence')=='verified',process
        assert {'umu-run','pressure-vessel'} <= set(process['provenance']['launch']['markers'])
        assert process['application']['kind']=='wine' and process['application']['key']!=python_key
        evidence.append(dict(name=name,prefix=str(prefix),process=process,decision=dropped,attribution=raw,holder_timeline=timeline,client_context=proc_context(pid),broker_context=proc_context(raw['owners'][0]['pid']),daemon_context=proc_context(daemon.pid)))
        save(token+'-evidence.json',evidence[-1])
        print('REPRODUCED',name,str(prefix),dropped['attribution']['status'],dropped['attribution']['reason'],flush=True)
        stop_prefix(prefix)
        child.wait(timeout=10)
    assert len({e['process']['application']['key'] for e in evidence})==3
    rules=call().get('rules',[])
    assert len(rules)==2+((5 if a.protocol=='tcp' else 4) if a.verify else 1),rules
    save('private-rules.json',rules)
    if a.verify:
        for index,(name,prefix) in enumerate([('SyntheticAlpha.exe',prefixes[0]),('SyntheticBeta.exe',prefixes[0]),('SyntheticAlpha.exe',prefixes[1])]):
            token='PE_REMEMBERED_'+str(index); before={d['id'] for d in records()}
            child,log=launch(name,prefix,token,False)
            if index!=1:wait(lambda:token in received,70)
            else:
                wait(lambda:any(d['id'] not in before and d.get('verdict',{}).get('state')=='drop_submitted' for d in records()),70)
                assert token not in received
            decisions=[d for d in records() if d['id'] not in before]
            save(token+'-decisions.json',decisions)
            assert not any(e['state']=='awaiting-decision' for e in call().get('events',[]))
            print('REMEMBERED RECEIVER',name,index!=1,prefix,flush=True)
            stop_prefix(prefix);child.wait(timeout=10)

    if a.verify:
        for rule in call().get('rules',[]):
            reply=call('rule-delete',generation=call()['generation'],id=rule['id'],expected_version=rule['version'])
            assert not reply.get('error'),reply
        assert not call().get('rules')
        with sqlite3.connect('file:'+str(RUN/'rules.db')+'?mode=ro',uri=True) as db:
            assert db.execute('select count(*) from rules').fetchone()[0]==0
    daemon.terminate();daemon.wait(timeout=10)
    assert subprocess.run(['nft','list','table','inet','flowgate_lab'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode!=0
    # Prove the same Windows clients and launch path actually send data with
    # the isolated interceptor removed; receiver delivery is the assertion.
    for index,name in enumerate(['SyntheticAlpha.exe','SyntheticBeta.exe']):
        token='PE_CONTROL_'+str(index);child,log=launch(name,prefixes[index],token,False)
        wait(lambda:token in received,70)
        print('CONTROL RECEIVED',token,flush=True)
        stop_prefix(prefixes[index])
        child.wait(timeout=10)
    result=dict(protocol=a.protocol,reproduced=not a.verify,verified=a.verify,source=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),lwp=str(Path(a.lwp).resolve()),lwp_sha256=digest(a.lwp),proton_sha256=digest(Path(a.proton)/'proton'),broker_sha256=digest(Path(a.proton)/'files/bin/wineserver'),client_sha256=digest(a.pe),python_rule_does_not_target_pe=True,received=received,observations=evidence,host_changed=False)
    save('result.json',result)
finally:
    try: save('decision-log.json',records())
    except (OSError,sqlite3.Error): pass
    try: save('last-state.json',call())
    except (OSError,ValueError): pass
    try: save('last-sockets.json',cli('sockets'))
    except (OSError,ValueError,RuntimeError): pass
    if sys.exc_info()[0] is not None and 'daemon' in globals() and daemon.poll() is None:
        daemon.send_signal(signal.SIGQUIT)
        try: daemon.wait(timeout=3)
        except subprocess.TimeoutExpired: pass
    for c in reversed(children):
        if c.poll() is None:c.terminate()
    for c in reversed(children):
        try:c.wait(timeout=5)
        except subprocess.TimeoutExpired:c.kill();c.wait()
    server.close()
    if udp_server:udp_server.close()
    print('CLEANED direct children; private PID/network namespace owns remaining runtime descendants',flush=True)

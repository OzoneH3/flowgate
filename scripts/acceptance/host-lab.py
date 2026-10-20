#!/usr/bin/env python3
"""Actual host-start path in disposable user/net namespaces; no host enforcement.
Run through scripts/lab.sh. --suite runs receiver assertions; otherwise serves
private UI test commands. All subprocesses/files belong to this test instance.
"""
import json, os, signal, socket, struct, subprocess, sys, threading, time, sqlite3
from datetime import datetime, timezone, timedelta
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
RUN=Path(sys.argv[1]).resolve()
assert RUN.is_relative_to(ROOT/'.workspace')
assert os.environ['FLOWGATE_PARENT_NETNS']!=os.readlink('/proc/self/ns/net')
RUN.mkdir(mode=0o700,parents=True,exist_ok=True)
STATE=RUN/'state';STATE.mkdir(mode=0o700,exist_ok=True)
WORKFLOW="--desktop-workflow" in sys.argv
API=RUN/'api/control.sock' if WORKFLOW else RUN/'control.sock'
PROFILE="both" if "--both" in sys.argv else "incoming"
clients=[]
observer=None
active_job=None
job_sequence=0
BIN=os.environ.get('FLOWGATE_TEST_BINARY',str(ROOT/'.workspace/flowgate'))
counts={};backend=None;stopping=False
signal.signal(signal.SIGTERM,lambda *_:globals().update(stopping=True))
signal.signal(signal.SIGINT,lambda *_:globals().update(stopping=True))
def cmd(*a):return subprocess.check_output(a,stderr=subprocess.STDOUT,text=True)
def wait(f,seconds=8):
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        v=f()
        if v:return v
        time.sleep(.05)
    raise AssertionError('wait timeout')
def api(op='list',**fields):
    with socket.socket(socket.AF_UNIX) as s:
        s.settimeout(4);s.connect(str(API));s.sendall((json.dumps(dict(version=1,operation=op,**fields))+'\n').encode());data=b''
        while b'\n' not in data:data+=s.recv(65536)
        return json.loads(data)
def receive(s,port,tcp):
    while not stopping:
        try:
            if tcp:
                c,_=s.accept()
                def read(c):
                    with c:
                        while not stopping:
                            try:b=c.recv(1024)
                            except OSError:break
                            if not b:break
                            counts[port]=counts.get(port,0)+1
                            with (RUN/f'receiver-{port}.log').open('a') as f:f.write('RECEIVED\n')
                threading.Thread(target=read,args=(c,),daemon=True).start()
            else:
                data,peer=s.recvfrom(1024);s.sendto(b'reply',peer);counts[port]=counts.get(port,0)+1
                with (RUN/f'receiver-{port}.log').open('a') as f:f.write('RECEIVED\n')
        except OSError:break
peer=subprocess.Popen(['unshare','--net','python3',str(ROOT/'scripts/acceptance/host-peer.py'),str(RUN)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
def remote(op,**kw):
    peer.stdin.write(json.dumps(dict(op=op,**kw))+'\n');peer.stdin.flush();r=json.loads(peer.stdout.readline());assert 'error' not in r,r;return r

def start(duration='120s'):
    global backend
    with (RUN/'backend.log').open('a') as f:
        args=[BIN,'host-start','--state',str(STATE),'--socket',str(API),'--uid','0','--duration',duration,'--timeout','8s']
        if WORKFLOW:args=[BIN,'host-session','--action','start','--state',str(STATE),'--database',str(RUN/'data/rules.db'),'--socket',str(API),'--uid','0','--duration',duration,'--timeout','8s']
        args += ["--profile",PROFILE]
        backend=subprocess.Popen(args,stdout=f,stderr=f)
    def ready():
        if backend.poll() is not None:raise RuntimeError((RUN/'backend.log').read_text())
        try:return api().get('enforcement',{}).get('state')=='active'
        except (OSError,ValueError):return False
    wait(ready)
def stop_backend():
    if backend and backend.poll() is None:
        cmd(BIN,'host-stop','--state',str(STATE));backend.wait(6)
def pending(port):
    return next((x for x in api().get('events',[]) if x['state']=='awaiting-decision' and x['flow']['local'].endswith(':'+str(port))),None)
def decide(port,action,scope='once'):
    e=wait(lambda:pending(port));r=api('decide',id=e['id'],action=action,scope=scope);assert 'error' not in r,r;return r
try:
    wait(lambda:os.readlink(f'/proc/{peer.pid}/ns/net')!=os.readlink('/proc/self/ns/net'))
    cmd('ip','link','add','fghost','type','veth','peer','name','fgpeer')
    cmd('ip','link','set','fgpeer','netns',str(peer.pid));cmd('ip','link','set','fghost','up')
    cmd('ip','addr','add','10.79.0.1/24','dev','fghost');cmd('ip','-6','addr','add','fd79::1/64','dev','fghost','nodad');remote('setup')
    cmd('nft','add','table','inet','unrelated_fixture')
    # Enable conntrack before the preexisting exchange, as a real host usually
    # already does. Without hooks there are no prior conntrack entries to dump.
    cmd('nft','add','chain','inet','unrelated_fixture','track','{ type filter hook input priority 0; policy accept; }')
    cmd('nft','add','rule','inet','unrelated_fixture','track','ct','state','established','counter')
    for v6,base in [(False,44000),(True,44100)]:
        for n in range(8):
            port=base+n;tcp=n%2==0;s=socket.socket(socket.AF_INET6 if v6 else socket.AF_INET,socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('fd79::1' if v6 else '10.79.0.1',port))
            if tcp:s.listen()
            counts[port]=0;(RUN/f'receiver-{port}.log').touch();threading.Thread(target=receive,args=(s,port,tcp),daemon=True).start()
    for v6,port in [(False,68),(True,546)]:
        s=socket.socket(socket.AF_INET6 if v6 else socket.AF_INET,socket.SOCK_DGRAM);s.bind(('fd79::1' if v6 else '10.79.0.1',port));counts[port]=0;threading.Thread(target=receive,args=(s,port,False),daemon=True).start()
    remote('tcp',port=44000);wait(lambda:counts[44000]==1)
    remote('tcp',port=44100,v6=True);wait(lambda:counts[44100]==1)
    preexisting=[]
    if '--outgoing-suite' in sys.argv:
        for proto in ['tcp4','tcp6']:
            log=RUN/('preserved-'+proto+'.log')
            with log.open('w') as f:p=subprocess.Popen([str(ROOT/'.workspace/clients/alpha'),proto,'fd79::2' if '6'in proto else '10.79.0.2','43000','fd79::1' if '6'in proto else '10.79.0.1'],stdin=subprocess.PIPE,stdout=f,stderr=f,env=dict(os.environ,FLOWGATE_CLIENT_REPEAT='1'))
            clients.append(p);preexisting.append((p,log));wait(lambda:'REPLY' in log.read_text())
    if not WORKFLOW:start()
    else:
        with (RUN/'observer.log').open('a') as f:observer=subprocess.Popen([BIN,'observe','--socket',str(RUN/'observer.sock'),'--interval','500ms'],stdout=f,stderr=f)
        wait(lambda:(RUN/'observer.sock').exists())
    if '--bootstrap-only'  in sys.argv:
        for v6,port in [(False,44000),(True,44100)]:remote('again',port=port,v6=v6);wait(lambda:counts[port]==2)
        for v6,port in [(False,68),(True,546)]:remote('udp',port=port,v6=v6,dhcp=True);wait(lambda:counts[port]==1);assert not pending(port)
        print('PASS pre-existing TCP IPv4/IPv6 and DHCP client-port bootstrap datagrams',flush=True)
        stop_backend();sys.exit(0)
    if '--observed-creation-suite' in sys.argv:
        from observed_rule_cases import exercise
        exercise(globals())
    elif '--delete-suite' in sys.argv:
        from delete_cases import exercise
        exercise(globals())
    elif '--outgoing-suite' in sys.argv:
        from outgoing_cases import exercise
        exercise(globals())
    elif '--suite' in sys.argv:
        remote('again',port=44000);wait(lambda:counts[44000]==2);print('PASS pre-existing incoming TCP survives activation',flush=True)
        for v6,base in [(False,44000),(True,44100)]:
            for n,act in [(2,'allow'),(4,'block'),(1,'allow'),(3,'block')]:
                p=base+n;remote('tcp' if n%2==0 else 'udp',port=p,v6=v6);e=wait(lambda:pending(p));assert counts[p]==0;decide(p,act)
                if act=='allow':wait(lambda:counts[p]==1)
                else:time.sleep(.25);assert counts[p]==0
                print('PASS',('IPv6' if v6 else 'IPv4'),('TCP' if n%2==0 else 'one-shot UDP'),act,flush=True)
            s=socket.socket(socket.AF_INET6 if v6 else socket.AF_INET,socket.SOCK_STREAM);s.settimeout(3);s.connect(('fd79::2' if v6 else '10.79.0.2',43000));s.sendall(b'outbound');assert s.recv(8)==b'outbound';s.close();print('PASS outgoing TCP reply not prompted',v6,flush=True)
            u=socket.socket(socket.AF_INET6 if v6 else socket.AF_INET,socket.SOCK_DGRAM);u.settimeout(3);u.sendto(b'udp reply',('fd79::2' if v6 else '10.79.0.2',43001));assert u.recv(128)==b'udp reply';u.close();remote('ping',v6=v6);print('PASS outbound UDP reply and ICMP/ICMPv6',v6,flush=True)
        remote('udp',port=44005);decide(44005,'allow','persistent');wait(lambda:counts[44005]==1)
        # A second start must leave the active generation and unrelated objects intact.
        duplicate=subprocess.run([BIN,'host-start','--state',str(STATE),'--socket',str(RUN/'duplicate.sock'),'--uid','0','--duration','10s'],capture_output=True);assert duplicate.returncode!=0
        print('PASS duplicate startup rejected',flush=True)
        rule=next(r for r in api()['rules'] if r['filter'].get('local_port')==44005)
        stop_backend();assert 'unrelated_fixture' in cmd('nft','list','tables');start()
        remote('udp',port=44005);wait(lambda:counts[44005]==2);assert not pending(44005);print('PASS persisted rule survives restart; unrelated firewall preserved',flush=True)
        assert 'error' not in api('rule',id=rule['id'],action='disable');remote('udp',port=44005);e=wait(lambda:pending(44005));assert counts[44005]==2
        time.sleep(4.2);r=api('decide',id=e['id'],action='allow',scope='once');assert 'error' in r;assert counts[44005]==2
        assert 'error' not in api('rule',id=rule['id'],action='delete');assert not api().get('rules');print('PASS disable/delete and expired approval rejection',flush=True)
        remote('udp',port=44007);decide(44007,'allow','application');wait(lambda:counts[44007]==1)
        stop_backend()
        # Fixture clock: shorten the stored absolute expiry, never the product's 1h scope.
        db=sqlite3.connect(STATE/'rules.db');rid,doc=db.execute('SELECT id,document FROM rules').fetchone();doc=json.loads(doc);expiry=(datetime.now(timezone.utc)+timedelta(seconds=2)).isoformat();doc['expires']=expiry;db.execute('UPDATE rules SET document=? WHERE id=?',(json.dumps(doc),rid));db.commit();db.close()
        start();loaded=api()['rules'][0];assert loaded['expires'].replace('Z','+00:00')==expiry
        time.sleep(2.1);remote('udp',port=44007);wait(lambda:pending(44007));assert counts[44007]==1;decide(44007,'block');print('PASS absolute stored expiry survives restart at receiver',flush=True)
        # Structural health differs from a live API: modifying our chain is degraded.
        cmd('nft','add','rule','inet','flowgate_host','input','counter');assert api()['enforcement']['state']=='degraded';stop_backend();start();print('PASS rule-health degradation detected independently of API connection',flush=True)
        for _ in range(30):remote('udp',port=44999)
        assert len(api().get('events',[]))<=256;assert not pending(44999);print('PASS no-listener bounded without prompt',flush=True)
        backend.kill();backend.wait();remote('udp',port=44007);time.sleep(.3);assert counts[44007]==1
        cmd(BIN,'host-recover','--state',str(STATE));cmd(BIN,'host-recover','--state',str(STATE));assert 'unrelated_fixture' in cmd('nft','list','tables');print('PASS queue consumer death fail-closed; repeated recovery preserves unrelated table',flush=True)
        for p in [API,Path(str(API)+'.monitor')]:p.unlink(missing_ok=True) # this harness's killed process only
        start('10s');wait(lambda:backend.poll() is not None,15);assert 'flowgate_host' not in cmd('nft','list','tables');print('PASS bounded automatic stop',flush=True)
        start('10s');backend.kill();backend.wait();wait(lambda:'flowgate_host' not in cmd('nft','list','tables'),15);print('PASS independent deadline recovery after daemon SIGKILL',flush=True)
        # Refuse occupied marks/foreign-owned objects and corrupt storage without touching them.
        cmd('nft','add','rule','inet','unrelated_fixture','track','ct','mark','set','0x1')
        failed=subprocess.run([BIN,'host-start','--state',str(STATE),'--socket',str(API),'--uid','0','--duration','10s'],capture_output=True);assert failed.returncode!=0;assert 'unrelated_fixture' in cmd('nft','list','tables');assert 'flowgate_host' not in cmd('nft','list','tables');print('PASS conflicting-mark startup refuses without unrelated mutations',flush=True)
    else:
        ctl=socket.socket(socket.AF_UNIX);ctl.bind(str(RUN/'demo.sock'));os.chmod(RUN/'demo.sock',0o600);ctl.listen(4);ctl.settimeout(.2);(RUN/'ready').write_text('isolated host-mode veth profile\n')
        def publish(job,phase,message='',token=''):
            global job_sequence
            job=Path(job);assert job.is_relative_to(ROOT/'.workspace') and job.is_dir();job_sequence+=1
            result={'version':1,'sequence':job_sequence,'phase':phase,'message':message,'generation':token}
            (job/'result.new').write_text(json.dumps(result));(job/'result.new').replace(job/'result.json')
        while not stopping:
            if active_job and backend and backend.poll() is not None:
                info=json.loads(cmd(BIN,'host-status','--state',str(STATE)))
                publish(active_job,'stopped' if info['state']=='stopped' and not info['table_present'] else 'unknown','Isolated controller exited; no automatic restart.',info['record']['Token']);active_job=None
            try:c,_=ctl.accept()
            except socket.timeout:continue
            with c:
                c.settimeout(1);pid,uid,gid=struct.unpack('3i',c.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                if uid!=os.getuid():continue
                q=json.loads(c.recv(1024));op=q['operation'];r={}
                if op=='send':remote('udp',port=q.get('port',44001),source_port=q.get('source_port',0));r={'sent_once':True}
                elif op=='stopbackend':stop_backend();r={'ok':True}
                elif op=='start':
                    job=q['job']
                    PROFILE=json.loads((Path(job)/'request.json').read_text()).get('profile','incoming') if (Path(job)/'request.json').exists() else 'incoming'
                    try:start('30s');active_job=job;publish(job,'ready','Namespace controller ready',api()['generation']);r={'ok':True}
                    except Exception as e:publish(job,'failed',str(e));r={'ok':False}
                elif op=='outgoing':
                    proto=q.get('protocol','udp4');assert proto in ['udp4','udp6','tcp4','tcp6']
                    app=q.get('app','alpha');assert app in ['alpha','beta']
                    log=RUN/'client.log';f=log.open('a');p=subprocess.Popen([str(ROOT/'.workspace/clients'/app),proto,'fd79::2' if '6' in proto else '10.79.0.2','43000' if proto.startswith('tcp') else '43001','fd79::1' if '6'in proto else '10.79.0.1'],stdout=f,stderr=f);f.close();clients.append(p);r={'ok':True}
                elif op=='stop':
                    try:cmd(BIN,'host-stop','--state',str(STATE),'--token',q['token']);backend.wait(6);publish(q['job'],'stopped','Scoped stop confirmed',q['token']);r={'ok':True}
                    except Exception as e:publish(q['job'],'failed',str(e));r={'ok':False}
                elif op=='cancel':publish(q['job'],'cancelled','Simulated authentication cancellation');r={'ok':True}
                elif op=='refuse':
                    cmd('nft','add','rule','inet','unrelated_fixture','track','ct','mark','set','0x1')
                    data=json.loads(cmd('nft','-j','-a','list','chain','inet','unrelated_fixture','track'));handle=[x['rule']['handle'] for x in data['nftables'] if 'rule'in x][-1]
                    try:start('20s');raise AssertionError('expected preflight refusal')
                    except RuntimeError as e:publish(q['job'],'failed',str(e));r={'ok':True}
                    finally:cmd('nft','delete','rule','inet','unrelated_fixture','track','handle',str(handle))
                elif op=='status':
                    try:r=json.loads(cmd(BIN,'host-status','--state',str(STATE)))
                    except Exception:r={'state':'unavailable'}
                    r['tables']=cmd('nft','list','tables')
                elif op=='kill':backend.kill();backend.wait();r={'ok':True}
                elif op=='recover':cmd(BIN,'host-recover','--state',str(STATE));publish(q['job'],'stopped','Scoped recovery confirmed',q.get('token',''));r={'ok':True}
                elif op=='quit':stopping=True;r={'ok':True}
                c.sendall(json.dumps(r).encode())
finally:
    stopping=True
    try:stop_backend()
    except Exception:pass
    for p in clients:
        if p.poll() is None:p.terminate();p.wait(3)
    if observer:observer.terminate();observer.wait(4)
    peer.terminate()
    try:peer.wait(3)
    except subprocess.TimeoutExpired:peer.kill();peer.wait()

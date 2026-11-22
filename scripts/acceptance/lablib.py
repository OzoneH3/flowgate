#!/usr/bin/env python3
"""Receiver-observed tests; must run via lab.sh in an isolated network/PID namespace."""
import hashlib, json, os, socket, subprocess, sys, time, pathlib, signal
ROOT=pathlib.Path.cwd(); RUN=ROOT/'.workspace/run'
SELECTED_BINARY = os.environ.get('FLOWGATE_TEST_BINARY')
BIN = str(pathlib.Path(SELECTED_BINARY).resolve()) if SELECTED_BINARY else str(ROOT/'.workspace/flowgate')
SOCK=str(RUN/'control.sock')
def start_receiver_daemon(fixture, *args, **kwargs):
    """Launch the explicitly selected daemon and attest the running image."""
    if not SELECTED_BINARY:
        raise RuntimeError('Set FLOWGATE_TEST_BINARY or use scripts/check.sh --receivers')
    process = subprocess.Popen([BIN, *args], **kwargs)
    try:
        executable = pathlib.Path(f'/proc/{process.pid}/exe')
        if executable.resolve(strict=True) != pathlib.Path(BIN):
            raise RuntimeError(f'{fixture} started a different executable: {executable.readlink()}')
        with executable.open('rb') as image:
            digest = hashlib.file_digest(image, 'sha256').hexdigest()
        result = dict(fixture=fixture, binary=dict(path=BIN, sha256=digest))
        (RUN / f'{fixture}-binary.json').write_text(json.dumps(result, indent=2) + '\n')
        print('DAEMON', json.dumps(result), flush=True)
    except BaseException:
        process.kill()
        process.wait()
        raise
    return process

def cli(*args):
    p=subprocess.run([BIN,*args],capture_output=True,text=True)
    if p.returncode: raise RuntimeError(p.stderr+p.stdout)
    return json.loads(p.stdout)
def wait(fn,timeout=5):
    until=time.monotonic()+timeout
    while time.monotonic()<until:
        v=fn()
        if v:return v
        time.sleep(.04)
    raise AssertionError('timed out')
def events():return cli('pending','--socket',SOCK).get('events',[])
def pending(port):return next((v for v in events() if v['flow']['local'].endswith(':'+str(port)) and v['state']=='awaiting-decision'),None)
def decide(v,action,scope='once'):return cli('decide','--socket',SOCK,'--id',v['id'],'--action',action,'--scope',scope)
def delivered(path):return path.exists() and 'RECEIVED' in path.read_text()
servercode='''import socket,sys
s=socket.socket(int(sys.argv[1]),int(sys.argv[2]));s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind((sys.argv[3],int(sys.argv[4])))
if int(sys.argv[2])==1:s.listen()
print("READY",flush=True)
while True:
 if int(sys.argv[2])==1:
  c,a=s.accept();b=c.recv(1024);c.close()
 else:b,a=s.recvfrom(1024)
 if b:print("RECEIVED",flush=True)
'''
children=[]
def server(port,udp=False,v6=False,address=None):
    path=RUN/f'receiver-{port}.log';f=path.open('w');p=subprocess.Popen([sys.executable,'-c',servercode,'10' if v6 else '2','2' if udp else '1',address or ('::1' if v6 else '127.0.0.1'),str(port)],stdout=f,stderr=f);children.append(p);wait(lambda:path.exists() and 'READY' in path.read_text());return p,path
def client(port,udp=False,v6=False):
    code='import socket,sys;s=socket.socket(int(sys.argv[1]),int(sys.argv[2]));s.settimeout(4);s.connect((sys.argv[3],int(sys.argv[4])));s.send(b"test")'
    p=subprocess.Popen([sys.executable,'-c',code,'10' if v6 else '2','2' if udp else '1','::1' if v6 else '127.0.0.1',str(port)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);children.append(p);return p

def localhost_ask_rules(direction):
    """Explicitly opt prompt/identity fixtures into localhost filtering."""
    RUN.mkdir(parents=True,exist_ok=True)
    path=RUN/f'localhost-ask-{direction}.json'
    path.write_text(json.dumps([{'schema':4,'id':f'localhost-fixture-{i}','version':1,'created':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),
        'action':'ask','filter':{'all_programs':True,'all_uids':True,'uid':0,
        'network_zone':'local','direction':direction,'protocol':'*','remote_address':address}}
        for i,address in enumerate(('127.0.0.0/8','::1/128'))]))
    return str(path)

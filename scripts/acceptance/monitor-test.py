#!/usr/bin/env python3
"""Focused host observation checks. Ordinary loopback fixtures; no firewall calls."""
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time

ROOT=Path(__file__).resolve().parents[2]
run=Path(tempfile.mkdtemp(prefix='monitor-test-',dir=ROOT/'.workspace'))
children=[]

def api(operation='list',**kwargs):
    with socket.socket(socket.AF_UNIX) as c:
        c.settimeout(4);c.connect(str(run/'control.sock'))
        c.sendall(json.dumps(dict(version=1,operation=operation,**kwargs)).encode()+b'\n')
        data=b''
        while b'\n' not in data:
            chunk=c.recv(65536)
            if not chunk:raise RuntimeError('short API response')
            data+=chunk
            if len(data)>4*1024*1024:raise RuntimeError('response overflow')
        return json.loads(data)

def wait(fn,timeout=12):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        value=fn()
        if value:return value
        time.sleep(.1)
    raise AssertionError('timed out')

def fixture(path,*args):
    p=subprocess.Popen([str(path),*map(str,args)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
    children.append(p)
    while True:
        line=p.stdout.readline()
        if line.startswith('{'):return p,json.loads(line)
        if not line:raise RuntimeError('fixture exited')

try:
    a,info=fixture(ROOT/'.workspace/monitor-fixtures/a/fixture','shared',ROOT/'.workspace/monitor-fixtures/b/fixture')
    b,other=fixture(ROOT/'.workspace/monitor-fixtures/b/fixture')
    with (run/'observer.log').open('w') as log:
        observer=subprocess.Popen([str(ROOT/'.workspace/flowgate'),'observe','--socket',str(run/'control.sock'),'--interval','500ms'],stdout=log,stderr=log)
    children.append(observer)
    wait(lambda:(run/'control.sock').exists())
    def visible():
        r=api();s=r.get('activity',{});rows=s.get('rows',[])
        owners=s.get('processes',{})
        return s if not s.get('error') and any(p['pid']==info['child'] for p in owners.values()) and any(p['pid']==b.pid for p in owners.values()) else None
    s=wait(visible)
    assert api()['read_only'] and api()['mode']=='host-monitor'
    assert 'read-only' in api('decide',id='anything',action='allow',scope='application')['error']
    assert not api().get('events'), 'observation fabricated policy events'
    def rows(port):return [r for r in s['rows'] if r['socket']['local'].endswith(':'+str(port))]
    listener=next(r for r in rows(info['tcp']) if r['state']=='Listening')
    assert len(listener['owners'])==2 and len(set(listener['owners']))==2
    assert {s['processes'][p]['pid'] for p in listener['owners']}=={a.pid,info['child']}
    assert len([r for r in s['rows'] if r['id']==listener['id']])==1
    assert any(r['state']=='Established' for r in rows(info['tcp']))
    assert any(r['state']=='Established' for r in rows(info['tcp_client']))
    assert any(r['state']=='Connecting (SYN sent)' for r in rows(info['connecting']))
    assert any(r['state']=='Listening' and r['socket']['local'].startswith('[::1]') for r in rows(info['tcp6']))
    assert any(r['state']=='Bound/unconnected UDP socket' for r in rows(info['udp']))
    assert any(r['state']=='Bound/unconnected UDP socket' and r['socket']['local'].startswith('[::1]') for r in rows(info['udp6']))
    assert any(r['state']=='Connected UDP socket' for r in rows(info['connected_udp']))
    assert all(r['direction']=='Unknown' for r in s['rows'])
    ap=next(p for p in s['processes'].values() if p['pid']==a.pid)
    bp=next(p for p in s['processes'].values() if p['pid']==b.pid)
    assert ap['application']['name']==bp['application']['name'] and ap['application']['key']!=bp['application']['key']
    assert ap['id']==str(a.pid)+':'+ap['start_ticks']
    print('PASS IPv4/IPv6 listeners, real TCP exchange, bound/connected UDP, path identity, shared owner census counted once, read-only mutation rejection')
    # Keep only controlled fixture evidence; no unrelated host process metadata.
    own={str(a.pid),str(b.pid),str(info['child'])}
    evidence={'processes':{k:v for k,v in s['processes'].items() if str(v['pid']) in own}}
    evidence['rows']=[r for r in s['rows'] if any(p in evidence['processes'] for p in r['owners'])]
    (run/'fixtures.json').write_text(json.dumps(evidence,indent=2))
    pid=b.pid;b.stdin.close();b.wait(timeout=3)
    wait(lambda:all(p['pid']!=pid for p in api()['activity']['processes'].values()))
    print('PASS process exit removed from current activity')
    costs=[];last=-1
    def next_snapshot():
        current=api()['activity']
        return current if current.get('sequence',0)>last else None
    for _ in range(5):
        current=wait(next_snapshot);last=current['sequence'];costs.append(current['duration_ms'])
    # /proc CPU jiffies over an idle sampling window, avoiding external profilers.
    def ticks():return sum(map(int,Path(f'/proc/{observer.pid}/stat').read_text().split()[13:15]))
    before=ticks();start=time.monotonic();time.sleep(3);cpu=(ticks()-before)/os.sysconf('SC_CLK_TCK');elapsed=time.monotonic()-start
    print('MEASURE',json.dumps({'duration_ms':costs,'cpu_seconds':round(cpu,3),'wall_seconds':round(elapsed,3),'interval':'500ms','rows':len(current['rows']),'inaccessible':current['inaccessible_processes'],'complete':current['complete']}))
    print('EVIDENCE',run)
finally:
    for p in reversed(children):
        if p.poll() is None:p.terminate()
    for p in reversed(children):
        try:p.wait(timeout=3)
        except subprocess.TimeoutExpired:p.kill();p.wait()

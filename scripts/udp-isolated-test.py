#!/usr/bin/env python3
"""Run ONLY inside a disposable privileged network namespace. No GUI as root.
Without initial-namespace BPF permissions it reports the exact load failure.
"""
import argparse,json,os,socket,subprocess,time
from pathlib import Path
root=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument('--run',required=True);args=p.parse_args();run=Path(args.run).resolve()
assert run.is_relative_to(root/'.workspace')
assert os.environ['FLOWGATE_PARENT_NETNS']!=os.readlink('/proc/self/ns/net')
run.mkdir(mode=0o755,parents=True,exist_ok=False)
subprocess.run(['ip','link','set','lo','up'],check=True)
uid=os.getuid();children=[]
def wait(f,seconds=8):
 end=time.monotonic()+seconds
 while time.monotonic()<end:
  v=f()
  if v:return v
  time.sleep(.1)
 raise AssertionError('timeout')
def snapshot():
 with socket.socket(socket.AF_UNIX) as s:
  s.settimeout(2);s.connect(str(run/'api.sock'));s.sendall(b'{"version":1,"operation":"list"}\n');data=b''
  while b'\n'not in data:data+=s.recv(65536)
  return json.loads(data)
def fixtures(family):
 p=subprocess.Popen(['python3',str(root/'scripts/udp-fixture.py'),family],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True);children.append(p);return p,json.loads(p.stdout.readline())
def counter(port):
 out=subprocess.check_output([str(root/'.workspace/flowgate'),'sockets'],text=True)
 rows=json.loads(out);s=next(s for s in rows if s['protocol']=='udp'and s['local'].endswith(':'+str(port)))
 return snapshot()['rows'].get(s['cookie'])
try:
 log=(run/'collector.log').open('w')
 c=subprocess.Popen([str(root/'.workspace/udp-test-driver'),str(run/'api.sock'),str(root/'.workspace/udp-collector'),str(uid)],stdout=log,stderr=log);children.append(c)
 def ready():
  if c.poll()is not None:raise RuntimeError((run/'collector.log').read_text())
  return (run/'api.sock').exists()
 wait(ready)
 for family in ['4','6']:
  f,ports=fixtures(family);wait(lambda:counter(ports['a'])is not None)
  f.stdin.write('transfer\n');f.stdin.flush();expected=json.loads(f.stdout.readline())
  wait(lambda:counter(ports['a'])['uploaded']==expected['a_up'])
  assert counter(ports['a'])['downloaded']==expected['a_down']
  assert counter(ports['b'])['uploaded']==1400 and counter(ports['c'])['downloaded']==600
  f.stdin.write('edges\n');f.stdin.flush();expected=json.loads(f.stdout.readline())
  wait(lambda:counter(ports['a'])['downloaded']==expected['a_down'])
  assert counter(ports['a'])['uploaded']==expected['a_up']
  print('PASS receiver-backed UDP'+family+' connected/unconnected, peers, PEEK/truncation/failed-send counters',flush=True)
 print('EVIDENCE',run)
finally:
 for p in children[::-1]:
  if p.poll()is None:p.terminate();p.wait(5)

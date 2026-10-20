#!/usr/bin/env python3
"""Held real TCP handshakes; never host namespaces or host API. No BPF/enforcement.
Run via scripts/lab.sh; --hold delegates the isolated API exclusively to UI until
its owner reports DONE, then the backend owner touches run/quit for cleanup.
"""
import argparse,datetime,errno,json,os,socket,subprocess,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
p=argparse.ArgumentParser();p.add_argument('--binary',required=True);p.add_argument('--run',required=True);p.add_argument('--hold',action='store_true');a=p.parse_args()
assert os.environ['FLOWGATE_PARENT_NETNS']!=os.readlink('/proc/self/ns/net')
run=Path(a.run).resolve();assert run.is_relative_to(ROOT/'.workspace');run.mkdir(mode=0o700)
api_dir=run/'api';data=run/'data';api_dir.mkdir(mode=0o700);data.mkdir(mode=0o700)
endpoint=str(api_dir/'daemon.sock');binary=Path(a.binary).resolve();assert binary!=ROOT/'.workspace/flowgate'
sockets=[];daemon=None;table=False

def cmd(*args):return subprocess.check_output(args,text=True)
def wait(fn,seconds=15):
 end=time.monotonic()+seconds
 while time.monotonic()<end:
  v=fn()
  if v:return v
  time.sleep(.05)
 raise AssertionError('timed out waiting for '+str(fn))
def api(endpoint=endpoint):
 with socket.socket(socket.AF_UNIX)as s:
  s.settimeout(5);s.connect(endpoint);s.sendall(b'{"version":1,"operation":"list"}\n');b=b''
  while b'\n'not in b:
   d=s.recv(65536)
   if not d:raise RuntimeError('API closed')
   b+=d
  v=json.loads(b);assert not v.get('error'),v;return v
def find(v,local,remote=None):
 return next((r for r in v.get('activity',{}).get('rows',[])if r['socket']['protocol']=='tcp'and r['socket']['local']==local and (remote is None or r['socket']['remote']==remote)),None)
def address(s):
 v=s.getsockname();return f'[{v[0]}]:{v[1]}'if s.family==socket.AF_INET6 else f'{v[0]}:{v[1]}'
def sock(family,kind=socket.SOCK_STREAM):
 s=socket.socket(family,kind);s.settimeout(5);sockets.append(s);return s
try:
 before=json.loads(cmd('nft','-j','list','ruleset'))
 # Established before observer starts: no initiation claim may be invented.
 pre=sock(socket.AF_INET);pre.bind(('127.0.0.1',0));pre.listen();pc=sock(socket.AF_INET);pc.connect(pre.getsockname());pa,_=pre.accept();sockets.append(pa)
 listeners=[]
 for family,host in [(socket.AF_INET,'127.0.0.1'),(socket.AF_INET6,'::1')]:
  s=sock(family);s.bind((host,0));s.listen();listeners.append(s)
 udp=sock(socket.AF_INET,socket.SOCK_DGRAM);udp.bind(('127.0.0.1',0));uc=sock(socket.AF_INET,socket.SOCK_DGRAM);uc.connect(udp.getsockname())
 with (run/'daemon.log').open('w')as f:daemon=subprocess.Popen([str(binary),'serve','--socket',endpoint,'--database',str(data/'rules.db'),'--uid','0','--administrator'],stdout=f,stderr=f)
 def ready():
  assert daemon.poll()is None,(run/'daemon.log').read_text()
  try:
   v=api();return v if find(v,address(pc))else None
  except OSError:return None
 initial=wait(ready);assert 'activity-initiation-v1'in initial['capabilities']
 assert find(initial,address(pc))['initiation']['state']=='unknown'
 rules='table inet direction_fixture {\n chain output {\n type filter hook output priority 0; policy accept;\n'+''.join(f' tcp sport {s.getsockname()[1]} tcp flags & (syn | ack) == (syn | ack) drop\n'for s in listeners)+' }\n}\n'
 subprocess.run(['nft','-f','-'],input=rules,text=True,check=True);table=True
 clients=[]
 for listener in listeners:
  c=sock(listener.family);c.setblocking(False);assert c.connect_ex(listener.getsockname())in [errno.EINPROGRESS,errno.EWOULDBLOCK];clients.append(c)
 def held():
  v=api();rows=[]
  for listener,client in zip(listeners,clients):
   outgoing=find(v,address(client),address(listener));incoming=find(v,address(listener),address(client))
   if not outgoing or not incoming:return None
   if outgoing['initiation'].get('direction')!='outgoing'or incoming['initiation'].get('direction')!='incoming':return None
   rows.extend([outgoing,incoming])
  return rows
 held=wait(held)
 subprocess.run(['nft','delete','table','inet','direction_fixture'],check=True);table=False
 for listener,client in zip(listeners,clients):
  accepted,_=listener.accept();sockets.append(accepted);client.settimeout(5);client.sendall(b'direction-fixture');assert accepted.recv(17)==b'direction-fixture'
 def established():
  v=api();by_cookie={r['socket']['cookie']:r for r in v.get('activity',{}).get('rows',[])}
  for old in held:
   r=by_cookie.get(old['socket']['cookie'])
   if not r or r['socket']['state']!=1:return None
   if any(r['initiation'].get(k)!=old['initiation'].get(k)for k in ['state','direction','source']):return None
   # Another genuine SYN sample can occur after the held API read and before
   # establishment; observed_at is the last direct handshake observation.
   assert datetime.datetime.fromisoformat(r['initiation']['observed_at'])>=datetime.datetime.fromisoformat(old['initiation']['observed_at'])
  return v
 try:final=wait(established)
 except AssertionError:
  (run/'failed-established.json').write_text(json.dumps(api(),indent=2));raise
 assert final['enforcement']['state']=='stopped'
 readonly=api(endpoint+'.monitor');assert readonly['read_only']and 'activity-initiation-v1'in readonly['capabilities']
 assert find(final,address(pre),'0.0.0.0:0')['initiation']['state']=='listening'
 udp_rows=[r for r in final['activity']['rows']if r['socket']['protocol']=='udp'];assert {'unknown','unconnected'}<={r['initiation']['state']for r in udp_rows}
 after=json.loads(cmd('nft','-j','list','ruleset'));assert [x for x in before['nftables']if 'metainfo'not in x]==[x for x in after['nftables']if 'metainfo'not in x]
 result=dict(generation=final['generation'],socket=endpoint,monitor_socket=endpoint+'.monitor',pid=daemon.pid,held=held,established=[r for r in final['activity']['rows']if r['socket']['cookie']in {v['socket']['cookie']for v in held}],preexisting=find(final,address(pc)),firewall_unchanged=True,binary=str(binary))
 (run/'result.json').write_text(json.dumps(result,indent=2))
 print('PASS real authenticated API: held TCP4/6 SYN-sent and passive SYN-received -> same-cookie established outgoing/incoming; preexisting unknown; listening/UDP neutral; read-only capability; no residual nft rules',flush=True)
 if a.hold:
  (run/'ready.json').write_text(json.dumps(result,indent=2));print('READY '+endpoint+'; exclusive UI driver; backend cleans only after DONE via '+str(run/'quit'),flush=True)
  while not (run/'quit').exists():time.sleep(.25)
 print('EVIDENCE '+str(run),flush=True)
finally:
 if table:subprocess.run(['nft','delete','table','inet','direction_fixture'],check=False)
 for s in sockets:s.close()
 if daemon and daemon.poll()is None:daemon.terminate();daemon.wait(8)
 print('CLEANED owned direction fixture',flush=True)

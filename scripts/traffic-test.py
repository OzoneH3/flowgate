#!/usr/bin/env python3
"""Actual unprivileged socket counters. No firewall, packet hooks or payload logs."""
import json,os,socket,subprocess,time,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
run=Path(tempfile.mkdtemp(prefix='traffic-test-',dir=ROOT/'.workspace'));children=[]
def fixture(app,mode=''):
 p=subprocess.Popen([str(ROOT/f'.workspace/traffic-fixtures/{app}/fixture'),*([mode]if mode else [])],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True);children.append(p)
 return p,json.loads(p.stdout.readline())
def api():
 with socket.socket(socket.AF_UNIX) as c:
  c.settimeout(5);c.connect(str(run/'control.sock'));c.sendall(b'{"version":1,"operation":"list"}\n');data=b''
  while b'\n'not in data:
   data+=c.recv(65536)
   assert len(data)<4*1024*1024
  return json.loads(data)['activity']
def wait(fn,seconds=12):
 end=time.monotonic()+seconds
 while time.monotonic()<end:
  r=fn()
  if r:return r
  time.sleep(.08)
 raise AssertionError('timeout')
def snapshot():return api()
def row(info,family):
 return next((r for r in snapshot()['rows'] if r['socket']['protocol']=='tcp' and r['socket']['local'].endswith(':'+str(info['client'+family]))),None)
def transfer(p):p.stdin.write('t\n');p.stdin.flush();assert p.stdout.readline().strip()=='TRANSFERRED'
def launch_observer():
 p=subprocess.Popen([str(ROOT/'.workspace/flowgate'),'observe','--socket',str(run/'control.sock'),'--interval','1s'],stdout=(run/'observer.log').open('a'),stderr=subprocess.STDOUT);children.append(p);wait(lambda:(run/'control.sock').exists());wait(lambda:not snapshot().get('error'));return p
try:
 a,ai=fixture('a');b,bi=fixture('b');shared,si=fixture('a','shared');hidden,hi=fixture('b','hidden')
 obs=launch_observer()
 wait(lambda:all(row(info,f) and row(info,f)['traffic']['available'] for info in [ai,bi,si,hi] for f in ['4','6']))
 baselines={(info['pid'],f):row(info,f)['id'] for info in [ai,bi,si,hi] for f in ['4','6']}
 for p,info in [(a,ai),(b,bi),(shared,si),(hidden,hi)]:
  transfer(p)
  for f in ['4','6']:
   r=wait(lambda:row(info,f) if row(info,f)['traffic']['uploaded']==262144 else None)
   t=r['traffic'];assert t['downloaded']==131072,(f,t);assert t.get('upload_bps',0)>0 and t.get('download_bps',0)>0,(f,t)
   assert r['id']==baselines[info['pid'],f]
   if p==hidden:assert not r['owners'] and r['ownership']=='Unknown owner',r
   elif p==shared:assert len(r['owners'])==2 and r['ownership']=='Shared socket',r
   else:
    assert len(r['owners'])==1
    proc=snapshot()['processes'][r['owners'][0]];assert proc['pid']==info['pid'] and f'/traffic-fixtures/{"a"if p==a else "b"}/fixture'in proc['executable']
 print('PASS exact payload counts: TCP IPv4/IPv6 upload262144, download131072; two executable identities; shared/unknown measured once per socket',flush=True)
 wait(lambda:row(ai,'4')['traffic'].get('upload_bps')==0 and row(ai,'4')['traffic'].get('download_bps')==0)
 print('PASS idle rates return to zero, totals retained',flush=True)
 udp=[r for r in snapshot()['rows']if r['socket']['protocol']=='udp'and any(r['socket']['local'].endswith(':'+str(ai[k]))for k in ['udp4','udp6'])]
 assert len(udp)==2 and all(not r['traffic']['available']for r in udp)
 print('PASS UDP v4/v6 explicitly unavailable, no invented per-peer counters',flush=True)
 # Bounded sustained transfer with serial census (no per-packet process scans).
 def cost():
  fields=Path(f'/proc/{obs.pid}/stat').read_text().split();status=Path(f'/proc/{obs.pid}/status').read_text();rss=int(next(x.split()[1]for x in status.splitlines()if x.startswith('VmRSS:')))
  return (int(fields[13])+int(fields[14]))/os.sysconf('SC_CLK_TCK'),rss
 cpu0,rss0=cost();at=time.monotonic()
 for _ in range(5):transfer(a);transfer(b);time.sleep(1)
 cpu1,rss1=cost();elapsed=time.monotonic()-at
 print(f'OVERHEAD unprivileged observer: {elapsed:.2f}s elapsed, {cpu1-cpu0:.3f}s CPU ({100*(cpu1-cpu0)/elapsed:.2f}% of one CPU), RSS {rss1}KiB; two applications, TCP4/6; collection {snapshot()["duration_ms"]}ms',flush=True)
 # Restore fixture visibility without replacing its socket. Measurement identity
 # and observed totals must survive the presentation reassociation.
 old=row(hi,'4');hidden.stdin.write('v\n');hidden.stdin.flush();assert hidden.stdout.readline().strip()=='VISIBLE'
 visible=wait(lambda:row(hi,'4') if len(row(hi,'4')['owners'])==1 else None)
 assert visible['id']==old['id'] and visible['traffic']['uploaded']==old['traffic']['uploaded'] and visible['traffic']['since']==old['traffic']['since']
 print('PASS actual inaccessible-to-visible owner transition preserves cookie, totals and baseline',flush=True)
 # Restart: baseline is new, never lifetime totals or a rate spike.
 obs.terminate();obs.wait(5);obs=launch_observer();r=wait(lambda:row(ai,'4'));assert r['traffic']['uploaded']==0 and r['traffic']['downloaded']==0,r
 wait(lambda:row(ai,'4')['traffic'].get('upload_bps')==0)
 print('PASS collector restart creates fresh observed baseline without spikes',flush=True)
 old=row(ai,'4')['id'];a.stdin.write('c\n');a.stdin.flush();assert a.stdout.readline().strip()=='CLOSED'
 wait(lambda:not any(r['id']==old for r in snapshot()['rows']))
 print('PASS socket closure removes prior observation; cookie/reset/reuse and ownership transition covered by focused Go tests',flush=True)
 # Retain only workspace fixture metadata in evidence.
 snap=snapshot();ports={str(info[k])for info in [ai,bi,si,hi]for k in ['client4','client6','server4','server6','udp4','udp6']}
 snap['rows']=[r for r in snap['rows']if r['socket']['local'].rsplit(':',1)[-1]in ports]
 wanted={o for r in snap['rows']for o in r['owners']};snap['processes']={k:v for k,v in snap['processes'].items()if k in wanted}
 (run/'fixture-snapshot.json').write_text(json.dumps(snap,indent=2));print('EVIDENCE',run,flush=True)
finally:
 for p in children:
  if p.poll()is None:
   if p.stdin:
    try:p.stdin.close();p.wait(2)
    except (BrokenPipeError,subprocess.TimeoutExpired):pass
   if p.poll()is None:p.terminate();p.wait(5)

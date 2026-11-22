#!/usr/bin/env python3
"""Focused unprivileged read-only ownership checks; no packet hooks or firewall."""
import json, os, socket, subprocess, tempfile, time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
run=Path(tempfile.mkdtemp(prefix='own-',dir=ROOT/'.workspace'));children=[]
def spawn(args):
 p=subprocess.Popen([str(x) for x in args],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=(run/'process.log').open('a'),text=True);children.append(p);return p
def fixture(path,*args):
 p=spawn([ROOT/path,*args]);return p,json.loads(p.stdout.readline())
def snapshot():
 with socket.socket(socket.AF_UNIX) as c:
  c.settimeout(4);c.connect(str(run/'api.sock'));c.sendall(b'{"version":1,"operation":"list"}\n');data=b''
  while b'\n' not in data:
   chunk=c.recv(65536);assert chunk;data+=chunk;assert len(data)<4*1024*1024
 return json.loads(data)['activity']
def wait(fn):
 end=time.monotonic()+10
 while time.monotonic()<end:
  try:
   result=fn()
   if result:return result
  except (FileNotFoundError,ConnectionRefusedError):pass
  time.sleep(.1)
 raise AssertionError('ownership check timed out')
def rows(s,port):return [r for r in s['rows'] if r['socket']['local'].endswith(':'+str(port))]
def one(port):
 return next((r for r in snapshot()['rows'] if r['socket']['local'].endswith(':'+str(port))),None)
try:
 leader,li=fixture('.workspace/ownership-fixtures/leader-exit')
 same,si=fixture('.workspace/ownership-fixtures/a/shared')
 cross,ci=fixture('.workspace/ownership-fixtures/a/shared',ROOT/'.workspace/ownership-fixtures/b/shared')
 hidden,hi=fixture('.workspace/traffic-fixtures/b/fixture','hidden')
 obs=spawn([ROOT/'build/flowgate','observe','--socket',run/'api.sock','--interval','500ms','--udp-socket',''])
 def leader_ok():
  s=snapshot(); rr=[r for p in li['ports'] for r in rows(s,p)]
  if len(rr)!=4 or any(len(r['owners'])!=1 for r in rr):return None
  for r in rr:
   p=s['processes'][r['owners'][0]]
   assert p['pid']==li['tid'] and p['thread_group_pid']==li['pid'] and p['start_ticks']
   assert p['executable'].endswith('/ownership-fixtures/leader-exit') and r['display_application']['key']==p['application']['key']
  return s
 s=wait(leader_ok)
 print('PASS departed leader: live TID/start/TGID resolves TCP4/TCP6/UDP4/UDP6 before any application data',flush=True)
 wait(lambda:one(si['port']) if len(one(si['port'])['owners'])==2 else None)
 r=one(si['port']);assert r['ownership_category']=='shared' and r['display_application']['key'];assert len(rows(snapshot(),si['port']))==1
 print('PASS same-application shared socket: both holders retained, one row and display-only common identity',flush=True)
 # Even a display-associated shared native socket cannot become a policy identity.
 decision=json.loads(subprocess.check_output([str(ROOT/'build/flowgate'),'attribute','--protocol','udp','--direction','incoming','--local',f"127.0.0.1:{si['port']}",'--remote','127.0.0.1:45678'],text=True))
 assert not decision.get('application') and decision['status']!='directly-associated',decision
 print('PASS enforcement Resolve withholds application permission for display-groupable shared socket',flush=True)
 def cross_ok():
  s=snapshot();r=rows(s,ci['port'])[0]
  if len(r['owners'])!=2:return None
  keys={s['processes'][p]['application']['key']for p in r['owners']}
  if len(keys)!=2:return None
  assert 'display_application' not in r and r['ownership_category']=='shared'
  return r
 wait(cross_ok)
 print('PASS distinct-executable shared socket: no common display identity and no duplicated row',flush=True)
 r=one(hi['client4']);assert not r['owners'] and r['ownership_category']=='unknown';id=r['id'];since=r['traffic']['since']
 hidden.stdin.write('t\n');hidden.stdin.flush();assert hidden.stdout.readline().strip()=='TRANSFERRED'
 wait(lambda:one(hi['client4']) if one(hi['client4'])['traffic']['uploaded']==262144 else None)
 hidden.stdin.write('v\n');hidden.stdin.flush();assert hidden.stdout.readline().strip()=='VISIBLE'
 r=wait(lambda:one(hi['client4']) if len(one(hi['client4'])['owners'])==1 else None)
 assert r['id']==id and r['traffic']['since']==since and r['traffic']['uploaded']==262144
 print('PASS restricted FD visibility remains Unknown; restoration preserves socket ID, measured bytes and baseline',flush=True)
 # New rows after worker exit must not inherit its current ownership.
 old_ids={r['id']for p in li['ports']for r in rows(snapshot(),p)}
 leader.terminate();leader.wait(3)
 wait(lambda:not old_ids.intersection(r['id']for r in snapshot()['rows']))
 print('PASS worker exit removes rows/current ownership; no last-known identity authorizes a replacement',flush=True)
 def cost():
  fields=Path(f'/proc/{obs.pid}/stat').read_text().split();status=Path(f'/proc/{obs.pid}/status').read_text()
  return (int(fields[13])+int(fields[14]))/os.sysconf('SC_CLK_TCK'),int(next(l.split()[1]for l in status.splitlines()if l.startswith('VmRSS:')))
 start=time.monotonic();cpu0,_=cost();time.sleep(3);cpu1,rss=cost();s=snapshot();elapsed=time.monotonic()-start
 summary={'elapsed_s':round(elapsed,3),'cpu_s':cpu1-cpu0,'cpu_percent_one_core':100*(cpu1-cpu0)/elapsed,'rss_kib':rss,'last_collection_ms':s['duration_ms'],'categories':s['ownership_counts']}
 (run/'summary.json').write_text(json.dumps(summary,indent=2));print('SANITY',json.dumps(summary),flush=True)
 print('EVIDENCE',run,flush=True)
finally:
 # The shared fixture owns/reaps its exact child; request graceful teardown first.
 for p in children:
  if p.poll() is None:
   try:p.stdin.write('q\n');p.stdin.flush()
   except (BrokenPipeError,OSError):pass
 for name in ['same','cross']:
  p=locals().get(name)
  if p is not None:
   try:p.wait(3)
   except subprocess.TimeoutExpired:pass
 for p in reversed(children):
  if p.poll() is None:
   p.terminate()
   try:p.wait(3)
   except subprocess.TimeoutExpired:p.kill();p.wait()

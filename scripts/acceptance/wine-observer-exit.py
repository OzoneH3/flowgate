#!/usr/bin/env python3
"""Observer must not keep a Wine prefix alive; no application processes are inferred by name."""
import argparse,json,os,pathlib,select,subprocess,tempfile,time
ROOT=pathlib.Path(__file__).resolve().parents[2]
p=argparse.ArgumentParser();p.add_argument('--bin',default='/usr/bin');a=p.parse_args()
import stat,struct
def direct_loader(path):
 """True for an executable regular ELF64 x86-64 file (header fields only;
 not equivalent to Go's debug/elf parser used by identity.observerRunner)."""
 try:
  st=path.stat()
  if not stat.S_ISREG(st.st_mode) or st.st_mode&0o111==0:return False
  with open(path,'rb') as f:h=f.read(64)
 except OSError:return False
 if len(h)<64 or h[:4]!=b'\x7fELF' or h[4]!=2 or h[5] not in (1,2) or h[6]!=1:return False
 return struct.unpack(('<' if h[5]==1 else '>')+'H',h[18:20])[0]==62
def observer_runner(bin):
 # Same candidate order as identity.observerRunner.
 for c in (bin/'../lib/wine/x86_64-unix/wine64',bin/'../lib64/wine/x86_64-unix/wine64',bin/'wine64',bin/'../lib/wine/x86_64-unix/wine',bin/'../lib64/wine/x86_64-unix/wine'):
  if direct_loader(c):return c.resolve()
 return None
def check_runner_selection():
 import shutil,sys
 good=pathlib.Path(sys.executable).resolve()
 with tempfile.TemporaryDirectory(dir=ROOT/'.workspace') as d:
  b=pathlib.Path(d)/'bin';b.mkdir();u=pathlib.Path(d)/'lib/wine/x86_64-unix';u.mkdir(parents=True)
  def put(p,data,mode=0o755):p.write_bytes(data);p.chmod(mode)
  elf=bytearray(good.read_bytes()[:64])
  put(u/'wine64',bytes(elf),0o644)                       # not executable
  bad32=bytearray(elf);bad32[4]=1;put(b/'wine64',bytes(bad32))                  # ELFCLASS32
  badm=bytearray(elf);badm[18:20]=struct.pack('<H',183);put(u/'wine',bytes(badm))  # aarch64 machine
  assert observer_runner(b) is None,'accepted non-executable, 32-bit or wrong-machine loader'
  put(u/'wine',b'\x7fELF\x02\x01')                     # truncated header
  assert observer_runner(b) is None,'accepted truncated loader'
  shutil.copy(good,u/'wine');(u/'wine').chmod(0o755)
  assert observer_runner(b)==(u/'wine').resolve(),'valid lowest-priority loader not selected'
  (u/'wine64').chmod(0o755);shutil.copy(good,u/'wine64');(u/'wine64').chmod(0o755)
  assert observer_runner(b)==(u/'wine64').resolve(),'candidate order not respected'
 print('PASS runner selection negatives: non-executable, 32-bit, wrong machine, truncated; order respected',flush=True)
check_runner_selection()
bin=pathlib.Path(a.bin);server=bin/'wineserver';runner=observer_runner(bin)
assert runner,'no direct x86-64 observer loader'
print('RUNNER',runner,flush=True)
run=pathlib.Path(tempfile.mkdtemp(prefix='observer-exit-',dir=ROOT/'.workspace'));print('EVIDENCE',run,flush=True)
children=[]
def wait(fn,seconds=30):
 end=time.monotonic()+seconds
 while time.monotonic()<end:
  if fn():return
  time.sleep(.05)
 raise AssertionError('deadline')
try:
 sessions=[]
 for index in range(2):
  base=run/str(index);base.mkdir();(base/'tmp').mkdir();(base/'home').mkdir()
  env=dict(os.environ,WINEPREFIX=str(base/'pfx'),WINEDEBUG='-all',WINEDLLOVERRIDES='mscoree,mshtml=',DISPLAY='',WAYLAND_DISPLAY='',HOME=str(base/'home'),TMPDIR=str(base/'tmp'),XDG_CACHE_HOME=str(base/'home'),XDG_CONFIG_HOME=str(base/'home'),XDG_DATA_HOME=str(base/'home'))
  apps=[]
  for n,name in enumerate(('alpha.exe','beta.exe')):
   log=base/(name+'.log');f=log.open('w');child=subprocess.Popen([str(runner),str(ROOT/'.workspace/windows'/name),'t',str(25100+index*10+n)],env=env,stdout=f,stderr=f);children.append(child);apps.append(child)
   wait(lambda:'READY' in log.read_text(),60)
  helper=subprocess.Popen([str(runner),str(ROOT/'.workspace/windows/table-probe.exe')],env=dict(env,WINELOADERNOEXEC='1'),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=(base/'helper.log').open('w'),text=True);children.append(helper)
  helper.stdin.write('t4\n');helper.stdin.flush();assert select.select([helper.stdout],[],[],10)[0]
  census=json.loads(helper.stdout.readline());assert census['complete'],census
  for n,name in enumerate(('alpha.exe','beta.exe')):
   rows=[r for r in census['rows'] if r['port']==25100+index*10+n];assert len(rows)==1 and pathlib.PureWindowsPath(rows[0]['image']).name==name,rows
  other_ports={25100+(1-index)*10,25101+(1-index)*10};assert not any(r['port'] in other_ports for r in census['rows'])
  sessions.append((apps,helper,env))
 # One ordinary app still keeps each observer useful.
 for apps,helper,env in sessions:
  apps[0].terminate();apps[0].wait(10);time.sleep(.5);assert helper.poll() is None
 # Last app in prefix 0 exits; observer 1 must remain alive and prefix-isolated.
 apps,helper,env=sessions[0];start=time.monotonic();apps[1].terminate();apps[1].wait(10);helper.wait(15);assert helper.returncode==0
 assert sessions[1][1].poll() is None
 print('PASS prefix 0 observer exits after last app; prefix 1 remains alive',round(time.monotonic()-start,3),flush=True)
 apps,helper,env=sessions[1];apps[1].terminate();apps[1].wait(10);helper.wait(15);assert helper.returncode==0
 for _,_,env in sessions:subprocess.run([str(server),'-w'],env=env,timeout=15,check=True)
 print('PASS two applications x two prefixes: census isolation, last-app exit and wineserver wait completion',flush=True)
 # Explicit persistence suppresses Wine's shutdown event. Exercise clean helper
 # EOF and replacement while the same server remains; manager renewal is unit-tested.
 env=sessions[0][2]
 persistent=subprocess.Popen([str(server),'-f','-p'],env=env,stdout=(run/'persistent-server.log').open('w'),stderr=subprocess.STDOUT);children.append(persistent)
 time.sleep(.2);assert persistent.poll() is None
 old_pid=None
 for index,name in enumerate(('alpha.exe','beta.exe')):
  log=(run/('persistent-'+name)).open('w')
  app=subprocess.Popen([str(runner),str(ROOT/'.workspace/windows'/name),'t',str(25200+index)],env=env,stdout=log,stderr=log);children.append(app)
  wait(lambda:'READY' in pathlib.Path(log.name).read_text(),60)
  assert persistent.poll() is None
  h=subprocess.Popen([str(runner),str(ROOT/'.workspace/windows/table-probe.exe')],env=dict(env,WINELOADERNOEXEC='1'),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=log,text=True);children.append(h)
  h.stdin.write('t4\n');h.stdin.flush();assert select.select([h.stdout],[],[],10)[0]
  census=json.loads(h.stdout.readline());assert census['complete']
  rows=[r for r in census['rows'] if r['port'] in (25200,25201)]
  assert len(rows)==1 and pathlib.PureWindowsPath(rows[0]['image']).name==name,rows
  if old_pid is not None:assert census['helper_pid']!=old_pid
  old_pid=census['helper_pid']
  h.stdin.close();h.wait(10);assert h.returncode==0
  app.terminate();app.wait(10)
 assert persistent.poll() is None
 persistent.terminate();persistent.wait(10)
 print('PASS persistent server: replacement helper has fresh rows and a new helper PID',flush=True)
except Exception:
 evidence=[]
 for proc in pathlib.Path('/proc').iterdir():
  if not proc.name.isdigit():continue
  try:
   if str(run).encode() in (proc/'environ').read_bytes():
    evidence.append(dict(pid=proc.name,cmd=(proc/'cmdline').read_bytes().replace(b'\0',b' ').decode(errors='replace'),exe=str((proc/'exe').resolve())))
  except OSError:pass
 (run/'failure-processes.json').write_text(json.dumps(evidence,indent=2))
 raise
finally:
 for child in children:
  if child.poll() is None:child.terminate()
 for child in children:
  try:child.wait(5)
  except subprocess.TimeoutExpired:child.kill();child.wait()

#!/usr/bin/env python3
import os,subprocess,time,tempfile,json,sys
from pathlib import Path
root=Path(__file__).resolve().parents[2]
assert os.getuid()!=0,'Launch as desktop user; only the test namespace uses sudo'
run=Path(tempfile.mkdtemp(prefix='udp-verified-',dir=root/'.workspace'));log=(run/'verification.log').open('w')
args=['sudo']+(['-n']if '--noninteractive'in sys.argv else [])
args+=['unshare','--net','--pid','--fork','--mount-proc','env','FLOWGATE_PARENT_NETNS='+os.readlink('/proc/self/ns/net'),'python3',str(root/'scripts/acceptance/udp-isolated-test.py'),'--run',str(run),'--uid',str(os.getuid()),'--gid',str(os.getgid()),'--gui']
p=subprocess.Popen(args,stdout=log,stderr=subprocess.STDOUT)
try:
 end=time.monotonic()+90
 while not(run/'ready.json').exists():
  if p.poll()is not None:raise RuntimeError((run/'verification.log').read_text())
  if time.monotonic()>end:raise RuntimeError('authentication/fixture timeout')
  time.sleep(.1)
 env=os.environ.copy();env.update(FLOWGATE_UDP_VERIFY_RUN=str(run),QT_QPA_PLATFORM='wayland',WAYLAND_DISPLAY=env.get('WAYLAND_DISPLAY','wayland-0'))
 result=subprocess.run([str(root/'.workspace/desktop/udp-measured-test')],env=env,stdout=(run/'wayland.log').open('w'),stderr=subprocess.STDOUT)
 if result.returncode:raise RuntimeError((run/'wayland.log').read_text())
 assert p.wait(15)==0,(run/'verification.log').read_text()
 print((run/'verification.log').read_text());print((run/'wayland.log').read_text());print('EVIDENCE',run)
finally:
 if p.poll()is None:p.terminate();p.wait(5)

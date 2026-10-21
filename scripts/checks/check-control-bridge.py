#!/usr/bin/env python3
"""Test the terminal bridge with simulated sudo in a disposable namespace.
No password/authentication mechanism or real-host activation is exercised.
"""

if not __debug__:
 raise RuntimeError('Optimized Python is unsupported: required verification checks would be disabled')

import json,os,subprocess,time,sys,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
os.umask(0o077)
assert os.environ['FLOWGATE_PARENT_NETNS']!=os.readlink('/proc/self/ns/net')
run=Path(tempfile.mkdtemp(prefix='bridge-',dir=ROOT/'.workspace'))
bindir=run/'bin';bindir.mkdir()
# Only this test's PATH selects the shim. It maps fixed production paths into
# workspace-owned namespace paths and simulates authentication success/failure.
shim=bindir/'sudo'
shim.write_text('''#!/usr/bin/python3
import os,sys
from pathlib import Path
base=Path(__file__).resolve().parents[2]
a=sys.argv[1:]
if a==['-v']:sys.exit(1 if (base/'auth-fail').exists() else 0)
assert a[0]=='-n'
a=a[1:]
if a[0]=='/run/flowgate/controller':a[0]=str(base/'state/controller')
assert a[1]=='host-session'
a+=['--state',str(base/'state'),'--socket',str(base/'api/control.sock'),'--database',str(base/'data/rules.db')]
os.execv(a[0],a)
''');shim.chmod(0o700)
env=os.environ.copy();env['PATH']=str(bindir)+':'+env['PATH']
def job(name):p=run/name;p.mkdir(mode=0o700);return p
def launch(action,path,token=''):
    args=['python3','scripts/desktop-control.py','--action',action,'--job',str(path)]
    if token:args+=['--token',token]
    return subprocess.Popen(args,env=env,stdout=(path/'output.log').open('w'),stderr=subprocess.STDOUT)
def wait(f,seconds=12):
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        try:
            value=f()
            if value:return value
        except (OSError,ValueError):pass
        time.sleep(.05)
    raise AssertionError('bridge timeout')
def result(path):return json.loads((path/'result.json').read_text())
start=job('start');controller=None
try:
    (run/'auth-fail').touch();cancel=job('cancel');p=launch('start',cancel);p.wait(5);assert result(cancel)['phase']=='cancelled';assert not (run/'api/control.sock').exists();(run/'auth-fail').unlink()
    (start/'request.json').write_text(json.dumps({'profile':'both'}))
    controller=launch('start',start);wait(lambda:result(start)['phase']=='ready');token=result(start)['generation'];assert len(token)==32
    active=json.loads(subprocess.check_output([str(run/'state/controller'),'host-status','--state',str(run/'state')],text=True));assert active['record']['Profile']=='both'
    # Snapshot is private and root-in-namespace-owned; later control survives a
    # change in the source pathname. We only inspect, never modify that source.
    assert (run/'state/controller').stat().st_mode&0o777==0o700
    wrong=job('stale-stop');p=launch('stop',wrong,'0'*32);p.wait(8);assert result(wrong)['phase']=='failed';assert controller.poll() is None
    stop=job('stop');p=launch('stop',stop,token);p.wait(8);assert result(stop)['phase']=='stopped';controller.wait(8);assert result(start)['phase']=='stopped'
    status=json.loads(subprocess.check_output([str(run/'state/controller'),'host-status','--state',str(run/'state')],text=True));assert status['state']=='stopped' and not status['table_present']
    print('PASS terminal bridge: simulated auth cancellation, real namespace root snapshot start/readiness, generation-scoped Stop and confirmed cleanup')
finally:
    if controller and controller.poll() is None:
        subprocess.run([str(ROOT/'.workspace/flowgate'),'host-stop','--state',str(run/'state')],check=False)
        controller.wait(8)
print('EVIDENCE',run)

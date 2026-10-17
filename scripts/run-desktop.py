#!/usr/bin/env python3
"""One private, unprivileged observer per launch; no shared socket deletion."""
import argparse
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description='Run FlowGate read-only host monitor')
parser.add_argument('--interval', default='1s', help='Observer refresh delay (500ms..30s)')
args = parser.parse_args()
run = Path(tempfile.mkdtemp(prefix='host-monitor-',dir=ROOT/'.workspace'))
observer = None
gui = None

def interrupted(*_):
    raise KeyboardInterrupt

signal.signal(signal.SIGTERM, interrupted)
try:
    with (run/'observer.log').open('w') as log:
        observer = subprocess.Popen([str(ROOT/'.workspace/flowgate'),'observe','--socket',str(run/'control.sock'),'--interval',args.interval],stdout=log,stderr=log)
    end=time.monotonic()+8
    while not (run/'control.sock').exists():
        if observer.poll() is not None: raise RuntimeError((run/'observer.log').read_text())
        if time.monotonic()>end: raise RuntimeError('Observer startup timeout')
        time.sleep(.05)
    env=os.environ.copy()
    if not env.get('WAYLAND_DISPLAY') and not env.get('DISPLAY') and Path('/run/user/'+str(os.getuid())+'/wayland-0').exists():
        env['WAYLAND_DISPLAY']='wayland-0';env['QT_QPA_PLATFORM']='wayland'
    print('FlowGate host monitor — read-only. No firewall rules or synthetic traffic.',flush=True)
    print('Private session:',run,flush=True)
    print('Close the window or press Ctrl+C here to stop this observer. Other instances are independent.',flush=True)
    gui=subprocess.Popen([str(ROOT/'.workspace/desktop/flowgate-desktop'),'--monitor-socket',str(run/'control.sock'),'--control-socket','/run/flowgate-api/control.sock'],env=env)
    gui.wait()
except KeyboardInterrupt:
    pass
finally:
    for p in (gui,observer):
        if p is not None and p.poll() is None:
            p.terminate()
            try: p.wait(timeout=5)
            except subprocess.TimeoutExpired: p.kill();p.wait()
    # Only this freshly-created private instance's stale socket, never another's.
    (run/'control.sock').unlink(missing_ok=True)
    print('Host observer stopped. Log retained:',run,flush=True)

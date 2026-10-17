#!/usr/bin/env python3
"""Own only a newly-created read-only observer; never start/stop enforcement."""
import argparse
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
ROOT = Path(__file__).resolve().parents[1]
p = argparse.ArgumentParser(description='FlowGate Electron: unprivileged Activity and existing-controller decisions')
p.add_argument('--observer', help='Reuse an existing read-only observer Unix socket; leave it running on exit')
p.add_argument('--control', help='Existing authenticated controller Unix socket; never start or stop its controller')
p.add_argument('--interval', default='1s', help='Owned observer interval, 500ms–30s (default 1s)')
p.add_argument('--width', type=int, default=1280, help='Initial main window width (800–3840)')
p.add_argument('--height', type=int, default=820, help='Initial main window height (550–2160)')
a = p.parse_args()
if not 800 <= a.width <= 3840 or not 550 <= a.height <= 2160:
    p.error('Window size outside supported range')
if os.geteuid() == 0:
    p.error('Electron must run as the desktop user, never root')
for endpoint in (a.observer, a.control):
    if endpoint and (not os.path.isabs(endpoint) or len(os.fsencode(endpoint)) > 107):
        p.error('Endpoints must be absolute Unix socket paths of at most 107 bytes')
run = Path(tempfile.mkdtemp(prefix='electron-run-', dir=ROOT/'.workspace'))
children = []
owned = None

def interrupted(*_):
    raise KeyboardInterrupt

signal.signal(signal.SIGTERM, interrupted)
signal.signal(signal.SIGINT, interrupted)
try:
    with (run/'observer.log').open('w') as log:
        if not a.observer:
            owned = run/'observer.sock'
            observer = subprocess.Popen([str(ROOT/'.workspace/electron-observer'), 'observe', '--socket', str(owned), '--interval', a.interval], stdout=log, stderr=log)
            children.append(observer)
            end = time.monotonic()+10
            while not owned.exists():
                if observer.poll() is not None:
                    raise RuntimeError((run/'observer.log').read_text())
                if time.monotonic() > end:
                    raise RuntimeError('Observer startup timeout')
                time.sleep(.05)
            a.observer = str(owned)
        env = os.environ.copy()
        if not env.get('WAYLAND_DISPLAY') and Path('/run/user/'+str(os.getuid())+'/wayland-0').exists():
            env['WAYLAND_DISPLAY'] = 'wayland-0'
        args = [str(ROOT/'electron/node_modules/.bin/electron'), str(ROOT/'electron'), '--observer', a.observer, '--width', str(a.width), '--height', str(a.height)]
        if env.get('WAYLAND_DISPLAY'):
            args.insert(1, '--ozone-platform=wayland')
        if a.control:
            args += ['--control', a.control]
        print('FlowGate: read-only Activity. Controller:', a.control or 'not attached; enforcement state unknown', flush=True)
        print('Owned run directory:', run, flush=True)
        gui = subprocess.Popen(args, env=env)
        children.append(gui)
        code = gui.wait()
        if code:
            raise RuntimeError(f'Electron exited with {code}; sandbox remains enabled')
except KeyboardInterrupt:
    pass
finally:
    for child in reversed(children):
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
    if owned:
        owned.unlink(missing_ok=True)

#!/usr/bin/env python3
"""Own only a newly-created read-only observer; never start/stop enforcement."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
ROOT = Path(__file__).resolve().parents[1]
import sys
sys.dont_write_bytecode = True  # no electron/__pycache__ when invoked directly
sys.path.insert(0, str(Path(__file__).resolve().parent))
import fontconfig_isolation  # noqa: E402
p = argparse.ArgumentParser(description='FlowGate Electron: unprivileged Activity and existing-controller decisions')
p.add_argument('--daemon', help='Reuse one existing daemon: companion Activity and primary policy; never start/stop it')
p.add_argument('--observer', help='Reuse an existing read-only observer Unix socket; leave it running on exit')
p.add_argument('--control', help='Existing authenticated controller Unix socket; never start or stop its controller')
p.add_argument('--interval', default='1s', help='Owned observer interval, 500ms–30s (default 1s)')
p.add_argument('--width', type=int, default=None, help='Initial main window width (800–3840)')
p.add_argument('--height', type=int, default=None, help='Initial main window height (550–2160)')
a = p.parse_args()
if a.daemon:
    if a.observer or a.control: p.error('--daemon cannot be combined with --observer/--control')
    a.control = a.daemon
    a.observer = a.daemon + '.monitor'
if (a.width is not None and not 800 <= a.width <= 3840) or (a.height is not None and not 550 <= a.height <= 2160):
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
        # Electron's bundled Fontconfig must not share caches with the host's
        # (possibly newer) Fontconfig; keeps fonts/rules, private versioned cache.
        fontconfig_isolation.apply(env, env.get('XDG_CACHE_HOME') or str(ROOT/'.workspace/cache'),
                                   fontconfig_isolation.runtime_version(ROOT/'electron/node_modules/electron/dist'))
        if not env.get('WAYLAND_DISPLAY') and Path('/run/user/'+str(os.getuid())+'/wayland-0').exists():
            env['WAYLAND_DISPLAY'] = 'wayland-0'
        args = [str(ROOT/'electron/node_modules/.bin/electron'), str(ROOT/'electron'), '--observer', a.observer]
        if a.width is not None: args += ['--width',str(a.width)]
        if a.height is not None: args += ['--height',str(a.height)]
        if env.get('WAYLAND_DISPLAY'):
            args.insert(1, '--ozone-platform=wayland')
        if a.control:
            args += ['--control', a.control]
        print('FlowGate: read-only Activity. Controller:', a.control or 'not attached; enforcement state unknown', flush=True)
        print('Owned run directory:', run, flush=True)
        (run/'launch.json').write_text(json.dumps({'args': args, 'started': time.time()}))
        gui = subprocess.Popen(args, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors='replace')
        children.append(gui)
        with (run/'electron.log').open('w') as gui_log:
            for line in gui.stdout:
                gui_log.write(line)
                gui_log.flush()
                print(line, end='', flush=True)
        code = gui.wait()
        (run/'exit.json').write_text(json.dumps({'code': code, 'finished': time.time()}))
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

#!/usr/bin/env python3
"""GUI stays outside the user/network namespace. Ctrl+C tears down only this lab."""
import json
import os
from pathlib import Path
import socket
import signal
import subprocess
import tempfile
import time

def interrupted(*_):
    raise KeyboardInterrupt

signal.signal(signal.SIGTERM, interrupted)

ROOT = Path(__file__).resolve().parents[1]
run = Path(tempfile.mkdtemp(prefix='desktop-demo-',dir=ROOT/'.workspace'))
lab = subprocess.Popen([str(ROOT/'scripts/lab.sh'),'python3',str(ROOT/'scripts/acceptance/desktop-lab.py'),str(run),'60s'])
gui = None

def command(value):
    with socket.socket(socket.AF_UNIX) as s:
        s.settimeout(2); s.connect(str(run/'demo.sock')); s.sendall(json.dumps(value).encode()+b'\n')
        return s.recv(4096)

try:
    end = time.monotonic()+12
    while not (run/'ready').exists():
        if lab.poll() is not None: raise RuntimeError('Lab failed; inspect '+str(run))
        if time.monotonic()>end: raise RuntimeError('Lab startup timeout')
        time.sleep(.05)
    env = os.environ.copy()
    if not env.get('WAYLAND_DISPLAY') and not env.get('DISPLAY') and Path('/run/user/'+str(os.getuid())+'/wayland-0').exists():
        env['WAYLAND_DISPLAY']='wayland-0'
        env['QT_QPA_PLATFORM']='wayland'
    gui = subprocess.Popen([str(ROOT/'.workspace/desktop/flowgate-desktop'),'--socket',str(run/'control.sock')],env=env)
    print('\nFlowGate isolated lab:',run,flush=True)
    print('Only workspace native UDP traffic is controlled. Normal host networking is unchanged.')
    print('Each attempt sends ONE datagram. Allow should add RECEIVED to receiver-41001.log.')
    print('Press Enter for another attempt; type 2..8 for another service port; q or Ctrl+C stops the lab.')
    print('Closing the window leaves enforcement running. The initial decision has 60 seconds.',flush=True)
    time.sleep(1)
    command({'operation':'send','port':41001})
    while True:
        try: line=input('Attempt [Enter / 2..8 / q]: ').strip()
        except EOFError:
            print('No terminal input; lab remains running until Ctrl+C.',flush=True)
            while True: time.sleep(1)
        if line=='q': break
        if line and line not in [str(i) for i in range(2,9)]: continue
        port=41000+int(line or '1')
        print(command({'operation':'send','port':port}).decode().strip())
        print('Receiver log:',run/f'receiver-{port}.log')
except KeyboardInterrupt:
    pass
finally:
    try: command({'operation':'quit'})
    except OSError: pass
    if gui and gui.poll() is None: gui.terminate(); gui.wait(timeout=5)
    try: lab.wait(timeout=8)
    except subprocess.TimeoutExpired: lab.terminate(); lab.wait(timeout=5)
    print('Lab stopped. Logs retained:',run)

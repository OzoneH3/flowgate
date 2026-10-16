#!/usr/bin/env python3
"""Disposable namespace supervisor. Commands affect only its own native fixtures."""
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
RUN = Path(sys.argv[1]).resolve()
assert RUN.is_relative_to(ROOT / '.workspace')
assert os.environ['FLOWGATE_PARENT_NETNS'] != os.readlink('/proc/self/ns/net')
TIMEOUT = sys.argv[2] if len(sys.argv) > 2 else '60s'
children = []
backend = None
stopping = False

def stop(*_):
    global stopping
    stopping = True

signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)

def spawn(args, log):
    with (RUN / log).open('a') as output:
        p = subprocess.Popen(args, stdout=output, stderr=output)
    children.append(p)
    return p

def start_backend():
    global backend
    for name in ('control.sock', 'control.sock.monitor'):
        (RUN / name).unlink(missing_ok=True)
    backend = spawn([str(ROOT / '.workspace/flowgate'), 'serve-lab', '--socket', str(RUN / 'control.sock'),
                     '--parent-netns', os.environ['FLOWGATE_PARENT_NETNS'], '--timeout', TIMEOUT], 'backend.log')
    end = time.monotonic() + 8
    while time.monotonic() < end:
        if backend.poll() is not None:
            raise RuntimeError((RUN / 'backend.log').read_text())
        # Readiness includes installed queue/rules, not merely the API listener.
        if (RUN / 'control.sock').exists() and 'READY: disposable namespace enforcement' in (RUN / 'backend.log').read_text():
            return
        time.sleep(.05)
    raise RuntimeError('lab backend startup timeout')

control = socket.socket(socket.AF_UNIX)
try:
    for port in range(41001, 41009):
        spawn([str(ROOT / '.workspace/flowgate-demo-receiver'), f'127.0.0.1:{port}'], f'receiver-{port}.log')
    end = time.monotonic() + 5
    while not all('READY' in (RUN / f'receiver-{p}.log').read_text() for p in range(41001,41009)):
        if time.monotonic() > end: raise RuntimeError('receiver startup timeout')
        time.sleep(.05)
    start_backend()
    control.bind(str(RUN / 'demo.sock'))
    os.chmod(RUN / 'demo.sock', 0o600)
    control.listen(4)
    control.settimeout(.2)
    (RUN / 'ready').write_text('isolated native UDP lab\n')
    while not stopping:
        try: c, _ = control.accept()
        except socket.timeout: continue
        with c:
            c.settimeout(1)
            pid, uid, gid = struct.unpack('3i', c.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid != os.getuid(): continue
            raw = c.recv(256)
            try:
                command = json.loads(raw)
                op = command['operation']
                if op == 'send':
                    port = int(command['port'])
                    if port not in range(41001,41009): raise ValueError('invalid fixture port')
                    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sender:
                        sender.bind(('127.0.0.1',0))
                        source = sender.getsockname()[1]
                        sender.sendto(b'FlowGate desktop demo',('127.0.0.1',port))
                    reply = {'sent_once': True, 'source_port': source}
                elif op == 'stop-backend':
                    # Abrupt consumer loss keeps the isolated rules fail-closed.
                    backend.kill(); backend.wait(); reply = {'stopped': True}
                elif op == 'quit':
                    stopping = True; reply = {'stopped': True}
                else: raise ValueError('unknown demo command')
                c.sendall(json.dumps(reply).encode()+b'\n')
            except (ValueError, KeyError) as e:
                c.sendall(json.dumps({'error': str(e)}).encode()+b'\n')
finally:
    control.close()
    for p in reversed(children):
        if p.poll() is None: p.terminate()
    for p in reversed(children):
        try: p.wait(timeout=3)
        except subprocess.TimeoutExpired: p.kill(); p.wait()
    for name in ('control.sock','control.sock.monitor','demo.sock','ready'):
        (RUN / name).unlink(missing_ok=True)

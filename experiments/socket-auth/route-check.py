#!/usr/bin/env python3
"""Bounded private-netns route probe; no host rules/service operations."""
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path('/home/flowgate-user/Apps/flowgate/.workspace/socket-auth-prototype')
PROBE = ROOT / 'build/socket-auth/route-probe'

if '--inside' in sys.argv:
    for name in ('pid', 'net', 'mnt'):
        assert os.stat(os.environ['FG_PARENT_' + name]).st_ino != os.stat('/proc/self/ns/' + name).st_ino
    assert os.getpid() == 1
    subprocess.run(['nft', '-f', '-'], input='add table inet flowgate_route_probe\nadd chain inet flowgate_route_probe gate { type filter hook output priority 10; policy drop; }\n', text=True, check=True, timeout=5)
    commands = [
        ['ip','link','set','lo','up'],
        ['ip','link','add','fgv0','type','veth','peer','name','fgv1'],
        ['ip','link','set','fgv1','address','02:00:00:00:00:02'],
        ['ip','link','set','fgv0','up'], ['ip','link','set','fgv1','up'],
        ['ip','address','add','198.18.0.1/32','dev','lo'],
        ['ip','route','add','198.18.0.2/32','dev','fgv0','src','198.18.0.1'],
        ['ip','neigh','add','198.18.0.2','lladdr','02:00:00:00:00:02','dev','fgv0','nud','permanent'],
    ]
    for command in commands:
        subprocess.run(command, check=True, timeout=5)
    os.execv(PROBE, [str(PROBE)])

if os.geteuid() != 0:
    raise SystemExit('Requires sudo for isolated BPF/netfilter loading; no host deployment.')
out = Path(tempfile.mkdtemp(prefix='route-', dir=ROOT / 'build/socket-auth'))
os.chmod(out, 0o700)
owner = ROOT.stat()
fds = []
env = dict(os.environ)
for name in ('pid', 'net', 'mnt'):
    fd = os.open('/proc/self/ns/' + name, os.O_RDONLY)
    fds.append(fd)
    env['FG_PARENT_' + name] = '/proc/self/fd/' + str(fd)

def inventory():
    result = {}
    for kind in ('prog', 'link'):
        p = subprocess.run(['bpftool', '-j', kind, 'show'], capture_output=True, text=True, timeout=5)
        if p.returncode:
            raise RuntimeError('Cannot inventory ' + kind + ': ' + p.stderr)
        result[kind] = sorted(x['id'] for x in json.loads(p.stdout))
    return result

rc = 1
try:
    before = inventory()
    provenance = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                  for p in [PROBE, ROOT / 'internal/socketgrant/route_kernel.c', ROOT / 'internal/socketgrant/route_kernel.h', ROOT / 'internal/socketgrant/bpf/route_gate.bpf.c', ROOT / 'internal/socketgrant/bpf/gate.h', ROOT / 'build/socket-route-build/route_gate.skel.h', ROOT / 'internal/socketgrant/owned_rule.c', ROOT / 'internal/socketgrant/owned_rule.h', *sorted((ROOT / 'experiments/socket-auth').glob('*'))] if p.is_file()}
    (out / 'provenance.json').write_text(json.dumps(provenance, indent=2))
    with (out / 'output.log').open('w') as log:
        p = subprocess.Popen(['unshare', '--mount', '--propagation', 'private', '--net', '--pid', '--fork',
                              '--mount-proc', sys.executable, str(Path(__file__).resolve()), '--inside'],
                             pass_fds=fds, env=env, stdout=log, stderr=subprocess.STDOUT,
                             start_new_session=True)
        try:
            rc = p.wait(timeout=60)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL)
            p.wait()
            rc = 124
    after = inventory()
    immediate = after
    if before != after:
        # Netfilter rule destruction can release its program after an RCU grace
        # period. Retain both inventories; never remove any unexpected object.
        time.sleep(1)
        after = inventory()
    (out / 'inventory.json').write_text(json.dumps({'before': before, 'immediate': immediate, 'after': after}, indent=2))
    if before != after:
        print('STOP: BPF inventory changed; inspect evidence; no automatic cleanup attempted.')
        rc = 1
    print('route:', 'PASS' if rc == 0 else 'FAIL', '; evidence:', out / 'output.log')
finally:
    for fd in fds:
        os.close(fd)
    for f in out.iterdir():
        os.chmod(f, 0o600)
        os.chown(f, owner.st_uid, owner.st_gid)
    os.chown(out, owner.st_uid, owner.st_gid)
print('Result:', out, 'exit', rc)
raise SystemExit(rc)

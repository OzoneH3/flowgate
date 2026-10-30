#!/usr/bin/env python3
"""Bounded private-netns protection-session lifecycle probe; no host rules/service operations."""
import hashlib
import ctypes
import json
import os
from pathlib import Path
import signal
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path('/home/flowgate-user/Apps/flowgate/.workspace/socket-auth-prototype')
PROBE = ROOT / '.workspace/socket-auth/daemon-regression.test'
IDENTITY = ROOT / '.workspace/socket-auth/identity-regression.test'
UDP = ROOT / '.workspace/socket-auth/udpaccount-regression.test'

if '--inside' in sys.argv:
    for name in ('pid', 'net', 'mnt'):
        assert os.stat(os.environ['FG_PARENT_' + name]).st_ino != os.stat('/proc/self/ns/' + name).st_ino
    assert os.getpid() == 1
    subprocess.run(['ip','link','set','lo','up'],check=True,timeout=5)
    # Requires explicit workspace-rule exception. Overlay the existing /run
    # only AFTER --inside was loaded; never mkdir on the host-backed /run.
    prior_mount_ids = {line.split()[0] for line in Path('/proc/self/mountinfo').read_text().splitlines()}
    subprocess.run(['mount','-t','tmpfs','-o','mode=0755,nosuid,nodev','tmpfs','/run'],check=True,timeout=5)
    mounts = [line.split() for line in Path('/proc/self/mountinfo').read_text().splitlines()]
    runs = [row for row in mounts if row[4] == '/run']
    assert runs
    mount = runs[-1]
    assert mount[0] not in prior_mount_ids
    separator = mount.index('-')
    assert mount[separator+1] == 'tmpfs'
    assert not any(field.startswith(('shared:', 'master:', 'propagate_from:')) for row in runs for field in row[6:row.index('-')])
    (Path(os.environ['FG_SESSION_RUN'])/'isolation.json').write_text(json.dumps({'run_mount':mount,'namespaces':{name:os.readlink('/proc/self/ns/'+name) for name in ('pid','net','mnt')}},indent=2))
    private = Path('/run/flowgate-session-test')
    private.mkdir(mode=0o700)
    env = dict(os.environ)
    env['FLOWGATE_PARENT_NETNS'] = os.readlink(os.environ['FG_PARENT_net'])
    env['FLOWGATE_SOCKET_SESSION_RUN'] = str(private)
    env['TMPDIR'] = str(private / 'tmp')
    Path(env['TMPDIR']).mkdir(mode=0o700)
    try:
        code = 0
        native = '^Test(ObservedActualNativeUnixAPI|EssentialAPIAtomicReplayStaleRemove|EndpointAPIAdminReadOnlyAndPersistence|ObservedUsageReadOnlyAPIProjection|ServicePrivateMountPreviewSave|EssentialDNSKernelReceivers)$'
        work = private / 'work/internal/daemon'
        work.mkdir(parents=True)
        (private / 'work/.workspace/tmp').mkdir(parents=True)
        for binary, selection, ordinary in ((IDENTITY, '^TestMappedIPv6OwnershipUsesSocketIdentity$', False), (PROBE, native, False), (PROBE, '.', True), (UDP, '.', False)):
            options = {}
            cwd = work
            if ordinary:
                # Ordinary-peer API tests require the desktop uid, not root.
                # Reproduce the package-relative scratch layout in tmpfs too.
                owner = ROOT.stat()
                cwd = private / 'work/internal/daemon'
                for current, dirs, files in os.walk(private):
                    os.chown(current, owner.st_uid, owner.st_gid)
                    for name in files:
                        os.chown(Path(current)/name, owner.st_uid, owner.st_gid, follow_symlinks=False)
                os.chown(env['FG_SESSION_RUN'], owner.st_uid, owner.st_gid)
                # The namespace init must also be visible to the ordinary peer's
                # complete census. Drop its credentials permanently before
                # starting the uid arm; remaining work only copies evidence.
                os.setgroups([])
                os.setgid(owner.st_gid)
                os.setuid(owner.st_uid)
                if ctypes.CDLL(None, use_errno=True).prctl(4, 1, 0, 0, 0) != 0:
                    raise RuntimeError('cannot make test init inspectable')
            env['FLOWGATE_TEST_PRIVATE_MOUNT'] = '1' if binary == PROBE and not ordinary else '0'
            env['FLOWGATE_ESSENTIAL_PRIVATE_NETNS'] = env['FLOWGATE_PARENT_NETNS'] if binary == PROBE and not ordinary else ''
            args = [str(binary), '-test.v', '-test.run='+selection, '-test.timeout=90s']
            result = subprocess.run(args,env=env,cwd=cwd,timeout=95,**options)
            code = max(code, result.returncode)
    finally:
        # Preserve state evidence, not the copied controller binary. Namespace
        # teardown discards the private filesystem and any remaining resources.
        shutil.copytree(private,Path(env['FG_SESSION_RUN'])/'private-state',ignore=shutil.ignore_patterns('controller','controller-*'),symlinks=True)
    raise SystemExit(code)

if os.geteuid() != 0:
    raise SystemExit('Requires sudo for isolated BPF/netfilter loading; no host deployment.')
out = Path(tempfile.mkdtemp(prefix='api-regression-', dir=ROOT / '.workspace/socket-auth'))
os.chmod(out, 0o700)
owner = ROOT.stat()
fds = []
env = dict(os.environ)
(out / 'tmp').mkdir(mode=0o700)
env['FG_SESSION_RUN'] = str(out)
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
    sources = [PROBE, IDENTITY, UDP, *sorted((ROOT/'internal/hostfirewall').glob('*')), *sorted((ROOT/'internal/socketgrant').rglob('*')), *sorted((ROOT/'internal/daemon').glob('socket*')), ROOT/'internal/identity/link_guard_linux.go', ROOT/'experiments/socket-auth/release-regression-check.py']
    provenance = {str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sources if p.is_file()}
    (out / 'provenance.json').write_text(json.dumps(provenance, indent=2))
    with (out / 'output.log').open('w') as log:
        p = subprocess.Popen(['unshare', '--mount', '--propagation', 'private', '--net', '--pid', '--fork',
                              '--mount-proc', sys.executable, str(Path(__file__).resolve()), '--inside'],
                             pass_fds=fds, env=env, stdout=log, stderr=subprocess.STDOUT,
                             start_new_session=True)
        try:
            rc = p.wait(timeout=390)
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
    print('session:', 'PASS' if rc == 0 else 'FAIL', '; evidence:', out / 'output.log')
finally:
    for fd in fds:
        os.close(fd)
    for current, dirs, files in os.walk(out, followlinks=False):
        for name in files:
            f=Path(current)/name
            if not f.is_symlink():
                os.chmod(f,0o600); os.chown(f,owner.st_uid,owner.st_gid,follow_symlinks=False)
        for name in dirs:
            f=Path(current)/name
            if not f.is_symlink():
                os.chmod(f,0o700); os.chown(f,owner.st_uid,owner.st_gid,follow_symlinks=False)
    os.chown(out, owner.st_uid, owner.st_gid)
print('Result:', out, 'exit', rc)
raise SystemExit(rc)

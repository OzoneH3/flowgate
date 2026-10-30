#!/usr/bin/env python3
"""Bounded private-netns production-session Wine smoke probe; no host rules/service operations."""
import hashlib
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
PROBE = ROOT / '.workspace/socket-auth/production-flowgate'
COMPARE=ROOT/'experiments/socket-auth/production-cost-compare.py'
PE=ROOT/'.workspace/socket-auth/routed-timed.exe'

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
    private.mkdir(mode=0o755)
    env = dict(os.environ)
    env['FLOWGATE_PARENT_NETNS'] = os.readlink(os.environ['FG_PARENT_net'])
    env['FLOWGATE_SOCKET_SESSION_RUN'] = str(private)
    env['TMPDIR'] = env['FG_SESSION_RUN'] + '/tmp'
    env['FLOWGATE_ROOT_PIDNS_FD'] = os.environ['FG_PARENT_pid'].rsplit('/',1)[1]
    env['FLOWGATE_ROOT_MNTNS_FD'] = os.environ['FG_PARENT_mnt'].rsplit('/',1)[1]
    env['FLOWGATE_FIXTURE_UID'] = str(ROOT.stat().st_uid)
    env['FLOWGATE_FIXTURE_GID'] = str(ROOT.stat().st_gid)
    env['FLOWGATE_TEST_ITERATOR_HELPER'] = str(Path(env['FG_SESSION_RUN'])/'loader')
    fixture=Path(env['FG_SESSION_RUN'])/'candidate'
    cmd=[sys.executable,str(COMPARE),'--binary',str(PROBE),'--helper','/home/flowgate-user/Apps/flowgate/.workspace/windows/table-probe.exe',
        '--run',str(fixture),'--proton','/home/flowgate-user/Apps/flowgate/.workspace/udp-capacity/proton',
        '--data','/home/flowgate-user/Apps/flowgate/.workspace/proton-launcher-fixture/data',
        '--prefix-source','/home/flowgate-user/Apps/flowgate/.workspace/proton-launcher-fixture/run11/prefix-a',
        '--pe',str(PE),'--lwp','/home/flowgate-user/user_config/scripts/lwp',
        '--sockets','2','--datagrams','7500','--interval-ms','8','--native-pps','20',
        '--min-native-delivery','.001','--max-native-p99-ms','10000','--min-allowed-socket-share','.001']
    try:
        result = subprocess.run(cmd,env=env,cwd=ROOT.parent.parent,pass_fds=(int(env['FLOWGATE_ROOT_PIDNS_FD']),int(env['FLOWGATE_ROOT_MNTNS_FD'])),timeout=400)
        code = result.returncode
    finally:
        # Preserve state evidence, not the copied controller binary. Namespace
        # teardown discards the private filesystem and any remaining resources.
        shutil.copytree(private,Path(env['FG_SESSION_RUN'])/'private-state',ignore=shutil.ignore_patterns('controller','controller-*'),symlinks=True)
    raise SystemExit(code)

if os.geteuid() != 0:
    raise SystemExit('Requires sudo for isolated production-path smoke; no host deployment.')
out = Path(tempfile.mkdtemp(prefix='production-cost-', dir=ROOT / '.workspace/socket-auth'))
os.chmod(out, 0o700)
owner = ROOT.stat()
os.chown(out, owner.st_uid, owner.st_gid)
fds = []
env = dict(os.environ)
(out / 'tmp').mkdir(mode=0o700)
shutil.copyfile('/home/flowgate-user/Apps/flowgate/.workspace/census-bottleneck/iterator/loader-v2', out/'loader')
os.chmod(out/'loader',0o700)
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
    sources = [PROBE, COMPARE, PE, out/'loader', ROOT/'experiments/socket-auth/production-cost-check.py', ROOT/'experiments/socket-auth/windows-udp-routed.c', *sorted((ROOT/'cmd/flowgate').glob('*.go')), *sorted((ROOT/'internal/hostfirewall').glob('*')), *sorted((ROOT/'internal/socketgrant').rglob('*')), *sorted((ROOT/'internal/daemon').glob('socket*')), ROOT/'internal/identity/link_guard_linux.go', ROOT/'experiments/socket-auth/session-check.py']
    provenance = {str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in sources if p.is_file()}
    (out / 'provenance.json').write_text(json.dumps(provenance, indent=2))
    with (out / 'output.log').open('w') as log:
        p = subprocess.Popen(['unshare', '--mount', '--propagation', 'private', '--net', '--pid', '--fork',
                              '--mount-proc', sys.executable, str(Path(__file__).resolve()), '--inside'],
                             pass_fds=fds, env=env, stdout=log, stderr=subprocess.STDOUT,
                             start_new_session=True)
        try:
            rc = p.wait(timeout=420)
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
    print('production smoke:', 'PASS' if rc == 0 else 'FAIL', '; evidence:', out / 'output.log')
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

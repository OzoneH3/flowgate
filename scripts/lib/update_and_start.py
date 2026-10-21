#!/usr/bin/env python3
"""One-command update orchestration. The installer remains monitoring-only."""
import argparse
import base64
import hashlib
import json
import os
import pathlib
import signal
import socket
import struct
import subprocess
import sys
import time


def say(message):
    print('==> ' + message, flush=True)


def verify_bundle(directory, manifest_name, revision):
    manifest = json.loads((directory / manifest_name).read_text())
    if manifest.get('source') != revision:
        raise RuntimeError('Bundle source does not match selected master')
    for name, expected in manifest['files'].items():
        path = directory / name
        if not path.resolve().is_relative_to(directory.resolve()):
            raise RuntimeError('Bundle path escapes release directory')
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise RuntimeError('Bundle hash mismatch: ' + str(path))
    return manifest


def mode(status):
    protection = status.get('protection') or {}
    selected = protection.get('desired_mode')
    if selected not in ('monitoring', 'incoming', 'both'):
        raise RuntimeError('Unknown protection mode; no update action taken')
    return selected


def at_mode(status, selected):
    p, e = status.get('protection') or {}, status.get('enforcement') or {}
    if selected == 'monitoring':
        return p.get('desired_mode') == selected and p.get('state') == 'stopped' and e.get('state') == 'stopped'
    return p.get('desired_mode') == selected and p.get('state') == 'active' and p.get('profile') == selected and e.get('state') == 'active' and e.get('profile') == selected


def matches(status, manifest):
    build = status.get('build') or {}
    return build.get('source') == manifest['source'] and build.get('executable_sha256') == manifest['files']['flowgate'] and build.get('modified') is False


# The privileged process receives bytes selected before authentication, never a
# path into the user's writable build tree. This is a local-source trust model,
# not a signature or proof that the selected source is trustworthy.
STAGE_INSTALL = r"""
import base64, hashlib, json, os, pathlib, subprocess, sys, tempfile
payload = json.load(sys.stdin)
base = pathlib.Path('/usr/local/lib/flowgate')
for path in reversed([base, *base.parents]):
    if not path.exists(): path.mkdir(mode=0o755)
    st = path.lstat()
    if path.is_symlink() or not path.is_dir() or st.st_uid != 0 or st.st_mode & 0o022:
        raise RuntimeError('Unsafe installation parent: ' + str(path))
with tempfile.TemporaryDirectory(prefix='.install-', dir=base) as temporary:
    stage = pathlib.Path(temporary)
    for name, encoded in payload['files'].items():
        if name in ('', '.', '..') or '/' in name:
            raise RuntimeError('Invalid staged filename')
        data = base64.b64decode(encoded, validate=True)
        (stage / name).write_bytes(data)
    manifest = json.loads((stage / 'manifest.json').read_bytes())
    for name, expected in manifest['files'].items():
        if name not in payload['files'] or hashlib.sha256((stage / name).read_bytes()).hexdigest() != expected:
            raise RuntimeError('Staged bundle hash mismatch')
    result = subprocess.run(['/usr/bin/python3', '-I', str(stage / 'install-monitoring.py'), '--bundle', str(stage)], check=False)
    sys.exit(result.returncode)
"""


def snapshot_bundle(backend, expected_manifest=None):
    manifest_bytes = (backend / 'manifest.json').read_bytes()
    manifest = json.loads(manifest_bytes)
    if expected_manifest is not None and manifest != expected_manifest:
        raise RuntimeError('Bundle manifest changed before authentication')
    files = {'manifest.json': base64.b64encode(manifest_bytes).decode()}
    if 'install-monitoring.py' not in manifest['files']:
        raise RuntimeError('Installer missing from bundle manifest')
    for name, expected in manifest['files'].items():
        if name in ('', '.', '..', 'manifest.json') or '/' in name:
            raise RuntimeError('Invalid backend bundle filename')
        data = (backend / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise RuntimeError('Bundle changed before authentication: ' + name)
        files[name] = base64.b64encode(data).decode()
    return json.dumps({'files': files}).encode()


class Host:
    def status(self):
        with socket.socket(socket.AF_UNIX) as client:
            client.settimeout(5)
            client.connect('/run/flowgate-api/daemon.sock')
            _, uid, _ = struct.unpack('3i', client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid != 0:
                raise RuntimeError('System daemon peer is not root')
            client.sendall(b'{"version":1,"operation":"list"}\n')
            response = json.loads(client.makefile('rb').readline())
        if response.get('error'):
            raise RuntimeError(response['error'])
        return {key: response.get(key) for key in ('generation', 'build', 'protection', 'enforcement')}

    def installed(self):
        return pathlib.Path('/usr/local/lib/flowgate/current').exists()

    def prepare_install(self, backend, root, wine_discovery, expected_manifest=None):
        self.install_payload = snapshot_bundle(backend, expected_manifest)
        self.wine_source = (root / 'scripts/lib/configure_wine_discovery.py').read_text() if wine_discovery else None

    def authenticate(self):
        subprocess.run(['sudo', '-v'], check=True)

    def install(self, backend):
        subprocess.run(['sudo', '-n', '/usr/bin/python3', '-I', '-c', STAGE_INSTALL], input=self.install_payload, check=True)

    def configure_wine(self, root):
        subprocess.run(['sudo', '-n', '/usr/bin/python3', '-I', '-c', self.wine_source], check=True)

    def action(self, backend, selected):
        # Existing typed client binds mutations to fresh generation/protection ID.
        subprocess.run([sys.executable, str(backend / 'control.py'), 'stop' if selected == 'monitoring' else selected], check=True)

    def sleep(self):
        time.sleep(.25)

    def switch_gui(self, root, bundle):
        # Only this user's released FlowGate main processes. Snapshot start time
        # and recheck before signalling so a reused PID is never targeted.
        processes = []
        for proc in pathlib.Path('/proc').iterdir():
            if not proc.name.isdigit():
                continue
            try:
                if proc.stat().st_uid != os.getuid():
                    continue
                args = (proc / 'cmdline').read_bytes().split(b'\0')
                executable = pathlib.Path(os.fsdecode(args[0]))
                releases = root / '.workspace/automatic-zone-releases'
                if not executable.is_relative_to(releases) or executable.parts[-2:] != ('runtime', 'electron'):
                    continue
                if len(args) < 3 or args[1] != b'--ozone-platform=wayland' or os.fsdecode(args[2]) != str(executable.parent.parent / 'electron'):
                    continue
                if b'/run/flowgate-api/daemon.sock' not in args or b'/run/flowgate-api/daemon.sock.monitor' not in args:
                    continue
                start = (proc / 'stat').read_text().rsplit(')', 1)[1].split()[19]
                processes.append((proc, start))
            except (OSError, ValueError, IndexError):
                continue
        for proc, start in processes:
            try:
                fd = os.pidfd_open(int(proc.name))
                try:
                    if (proc / 'stat').read_text().rsplit(')', 1)[1].split()[19] == start:
                        signal.pidfd_send_signal(fd, signal.SIGTERM)
                finally:
                    os.close(fd)
            except (ProcessLookupError, FileNotFoundError):
                pass
        for _ in range(40):
            alive = []
            for proc, start in processes:
                try:
                    fields = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
                    if fields[19] == start and fields[0] != 'Z':
                        alive.append((proc, start))
                except FileNotFoundError:
                    pass
            if not alive:
                break
            self.sleep()
        else:
            raise RuntimeError('Old FlowGate GUI did not exit; no duplicate GUI started')
        launch = str(bundle / 'launch-ui')
        os.execv(launch, [launch, '--observer', '/run/flowgate-api/daemon.sock.monitor', '--control', '/run/flowgate-api/daemon.sock'])


def transition(host, backend, selected):
    try:
        host.action(backend, selected)
    except (OSError, subprocess.CalledProcessError):
        say('Control acknowledgement missing; checking state without replaying the action')
    for _ in range(120):
        status = host.status()
        if at_mode(status, selected):
            return status
        state = (status.get('protection') or {}).get('state')
        if state not in ('starting', 'stopping'):
            break
        host.sleep()
    raise RuntimeError('Protection did not reach ' + selected + '; inspect flowgate-control status. No action was replayed.')


def update(host, root, revision, *, dry=False, gui=True, profile="both", wine_discovery=False, recover_stopped=False):
    bundle = root / '.workspace/automatic-zone-releases' / revision
    backend = root / '.workspace/daily-releases' / revision
    manifest = None
    if not dry or (bundle / 'matched-manifest.json').exists():
        verify_bundle(bundle, 'matched-manifest.json', revision)
        manifest = verify_bundle(backend, 'manifest.json', revision)
    try:
        before = host.status()
    except OSError:
        if host.installed() and not recover_stopped:
            raise RuntimeError('Installed daemon status unavailable; use --recover-stopped for guarded monitoring-only recovery. No action taken')
        before = None
    if recover_stopped and before is None:
        profile = 'monitoring'
    previous = mode(before) if before else 'monitoring'
    selected = previous if profile == "preserve" else profile
    needs_install = wine_discovery or before is None or (not matches(before, manifest) if manifest else (before.get('build') or {}).get('source') != revision)
    if dry:
        if needs_install:
            say('Would authenticate sudo, stop protection, install and verify ' + revision)
        else:
            say('Matching daemon already running; no daemon restart needed')
        say(('Would enable generic Wine discovery; preserve valid rules; final protection mode: ' if wine_discovery else 'Would preserve existing Wine configuration and valid rules; final protection mode: ') + selected)
        if needs_install:
            say('Daemon startup would archive expired and confirmed obsolete native rules')
        if gui:
            say('Would close the old released GUI and launch ' + str(bundle / 'launch-ui'))
        return
    stopped_for_update = False
    recovery_status = None
    rollback_verified = False
    try:
        if needs_install:
            # Authenticate before interrupting a running firewall. Re-read after
            # the password prompt so user changes during authentication win.
            host.prepare_install(backend, root, wine_discovery, manifest)
            host.authenticate()
            current = host.status() if before is not None else None
            if current is not None:
                selected = mode(current) if profile == "preserve" else profile
                if not at_mode(current, 'monitoring'):
                    say('Stopping protection for the update; will restore ' + selected)
                    stopped_for_update = True
                    recovery_status = current
                    transition(host, backend, 'monitoring')
            if wine_discovery:
                host.configure_wine(root)
            try:
                host.install(backend)
            except subprocess.CalledProcessError as install_error:
                # Only the privileged installer emits 75 after restoring and
                # verifying the previous build/database pair in monitoring.
                rollback_verified = install_error.returncode == 75
                raise
            after = host.status()
            if not matches(after, manifest) or not at_mode(after, 'monitoring'):
                raise RuntimeError('Installed build/stopped-state verification failed')
        else:
            say('Matching daemon already running; no daemon restart needed')
        if needs_install or profile is not None:
            current = host.status()
            if not at_mode(current, selected):
                say('Restoring protection mode: ' + selected)
                transition(host, backend, selected)
        final = host.status()
        if not matches(final, manifest) or not at_mode(final, selected):
            raise RuntimeError('Final daemon build/protection verification failed')
        say('Update verified; protection mode: ' + selected)
    except Exception:
        if stopped_for_update:
            restored = False
            try:
                current = host.status()
                # Restore only the known original daemon: it must still own
                # its original generation and executable, or root must
                # have verified a matched executable/database rollback (exit 75).
                original_build = recovery_status.get('build') if recovery_status else None
                same_build = bool(original_build) and current.get('build') == original_build
                same_generation = recovery_status and current.get('generation') == recovery_status.get('generation')
                if same_build and current.get('generation') and (same_generation or rollback_verified) and at_mode(current, 'monitoring'):
                    transition(host, backend, mode(recovery_status))
                    restored = True
            except Exception as recovery_error:
                say('Previous protection could not be restored: ' + str(recovery_error))
            if restored:
                say('Update failed; previous daemon verified and its original protection mode restored.')
            else:
                say('Update incomplete; protection may remain OFF across reboot. Previous daemon could not be verified/restored. Use --recover-stopped for monitoring-only recovery, then explicitly start protection.')
        raise
    if gui:
        say('Switching to the matching GUI')
        host.switch_gui(root, bundle)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=pathlib.Path, required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--no-gui', action='store_true')
    parser.add_argument('--wine-discovery', action='store_true')
    parser.add_argument('--recover-stopped', action='store_true')
    parser.add_argument('--profile', choices=('preserve', 'monitoring', 'incoming', 'both'), default='both')
    args = parser.parse_args()
    try:
        update(Host(), args.root.resolve(), args.revision, dry=args.dry_run, gui=not args.no_gui, profile=args.profile, wine_discovery=args.wine_discovery, recover_stopped=args.recover_stopped)
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        if isinstance(error, subprocess.CalledProcessError):
            sys.exit('Update failed: command exited ' + str(error.returncode) + '; see verification/recovery status above')
        sys.exit('Update failed: ' + str(error))

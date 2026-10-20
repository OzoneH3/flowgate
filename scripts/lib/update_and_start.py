#!/usr/bin/env python3
"""One-command update orchestration. The installer remains monitoring-only."""
import argparse
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

    def authenticate(self):
        subprocess.run(['sudo', '-v'], check=True)

    def install(self, backend):
        subprocess.run(['sudo', '-n', sys.executable, str(backend / 'install-monitoring.py'), '--bundle', str(backend)], check=True)

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


def update(host, root, revision, *, dry=False, gui=True, profile="both"):
    bundle = root / '.workspace/automatic-zone-releases' / revision
    backend = root / '.workspace/daily-releases' / revision
    manifest = None
    if not dry or (bundle / 'matched-manifest.json').exists():
        verify_bundle(bundle, 'matched-manifest.json', revision)
        manifest = verify_bundle(backend, 'manifest.json', revision)
    try:
        before = host.status()
    except OSError:
        if host.installed():
            raise RuntimeError('Installed daemon status unavailable; no protection or installation action taken')
        before = None
    previous = mode(before) if before else 'monitoring'
    selected = previous if profile == "preserve" else profile
    needs_install = before is None or (not matches(before, manifest) if manifest else before.get('build', {}).get('source') != revision)
    if dry:
        if needs_install:
            say('Would authenticate sudo, stop protection, install and verify ' + revision)
        else:
            say('Matching daemon already running; no daemon restart needed')
        say('Would preserve existing Wine configuration and stored rules; final protection mode: ' + selected)
        if gui:
            say('Would close the old released GUI and launch ' + str(bundle / 'launch-ui'))
        return
    stopped_for_update = False
    try:
        if needs_install:
            # Authenticate before interrupting a running firewall. Re-read after
            # the password prompt so user changes during authentication win.
            host.authenticate()
            current = host.status() if before is not None else None
            if current is not None:
                selected = mode(current) if profile == "preserve" else profile
                if not at_mode(current, 'monitoring'):
                    say('Stopping protection for the update; will restore ' + selected)
                    stopped_for_update = True
                    transition(host, backend, 'monitoring')
            host.install(backend)
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
            say('Update incomplete after requesting a protection stop. No automatic installation or activation retry; inspect flowgate-control status.')
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
    parser.add_argument('--profile', choices=('preserve', 'monitoring', 'incoming', 'both'), default='both')
    args = parser.parse_args()
    try:
        update(Host(), args.root.resolve(), args.revision, dry=args.dry_run, gui=not args.no_gui, profile=args.profile)
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        sys.exit('Update failed: ' + str(error))

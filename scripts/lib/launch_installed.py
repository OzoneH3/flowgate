#!/usr/bin/env python3
"""Launch the installed approved GUI without updating or touching the daemon."""
import argparse
import fcntl
import os
import pathlib
import sys
from update_and_start import Host, check_release_approval, released_gui, start_time, verify_bundle


def select_bundle(root, status):
    build = status.get('build') if isinstance(status, dict) else None
    if not isinstance(build, dict):
        raise RuntimeError('Installed build identity is unavailable')
    revision = build.get('source', '')
    if not isinstance(revision, str) or len(revision) != 40 or any(c not in '0123456789abcdef' for c in revision) or build.get('modified') is not False:
        raise RuntimeError('Installed release identity is unavailable or modified; no GUI started')
    check_release_approval(root, revision)
    bundle = root / '.workspace/automatic-zone-releases' / revision
    try:
        verify_bundle(bundle, 'matched-manifest.json', revision)
    except (KeyError, TypeError, AttributeError) as exc:
        raise RuntimeError('Malformed GUI manifest; no GUI started') from exc
    return bundle.resolve()


def launch(root, host, dry=False):
    workspace = root / '.workspace'
    workspace.mkdir(exist_ok=True)
    with (workspace / 'launch-installed.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        before = host.status()
        bundle = select_bundle(root, before)
        processes = []
        releases = (workspace / 'automatic-zone-releases').resolve()
        for proc in pathlib.Path('/proc').iterdir():
            if not proc.name.isdigit():
                continue
            try:
                stamp = start_time(proc)
                if released_gui(proc, releases) and start_time(proc) == stamp:
                    processes.append(pathlib.Path(os.readlink(proc / 'exe')).parent.parent)
            except (OSError, ValueError, IndexError):
                continue
        current = host.status()
        if current.get('generation') != before.get('generation') or current.get('build') != before.get('build'):
            raise RuntimeError('Daemon changed while checking the launcher; retry')
        if dry:
            print("Would reuse/launch installed GUI: " + str(bundle / "launch-ui") + "; no update or daemon restart")
            return
        if processes == [bundle]:
            print('FlowGate GUI already running for ' + bundle.name + '; use its tray icon')
            return
        host.switch_gui(root, bundle)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    try:
        launch(pathlib.Path(__file__).resolve().parents[2], Host(), args.dry_run)
    except (OSError, ValueError, RuntimeError) as exc:
        sys.exit('Launch refused: ' + str(exc) + '. Use --update only to explicitly request the approved pinned update.')

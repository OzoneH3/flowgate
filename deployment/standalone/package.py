#!/usr/bin/env python3
"""Create a curated offline package from make build output."""
import datetime
import fcntl
import gzip
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / 'build/standalone-build'
SHA256SUM = '/usr/bin/sha256sum'


def digest(path):
    with path.open('rb') as file:
        return subprocess.check_output([SHA256SUM], stdin=file).split()[0].decode('ascii')


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def receipt(path):
    return f'{digest(path)}  {path.name}\n'


def source_bytes(identity, path):
    return subprocess.check_output(['git', 'show', f"{identity['source']}:{path}"], cwd=ROOT)


def write_archive(archive, staging, epoch):
    def normalize(member):
        member.uid = member.gid = 0
        member.uname = member.gname = ''
        member.mtime = epoch
        if member.isdir():
            member.mode = 0o755
        return member

    # An explicit empty gzip filename keeps the staging name out of the header.
    with archive.open('wb') as file:
        with gzip.GzipFile(filename='', fileobj=file, mode='wb', compresslevel=3, mtime=epoch) as compressed:
            with tarfile.open(fileobj=compressed, mode='w', format=tarfile.PAX_FORMAT) as stream:
                for path in ('release.json', 'backend', 'gui'):
                    stream.add(staging / path, arcname=path, filter=normalize)


def verify_retained(output, identity):
    bootstrap = output.with_name('flowgate-release.py')
    for path in (output, bootstrap):
        if path.with_suffix(path.suffix + '.sha256').read_text() != receipt(path):
            raise RuntimeError(f'Retained receipt does not match {path}')
    with tarfile.open(output, 'r:gz') as stream:
        manifest = json.load(stream.extractfile('release.json'))
    if manifest['schema'] != 2 or any(manifest[key] != value for key, value in identity.items()):
        raise RuntimeError(f'Retained archive has a different build identity: {output}')
    if bootstrap.read_bytes() != source_bytes(identity, 'deployment/standalone/release.py'):
        raise RuntimeError(f'Retained installer differs from this source: {bootstrap}')


def pack(identity, output):
    if json.loads((BUILD / 'identity.json').read_text()) != identity:
        raise RuntimeError('Build and clean source identity must match. Run make build again.')
    if output.parent.exists() or output.parent.is_symlink():
        verify_retained(output, identity)
        return
    epoch = int(subprocess.check_output(['git', 'show', '-s', '--format=%ct', identity['source']], cwd=ROOT))
    output.parent.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=output.parent.parent) as folder:
        staging = Path(folder) / 'payload'
        artifacts = Path(folder) / 'artifacts'
        artifacts.mkdir()
        backend = staging / 'backend'
        gui = staging / 'gui'
        backend.mkdir(parents=True)
        (gui / 'electron').mkdir(parents=True)
        files = {
            'flowgate': BUILD / 'flowgate',
            'holder-iterator': BUILD / 'holder-iterator',
            'tcp-initiation': BUILD / 'tcp-initiation-collector',
            'udp-collector': BUILD / 'udp-collector',
            'wine-owner-observer.exe': BUILD / 'table-probe.exe',
            'flowgate.png': BUILD / 'electron/dist/flowgate.png',
        }
        for name in ('kernel', 'probe', 'controller.py', 'classify.bpf.o'):
            files[name] = BUILD / 'shaping' / name
        for name, path in files.items():
            shutil.copyfile(path, backend / name)
        sources = {
            'launch': 'deployment/launch',
            'control.py': 'deployment/control.py',
            'install-monitoring.py': 'scripts/install-monitoring.py',
            'recover.py': 'deployment/standalone/recover',
            'uninstall.py': 'deployment/standalone/uninstall',
        }
        for name in ('release.py', 'flowgate-ui', 'flowgate.desktop'):
            sources[name] = f'deployment/standalone/{name}'
        for name in ('flowgate.service', 'flowgate-guard.service', '50-flowgate-guard.conf'):
            sources[name] = f'deployment/systemd/{name}'
        for name, path in sources.items():
            (backend / name).write_bytes(source_bytes(identity, path))
        executables = [
            'flowgate', 'launch', 'holder-iterator', 'tcp-initiation', 'udp-collector',
            'control.py', 'recover.py', 'uninstall.py', 'release.py', 'flowgate-ui',
            'kernel', 'probe',
        ]
        for name in executables:
            (backend / name).chmod(0o755)
        write_json(backend / 'standalone-release.json', identity)
        # The legacy field gates reuse of the monitoring installer. The standalone
        # manifest records its own test scope separately.
        build = json.loads(subprocess.check_output([str(backend / 'flowgate'), 'version']))
        if (any(build.get(key) != identity[key] for key in ('version', 'source')) or
            build.get('holder_iterator_sha256') != digest(backend / 'holder-iterator') or
            build.get('udp_collector_sha256') != digest(backend / 'udp-collector')):
            raise RuntimeError('Daemon or collector build does not match the payload')
        write_json(backend / 'manifest.json', {
            **identity, 'max_rule_schema': build['max_rule_schema'],
            'isolated_passed': False, 'executables': executables,
            'state_compatibility': 'flowgate-rules-and-settings-v1',
            'files': {p.name: digest(p) for p in sorted(backend.iterdir())},
        })
        electron = BUILD / 'electron'
        shutil.copytree(electron / 'dist', gui / 'electron/dist')
        app = json.loads((electron / 'package.json').read_text())
        runtime = electron / 'node_modules/electron/dist'
        if (runtime / 'version').read_text().strip() != app['devDependencies']['electron']:
            raise RuntimeError('Packaged Electron runtime does not match the desktop pin')
        app['version'] = identity['version']
        write_json(gui / 'electron/package.json', app)
        shutil.copytree(runtime, gui / 'runtime')
        (gui / 'fontconfig_isolation.py').write_bytes(source_bytes(identity, 'electron/fontconfig_isolation.py'))
        shutil.copy2(backend / 'flowgate-ui', gui / 'flowgate-ui')
        write_json(gui / 'matched-manifest.json', {
            **identity,
            'built_at': datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).isoformat(),
            'files': {str(p.relative_to(gui)): digest(p) for p in (gui / 'electron').rglob('*') if p.is_file()},
        })
        for path in staging.rglob('*'):
            if path.is_symlink():
                raise RuntimeError(f'Symlink in release payload: {path}')
            if path.is_file():
                path.chmod(0o755 if path.stat().st_mode & 0o111 else 0o644)
        manifest = {
            **identity, 'schema': 2, 'platform': 'linux-x86_64',
            'files': {
                str(p.relative_to(staging)): {'sha256': digest(p), 'mode': stat.S_IMODE(p.stat().st_mode)}
                for p in sorted(staging.rglob('*')) if p.is_file()
            },
        }
        write_json(staging / 'release.json', manifest)
        # Standalone installation uses the exact externally pinned archive.
        # The separate bootstrap is for the first install on machines without the tool.
        archive = artifacts / output.name
        write_archive(archive, staging, epoch)
        bootstrap = artifacts / 'flowgate-release.py'
        shutil.copyfile(backend / 'release.py', bootstrap)
        for path in (archive, bootstrap):
            path.with_suffix(path.suffix + '.sha256').write_text(receipt(path))
        # Publish the archive, installer and receipts together. If a concurrent
        # build wins, retain and check its already published files.
        try:
            artifacts.rename(output.parent)
        except OSError:
            if not output.parent.is_dir():
                raise
            verify_retained(output, identity)


if __name__ == '__main__':
    if sys.version_info < (3, 9):
        raise SystemExit('FlowGate packaging requires Python 3.9 or newer.')
    if not os.access(SHA256SUM, os.X_OK):
        raise SystemExit(f'FlowGate packaging requires {SHA256SUM}.')
    from identity import archive_path, source_identity

    if len(sys.argv) != 1:
        raise SystemExit('Use make package from the chosen commit or release tag; the archive name is derived from its identity.')
    try:
        identity = source_identity(require_clean=True)
        output = archive_path(identity)
        with (BUILD.parent / '.standalone.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_SH)
            pack(identity, output)
        print(output)
    except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError) as error:
        raise SystemExit(f'FlowGate: {error}') from None

#!/usr/bin/env python3
"""Create a curated offline package from make build output."""
import datetime
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
HERE = ROOT / 'deployment/standalone'
BUILD = ROOT / 'build/standalone-build'
SHA256SUM = '/usr/bin/sha256sum'


def digest(path):
    with path.open('rb') as file:
        return subprocess.check_output([SHA256SUM], stdin=file).split()[0].decode('ascii')


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def receipt(path):
    return f'{digest(path)}  {path.name}\n'


def verify_retained(output, identity):
    bootstrap = output.with_name('flowgate-release.py')
    for path in (output, bootstrap):
        if path.with_suffix(path.suffix + '.sha256').read_text() != receipt(path):
            raise RuntimeError(f'Retained receipt does not match {path}')
    with tarfile.open(output, 'r:gz') as stream:
        manifest = json.load(stream.extractfile('release.json'))
    if manifest['schema'] != 2 or any(manifest[key] != value for key, value in identity.items()):
        raise RuntimeError(f'Retained archive has a different build identity: {output}')
    if bootstrap.read_bytes() != (HERE / 'release.py').read_bytes():
        raise RuntimeError(f'Retained installer differs from this source: {bootstrap}')


def pack(identity, output):
    if json.loads((BUILD / 'identity.json').read_text()) != identity:
        raise RuntimeError('Build and clean source identity must match. Run make build again.')
    if output.parent.exists() or output.parent.is_symlink():
        verify_retained(output, identity)
        return
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
            'holder-iterator': ROOT / 'build/holder-iterator',
            'tcp-initiation': ROOT / 'build/tcp-initiation-collector',
            'udp-collector': ROOT / 'build/udp-collector',
            'wine-owner-observer.exe': ROOT / 'build/windows/table-probe.exe',
            'launch': ROOT / 'deployment/launch',
            'control.py': ROOT / 'deployment/control.py',
            'recover.py': HERE / 'recover',
            'uninstall.py': HERE / 'uninstall',
            'release.py': HERE / 'release.py',
            'flowgate-ui': HERE / 'flowgate-ui',
            'flowgate.desktop': HERE / 'flowgate.desktop',
            'flowgate.png': BUILD / 'electron/dist/flowgate.png',
            'install-monitoring.py': ROOT / 'scripts/install-monitoring.py',
        }
        for name in ('kernel', 'probe', 'controller.py', 'classify.bpf.o'):
            files[name] = BUILD / 'shaping' / name
        for name in ('flowgate.service', 'flowgate-guard.service', '50-flowgate-guard.conf'):
            files[name] = ROOT / 'deployment/systemd' / name
        for name, path in files.items():
            shutil.copyfile(path, backend / name)
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
        shutil.copyfile(ROOT / 'electron/fontconfig_isolation.py', gui / 'fontconfig_isolation.py')
        shutil.copy2(HERE / 'flowgate-ui', gui / 'flowgate-ui')
        write_json(gui / 'matched-manifest.json', {
            **identity,
            'built_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
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
        with tarfile.open(archive, 'w:gz', compresslevel=3) as stream:
            for path in ('release.json', 'backend', 'gui'):
                stream.add(staging / path, arcname=path)
        bootstrap = artifacts / 'flowgate-release.py'
        shutil.copyfile(HERE / 'release.py', bootstrap)
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
        pack(identity, output)
        print(output)
    except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError) as error:
        raise SystemExit(f'FlowGate: {error}') from None

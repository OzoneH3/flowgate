#!/usr/bin/env python3
"""Create a curated offline package from make build output."""
import datetime
import hashlib
import json
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[2]
HERE = ROOT / 'deployment/standalone'
BUILD = ROOT / '.workspace/standalone-build'


def digest(path):
    with path.open('rb') as file:
        return hashlib.file_digest(file, 'sha256').hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def pack(version, output):
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9]+(?:\.[a-zA-Z0-9]+)*)?', version):
        raise ValueError('Invalid release version')
    source = (BUILD / 'source').read_text().strip()
    revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    if source != revision or subprocess.check_output(
        ['git', 'status', '--porcelain', '--untracked-files=no'], cwd=ROOT, text=True,
    ):
        raise RuntimeError('Build and clean source commit must match')
    release = f'{version}-{revision[:12]}'
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=output.parent) as folder:
        staging = Path(folder)
        backend = staging / 'backend'
        gui = staging / 'gui'
        backend.mkdir()
        (gui / 'electron').mkdir(parents=True)
        files = {
            'flowgate': BUILD / 'flowgate',
            'holder-iterator': ROOT / '.workspace/holder-iterator',
            'tcp-initiation': ROOT / '.workspace/tcp-initiation-collector',
            'udp-collector': ROOT / '.workspace/udp-collector',
            'wine-owner-observer.exe': ROOT / '.workspace/windows/table-probe.exe',
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
        write_json(backend / 'standalone-release.json', {'version': version, 'source': source})
        # The legacy field gates reuse of the monitoring installer. The standalone
        # manifest records its own test scope separately.
        build = json.loads(subprocess.check_output([str(backend / 'flowgate'), 'version']))
        if build.get('source') != source or build.get('holder_iterator_sha256') != digest(backend / 'holder-iterator'):
            raise RuntimeError('Daemon or collector build does not match the payload')
        write_json(backend / 'manifest.json', {
            'release': release, 'source': source, 'max_rule_schema': build['max_rule_schema'],
            'isolated_passed': False, 'executables': executables,
            'files': {p.name: digest(p) for p in sorted(backend.iterdir())},
        })
        electron = BUILD / 'electron'
        shutil.copytree(electron / 'dist', gui / 'electron/dist')
        shutil.copyfile(electron / 'package.json', gui / 'electron/package.json')
        shutil.copytree(electron / 'node_modules/electron/dist', gui / 'runtime')
        shutil.copyfile(ROOT / 'electron/fontconfig_isolation.py', gui / 'fontconfig_isolation.py')
        shutil.copy2(HERE / 'flowgate-ui', gui / 'flowgate-ui')
        write_json(gui / 'matched-manifest.json', {
            'source': source, 'version': version,
            'built_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'files': {str(p.relative_to(gui)): digest(p) for p in (gui / 'electron').rglob('*') if p.is_file()},
        })
        for path in staging.rglob('*'):
            if path.is_symlink():
                raise RuntimeError(f'Symlink in release payload: {path}')
            if path.is_file():
                path.chmod(0o755 if path.stat().st_mode & 0o111 else 0o644)
        manifest = {
            'schema': 1, 'platform': 'linux-x86_64', 'release': release,
            'version': version, 'source': source,
            'files': {
                str(p.relative_to(staging)): {'sha256': digest(p), 'mode': stat.S_IMODE(p.stat().st_mode)}
                for p in sorted(staging.rglob('*')) if p.is_file()
            },
        }
        write_json(staging / 'release.json', manifest)
        # Standalone installation uses the exact externally pinned archive.
        # The separate bootstrap is for the first install on machines without the tool.
        archive = staging / 'package.tar.gz'
        with tarfile.open(archive, 'w:gz', compresslevel=3) as stream:
            for path in ('release.json', 'backend', 'gui'):
                stream.add(staging / path, arcname=path)
        archive.replace(output)
    bootstrap = output.parent / 'flowgate-release.py'
    shutil.copyfile(HERE / 'release.py', bootstrap)
    output.with_suffix(output.suffix + '.sha256').write_text(f'{digest(output)}  {output.name}\n')
    (output.parent / 'flowgate-release.py.sha256').write_text(f'{digest(bootstrap)}  {bootstrap.name}\n')
    print(output)


if __name__ == '__main__':
    pack(sys.argv[1], Path(sys.argv[2]).resolve())

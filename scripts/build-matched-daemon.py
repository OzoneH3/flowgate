#!/usr/bin/env python3
"""Build a daemon with the exact native helpers it will ship beside.

No install or kernel load. The same entry point supports ordinary and
socketprototype releases so custom release builds cannot omit the loader pin.
"""
import argparse
import hashlib
import pathlib
import re
import subprocess


def helper_digest(path):
    if not path.is_file() or not 0 < path.stat().st_size <= 32 * 1024 * 1024:
        raise ValueError(f'Native helper must be a nonempty file within 32 MiB: {path}')
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(output, loader, revision, tags='', version='', udp_helper=None):
    if not re.fullmatch(r'[0-9a-f]{40}', revision):
        raise ValueError('source revision must be a full commit hash')
    if tags not in ('', 'socketprototype'):
        raise ValueError('unsupported release build tags')
    if version and not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?', version):
        raise ValueError('invalid release version')
    helpers = {'holderIteratorSHA256': pathlib.Path(loader).resolve(strict=True)}
    if udp_helper is not None:
        helpers['udpCollectorSHA256'] = pathlib.Path(udp_helper).resolve(strict=True)
    digests = {name: helper_digest(path) for name, path in helpers.items()}
    command = ['go', 'build', '-trimpath', '-buildvcs=false']
    if tags:
        command += ['-tags', tags]
    flags = f'-X main.sourceRevision={revision}'
    flags += ''.join(f' -X main.{name}={digest}' for name, digest in digests.items())
    if version:
        flags += f' -X main.releaseVersion={version}'
    command += ['-ldflags', flags,
                '-o', str(output), './cmd/flowgate']
    subprocess.run(command, check=True)
    if any(helper_digest(path) != digests[name] for name, path in helpers.items()):
        pathlib.Path(output).unlink(missing_ok=True)
        raise RuntimeError('Native helper changed during build; discarded daemon')
    return digests['holderIteratorSHA256']


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', required=True)
    p.add_argument('--loader', required=True)
    p.add_argument('--revision', required=True)
    p.add_argument('--tags', default='')
    p.add_argument('--version', default='')
    p.add_argument('--udp-helper')
    a = p.parse_args()
    print('Matched iterator SHA256:', build(a.output, a.loader, a.revision, a.tags, a.version, a.udp_helper))


if __name__ == '__main__':
    main()

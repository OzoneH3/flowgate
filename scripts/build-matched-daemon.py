#!/usr/bin/env python3
"""Build a daemon with the exact optional iterator it will ship beside.

No install or kernel load. The same entry point supports ordinary and
socketprototype releases so custom release builds cannot omit the loader pin.
"""
import argparse
import hashlib
import pathlib
import re
import subprocess


def build(output, loader, revision, tags=''):
    if not re.fullmatch(r'[0-9a-f]{40}', revision):
        raise ValueError('source revision must be a full commit hash')
    if tags not in ('', 'socketprototype'):
        raise ValueError('unsupported release build tags')
    loader = pathlib.Path(loader).resolve(strict=True)
    if not loader.is_file() or not 0 < loader.stat().st_size <= 32 * 1024 * 1024:
        raise ValueError('iterator loader must be a nonempty file within 32 MiB')
    digest = hashlib.sha256(loader.read_bytes()).hexdigest()
    command = ['go', 'build', '-trimpath', '-buildvcs=false']
    if tags:
        command += ['-tags', tags]
    command += ['-ldflags', f'-X main.sourceRevision={revision} -X main.holderIteratorSHA256={digest}',
                '-o', str(output), './cmd/flowgate']
    subprocess.run(command, check=True)
    if hashlib.sha256(loader.read_bytes()).hexdigest() != digest:
        pathlib.Path(output).unlink(missing_ok=True)
        raise RuntimeError('iterator loader changed during build; discarded daemon')
    return digest


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', required=True)
    p.add_argument('--loader', required=True)
    p.add_argument('--revision', required=True)
    p.add_argument('--tags', default='')
    a = p.parse_args()
    print('Matched iterator SHA256:', build(a.output, a.loader, a.revision, a.tags))


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Resolve the version and provenance used by a standalone build."""
import argparse
import json
from pathlib import Path
import re
import subprocess

from release import release_id

ROOT = Path(__file__).resolve().parents[2]
TAG_PREFIX = 'flowgate-v'
RELEASE_VERSION = re.compile(r'[0-9]+\.[0-9]+\.[0-9]+(?:-rc\.[0-9]+)?')


def source_identity(root=ROOT, *, require_clean=False):
    def git(*args):
        return subprocess.run(['git', *args], cwd=root, check=True, text=True,
                              capture_output=True).stdout.strip()

    # In particular, do not borrow the enclosing repository's HEAD when a source
    # tarball is extracted beneath another checkout.
    if not (root / '.git').exists() or Path(git('rev-parse', '--show-toplevel')).resolve() != root.resolve():
        raise RuntimeError('Source archive has no Git provenance. Build from a clean Git clone at the desired commit; fetch the FlowGate tags, or use the verified binary package.')
    if require_clean and git('status', '--porcelain', '--untracked-files=no'):
        raise RuntimeError('Commit or restore tracked changes before building a package.')
    source = git('rev-parse', 'HEAD')
    tags = git('tag', '--list', TAG_PREFIX + '*', '--points-at', source).splitlines()
    if len(tags) > 1:
        raise RuntimeError('Multiple FlowGate release tags point to this commit: ' + ', '.join(tags))
    exact = bool(tags)
    tag = tags[0] if exact else git('describe', '--tags', '--first-parent', '--match',
                                      TAG_PREFIX + '*', '--abbrev=0', '--always', source)
    if tag.startswith(TAG_PREFIX):
        base = tag[len(TAG_PREFIX):]
        if not RELEASE_VERSION.fullmatch(base):
            raise RuntimeError(f'Invalid FlowGate release tag {tag}; use {TAG_PREFIX}X.Y.Z or {TAG_PREFIX}X.Y.Z-rc.N.')
    else:
        base = json.loads((root / 'electron/package.json').read_text())['version']
        if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', base):
            raise RuntimeError('The Electron package needs a numeric X.Y.Z baseline before the first FlowGate tag.')
    version = base if exact else base + ('.dev-' if '-' in base else '-dev-') + source[:12]
    release = release_id(version, source)
    return {'version': version, 'source': source, 'release': release}


def archive_path(identity, root=ROOT):
    release = identity['release']
    return root / 'build/dist' / release / f'flowgate-{release}-linux-x86_64.tar.gz'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--require-clean', action='store_true')
    parser.add_argument('--field', choices=('version', 'source', 'release', 'archive'))
    args = parser.parse_args()
    try:
        identity = source_identity(require_clean=args.require_clean)
        if args.field == 'archive':
            print(archive_path(identity))
        else:
            print(identity[args.field] if args.field else json.dumps(identity))
    except (OSError, RuntimeError, subprocess.CalledProcessError, ValueError) as error:
        parser.exit(1, f'FlowGate: {error}\n')


if __name__ == '__main__':
    main()

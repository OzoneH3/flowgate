#!/usr/bin/env python3
"""Private Fontconfig configuration for Electron's bundled Fontconfig.

Electron/Chromium ship their own Fontconfig. With the system configuration it
reads the host's cache directories, which a newer system Fontconfig writes, and
then warns that it will not regenerate them. Sharing one cache between two
Fontconfig versions is the problem, so this derives a configuration with the
same font directories and rules, but with every cache directory replaced by one
private cache per Electron runtime version. Host caches are never modified.

An explicit FONTCONFIG_FILE or FONTCONFIG_PATH set by the user is respected.
"""
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import xml.etree.ElementTree as ET

SYSTEM_CONFIG = Path('/etc/fonts/fonts.conf')


def _absolute(base, value):
    if not value or value.startswith(('/', '~')):
        return value
    return str((base / value).resolve())


def _included_cachedirs(config, seen=None, limit=256):
    """Cache directories that included files would add back (reported, not hidden)."""
    seen = set() if seen is None else seen
    found = []
    try:
        root = ET.parse(config).getroot()
    except (OSError, ET.ParseError):
        return found
    for element in root.iter('include'):
        if element.get('prefix') or len(seen) >= limit:
            continue
        target = Path(os.path.expanduser(_absolute(config.parent, (element.text or '').strip())))
        candidates = sorted(p for p in target.iterdir() if p.suffix == '.conf') if target.is_dir() else [target]
        for path in candidates:
            if path in seen or not path.is_file():
                continue
            seen.add(path)
            try:
                if any(True for _ in ET.parse(path).getroot().iter('cachedir')):
                    found.append(str(path))
            except (OSError, ET.ParseError):
                continue
            found.extend(_included_cachedirs(path, seen, limit))
    return found


def private_config(cache_home, runtime_version, source=None):
    """Write the private configuration and return its path, or None if not applicable."""
    source = SYSTEM_CONFIG if source is None else source
    if not source.is_file():
        return None
    tree = ET.parse(source)
    root = tree.getroot()
    for parent in list(root.iter()):
        for child in list(parent):
            if child.tag == 'cachedir':
                parent.remove(child)
            elif child.tag in ('include', 'dir') and not child.get('prefix'):
                child.text = _absolute(source.parent, (child.text or '').strip())
    version = ''.join(c if c.isalnum() or c in '.-_' else '_' for c in runtime_version)
    if version in ('', '.', '..'):
        version = 'unknown'  # never a path component that leaves the private cache root
    directory = Path(cache_home) / 'flowgate-fontconfig' / version
    cache = directory / 'cache'
    cache.mkdir(mode=0o700, parents=True, exist_ok=True)
    element = ET.SubElement(root, 'cachedir')
    element.text = str(cache)
    data = b'<?xml version="1.0"?>\n<!DOCTYPE fontconfig SYSTEM "urn:fontconfig:fonts.dtd">\n' + ET.tostring(root)
    target = directory / ('fonts-' + hashlib.sha256(data).hexdigest()[:16] + '.conf')
    if not target.exists() or target.read_bytes() != data:
        with tempfile.NamedTemporaryFile(dir=directory, delete=False) as handle:
            handle.write(data)
        os.replace(handle.name, target)
    return target


def apply(env, cache_home, runtime_version, log=sys.stderr):
    """Set FONTCONFIG_FILE in env unless the user chose a configuration."""
    if env.get('FONTCONFIG_FILE') or env.get('FONTCONFIG_PATH'):
        print('Fontconfig: keeping user-selected configuration', file=log)
        return None
    try:
        target = private_config(cache_home, runtime_version)
    except (OSError, ET.ParseError) as error:
        print('Fontconfig: private configuration unavailable (%s); using system configuration' % error, file=log)
        return None
    if target is None:
        return None
    try:  # diagnostic only: never fatal to the launcher
        readded = _included_cachedirs(SYSTEM_CONFIG)
    except (OSError, ValueError, RecursionError) as error:
        readded = []
        print('Fontconfig: included configuration not inspected (%s)' % error, file=log)
    if readded:
        print('Fontconfig: included configuration also declares cache directories: ' + ', '.join(readded), file=log)
    env['FONTCONFIG_FILE'] = str(target)
    return target


def runtime_version(dist):
    try:
        return Path(dist, 'version').read_text().strip()
    except OSError:
        return 'unknown'


if __name__ == '__main__':
    # Shell launchers: print the configuration path (empty when not applicable).
    if len(sys.argv) != 3:
        raise SystemExit('usage: fontconfig_isolation.py CACHE_HOME ELECTRON_DIST')
    env = dict(os.environ)
    path = apply(env, sys.argv[1], runtime_version(sys.argv[2]))
    print(path or '')

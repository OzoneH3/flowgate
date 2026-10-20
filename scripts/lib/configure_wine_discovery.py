#!/usr/bin/env python3
"""Explicit --wine-discovery update step; backs up the former observer restriction."""
import hashlib
import json
import os
import pathlib


def configure(directory):
    config = directory / 'wine.json'
    if config.is_symlink():
        raise RuntimeError('Refusing symlink Wine configuration')
    if config.exists():
        st = config.stat()
        if st.st_uid != 0 or st.st_mode & 0o022 or st.st_size > 65536:
            raise RuntimeError('Unsafe Wine observer configuration')
        old = config.read_bytes()
        if json.loads(old) == {'schema': 1, 'mode': 'discover'}:
            return
        backup = directory / ('wine.json.before-discovery-' + hashlib.sha256(old).hexdigest())
        try:
            with backup.open('xb') as f:
                os.fchmod(f.fileno(), 0o600)
                f.write(old)
                f.flush()
                os.fsync(f.fileno())
        except FileExistsError:
            if backup.is_symlink() or backup.read_bytes() != old:
                raise RuntimeError('Wine configuration backup mismatch')
    directory.mkdir(mode=0o755, parents=True, exist_ok=True)
    tmp = directory / ('wine.json.discovery-' + str(os.getpid()))
    try:
        with tmp.open('xb') as f:
            os.fchmod(f.fileno(), 0o644)
            f.write(b'{"schema":1,"mode":"discover"}\n')
            f.flush()
            os.fsync(f.fileno())
        tmp.replace(config)
    finally:
        tmp.unlink(missing_ok=True)


if __name__ == '__main__':
    if os.geteuid() != 0:
        raise SystemExit('Root required; invoke through update-and-start --wine-discovery')
    configure(pathlib.Path('/etc/flowgate'))

#!/usr/bin/env python3
"""Install a selected local bundle in monitoring mode through isolated staging."""
import argparse
import pathlib
import subprocess
import sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent / 'lib'))
from update_and_start import Host

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', required=True, type=pathlib.Path)
    args = parser.parse_args()
    host = Host()
    host.prepare_install(args.bundle.resolve(), pathlib.Path.cwd(), False)
    host.authenticate()
    try:
        host.install(args.bundle)
    except subprocess.CalledProcessError as error:
        sys.exit('Installation failed: command exited ' + str(error.returncode) + '; see verification/recovery status above')

#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
export PYTHONDONTWRITEBYTECODE=1
export XDG_CACHE_HOME="$PWD/.workspace/cache" TMPDIR="$PWD/.workspace/tmp"
if [ "${1:-}" = "--help" ]; then
  exec python3 electron/launch.py --help
fi
scripts/build-electron.sh
exec python3 electron/launch.py "$@"

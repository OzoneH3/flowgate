#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
export PYTHONDONTWRITEBYTECODE=1
export XDG_CACHE_HOME="$PWD/build/cache" TMPDIR="$PWD/build/tmp"
if [ "${1:-}" = "--help" ]; then
  exec python3 electron/launch.py --help
fi
scripts/build.sh electron
exec python3 electron/launch.py "$@"

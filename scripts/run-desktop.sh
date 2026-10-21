#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
. ./scripts/go-env.sh
export PYTHONDONTWRITEBYTECODE=1 XDG_CACHE_HOME="$PWD/.workspace/desktop-cache"
scripts/build.sh desktop
exec python3 scripts/run-desktop.py "$@"

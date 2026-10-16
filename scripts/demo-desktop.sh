#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
. ./scripts/go-env.sh
export PYTHONDONTWRITEBYTECODE=1 XDG_CACHE_HOME="$PWD/.workspace/desktop-cache"
scripts/build-desktop.sh
exec python3 scripts/demo-desktop.py

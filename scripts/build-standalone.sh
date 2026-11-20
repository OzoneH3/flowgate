#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
. ./scripts/go-env.sh
export npm_config_cache="$PWD/build/npm-cache"
export electron_config_cache="$PWD/build/electron-cache"
export XDG_CACHE_HOME="$PWD/build/cache"
export PYTHONDONTWRITEBYTECODE=1
umask 022

test -z "$(git status --porcelain --untracked-files=no)" || {
  echo 'Commit tracked changes before building a release.' >&2
  exit 1
}
python3 -B -c 'import sys; sys.version_info >= (3, 9) or sys.exit("FlowGate requires Python 3.9 or newer.")'
test -x /usr/bin/sha256sum || { echo 'FlowGate requires /usr/bin/sha256sum.' >&2; exit 1; }
revision=$(git rev-parse HEAD)
stage="$PWD/build/standalone-build"
mkdir -p "$stage/electron" "$TMPDIR" "$XDG_CACHE_HOME"

# Copy the committed Electron source to an isolated build directory.
git archive "$revision" electron | tar -x -C "$stage"
if [ ! -d "$stage/electron/node_modules" ]; then
  ELECTRON_SKIP_BINARY_DOWNLOAD=1 npm --prefix "$stage/electron" ci
fi
node "$stage/electron/node_modules/electron/install.js"
if [ ! -x "$stage/electron/node_modules/electron/dist/electron" ]; then
  echo 'The Electron runtime installer did not produce a runnable Linux binary.' >&2
  exit 1
fi
npm --prefix "$stage/electron" run build
scripts/build-socket-authorization.sh
scripts/build.sh holder-iterator tcp-initiation udp wine-table
experimental/upload-shaper/build.sh "$stage/shaping"
python3 -B scripts/build-matched-daemon.py --revision "$revision" \
  --loader build/holder-iterator --tags socketprototype --output "$stage/flowgate"
printf '%s\n' "$revision" > "$stage/source"

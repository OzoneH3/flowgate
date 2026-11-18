#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
. ./scripts/go-env.sh
export npm_config_cache="$PWD/.workspace/npm-cache"
export electron_config_cache="$PWD/.workspace/electron-cache"
export XDG_CACHE_HOME="$PWD/.workspace/cache"
export PYTHONDONTWRITEBYTECODE=1
umask 022

test -z "$(git status --porcelain --untracked-files=no)" || {
  echo 'Commit tracked changes before building a release.' >&2
  exit 1
}
revision=$(git rev-parse HEAD)
stage="$PWD/.workspace/standalone-build"
mkdir -p "$stage/electron" "$TMPDIR" "$XDG_CACHE_HOME"

# Copy the committed Electron source to an isolated build directory.
git archive "$revision" electron | tar -x -C "$stage"
if [ ! -d "$stage/electron/node_modules" ]; then
  if [ -d electron/node_modules ]; then
    ln -s "$PWD/electron/node_modules" "$stage/electron/node_modules"
  else
    npm --prefix "$stage/electron" ci
  fi
fi
npm --prefix "$stage/electron" run build
test -x "$stage/electron/node_modules/electron/dist/electron"
scripts/build-socket-authorization.sh
scripts/build.sh holder-iterator tcp-initiation udp wine-table
experimental/upload-shaper/build.sh "$stage/shaping"
python3 -B scripts/build-matched-daemon.py --revision "$revision" \
  --loader .workspace/holder-iterator --tags socketprototype --output "$stage/flowgate"
printf '%s\n' "$revision" > "$stage/source"

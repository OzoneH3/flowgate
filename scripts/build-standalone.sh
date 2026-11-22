#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
identity=$(python3 -B deployment/standalone/identity.py --require-clean)
revision=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["source"])' "$identity")
version=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["version"])' "$identity")
. ./scripts/go-env.sh
export npm_config_cache="$PWD/build/npm-cache"
export electron_config_cache="$PWD/build/electron-cache"
export XDG_CACHE_HOME="$PWD/build/cache"
export PYTHONDONTWRITEBYTECODE=1
umask 022

python3 -B -c 'import sys; sys.version_info >= (3, 9) or sys.exit("FlowGate requires Python 3.9 or newer.")'
test -x /usr/bin/sha256sum || { echo 'FlowGate requires /usr/bin/sha256sum.' >&2; exit 1; }
stage="$PWD/build/standalone-build"
mkdir -p "$stage/electron" "$TMPDIR" "$XDG_CACHE_HOME"
rm -f "$stage/identity.json"

# Copy the committed Electron source to an isolated build directory.
git archive "$revision" electron | tar -x -C "$stage"
rm -rf "$stage/electron/dist"
scripts/ensure-electron.sh "$stage/electron"
npm --prefix "$stage/electron" run build
scripts/build-socket-authorization.sh
scripts/build.sh holder-iterator tcp-initiation udp wine-table
experimental/upload-shaper/build.sh "$stage/shaping"
python3 -B scripts/build-matched-daemon.py --revision "$revision" --version "$version" \
  --loader build/holder-iterator --udp-helper build/udp-collector --tags socketprototype --output "$stage/flowgate"
test "$identity" = "$(python3 -B deployment/standalone/identity.py --require-clean)" || {
  echo 'Source or tag changed during build. Run make build again.' >&2
  exit 1
}
printf '%s\n' "$identity" > "$stage/identity.json"

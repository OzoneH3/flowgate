#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
root="$PWD"
identity=$(python3 -B deployment/standalone/identity.py --require-clean)
revision=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["source"])' "$identity")
version=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["version"])' "$identity")
umask 022

# Export once into a fresh tree so no working-tree source or old generated
# input can enter the compilers. Share only the checkout's dependency caches.
mkdir -p build
work=$(mktemp -d "$root/build/.standalone.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
trap 'exit 1' HUP INT TERM
git archive --output="$work/source.tar" "$revision"
mkdir "$work/source"
tar -xf "$work/source.tar" -C "$work/source"
rm "$work/source.tar"
cd "$work/source"
mkdir build
for cache in go-cache go npm-cache electron-cache cache backend-go; do
  mkdir -p "$root/build/$cache"
  ln -s "$root/build/$cache" "build/$cache"
done
. ./scripts/go-env.sh
export GOENV=off GOFLAGS=-buildvcs=false GOWORK=off
export npm_config_cache="$PWD/build/npm-cache"
export electron_config_cache="$PWD/build/electron-cache"
export XDG_CACHE_HOME="$PWD/build/cache"
export PYTHONDONTWRITEBYTECODE=1

python3 -B -c 'import sys; sys.version_info >= (3, 9) or sys.exit("FlowGate requires Python 3.9 or newer.")'
test -x /usr/bin/sha256sum || { echo 'FlowGate requires /usr/bin/sha256sum.' >&2; exit 1; }
stage="$PWD/build/standalone-build"
mkdir -p "$stage" "$TMPDIR" "$XDG_CACHE_HOME"
mv electron "$stage/electron"
scripts/ensure-electron.sh "$stage/electron"
npm --prefix "$stage/electron" run build
scripts/build-socket-authorization.sh
scripts/build.sh holder-iterator tcp-initiation udp wine-table
experimental/upload-shaper/build.sh "$stage/shaping"
python3 -B scripts/build-matched-daemon.py --revision "$revision" --version "$version" \
  --loader build/holder-iterator --udp-helper build/udp-collector --tags socketprototype --output "$stage/flowgate"
mv build/holder-iterator build/tcp-initiation-collector build/udp-collector build/windows/table-probe.exe "$stage/"
cd "$root"
test "$identity" = "$(python3 -B deployment/standalone/identity.py --require-clean)" || {
  echo 'Source or tag changed during build. Run make build again.' >&2
  exit 1
}
printf '%s\n' "$identity" > "$stage/identity.json"
(
  flock -x 9
  rm -rf -- build/standalone-build
  mv -T -- "$stage" build/standalone-build
) 9>>build/.standalone.lock

#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
export npm_config_cache="$PWD/.workspace/npm-cache" XDG_CACHE_HOME="$PWD/.workspace/cache" electron_config_cache="$PWD/.workspace/electron-cache" TMPDIR="$PWD/.workspace/tmp"
mkdir -p "$TMPDIR" "$XDG_CACHE_HOME"
if [ ! -f electron/node_modules/electron/package.json ]; then
  (cd electron && npm ci)
fi
node electron/node_modules/electron/install.js
(cd electron && npm run build)
. ./scripts/go-env.sh
go build -o .workspace/electron-observer ./cmd/flowgate

go build -o .workspace/electron-backend ./cmd/flowgate

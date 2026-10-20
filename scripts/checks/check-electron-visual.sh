#!/bin/sh
# Existing local dependencies; actual Wayland + disposable namespace controller.
set -eu
cd "$(dirname "$0")/../.."
mkdir -p .workspace
(cd electron && npm run build && node --test test/model.test.cjs)
. ./scripts/go-env.sh
go build -o .workspace/electron-observer ./cmd/flowgate
cc -Wall -Wextra -O2 fixtures/traffic/traffic.c -o .workspace/electron-traffic-fixture
node electron/test/visual.mjs

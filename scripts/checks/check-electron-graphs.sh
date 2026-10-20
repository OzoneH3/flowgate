#!/bin/sh
# Existing local dependencies only; real unprivileged TCP, no controller/collector.
set -eu
cd "$(dirname "$0")/../.."
(cd electron && npm run build && node --test test/history.test.cjs test/model.test.cjs)
. ./scripts/go-env.sh
go build -o .workspace/electron-observer ./cmd/flowgate
cc -Wall -Wextra -O2 fixtures/traffic/traffic.c -o .workspace/electron-traffic-fixture
node electron/test/graphs.mjs

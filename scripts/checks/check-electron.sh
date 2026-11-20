#!/bin/sh
# Real read-only TCP fixtures + existing disposable enforcement namespace only.
set -eu
cd "$(dirname "$0")/../.."
export PYTHONDONTWRITEBYTECODE=1
scripts/build.sh electron
. ./scripts/go-env.sh
go build -o build/flowgate ./cmd/flowgate
go build -o build/flowgate-demo-receiver ./fixtures/native
cc -Wall -Wextra -O2 fixtures/traffic/traffic.c -o .workspace/electron-traffic-fixture
(cd electron && npm test)
node electron/test/acceptance.mjs

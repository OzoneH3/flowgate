#!/bin/sh
# Focused conditional deletion only; existing local dependencies required.
set -eu
cd "$(dirname "$0")/.."
export PYTHONDONTWRITEBYTECODE=1
(cd electron && npm run build && node --test test/delete.test.cjs test/rules.test.cjs)
. ./scripts/go-env.sh
go build -o .workspace/flowgate ./cmd/flowgate
node electron/test/delete.mjs

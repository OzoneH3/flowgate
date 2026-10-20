#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
. ./scripts/go-env.sh
go test -race ./...
go build -o .workspace/flowgate ./cmd/flowgate
go build -o .workspace/native-a ./fixtures/native
cp .workspace/native-a .workspace/native-b
scripts/lab.sh python3 scripts/acceptance/integration.py
scripts/lab.sh python3 scripts/acceptance/outgoing.py
if [ "${1:-}" = "--wine" ]; then
 scripts/build-windows.sh
 scripts/lab.sh python3 scripts/acceptance/wine-integration.py
fi

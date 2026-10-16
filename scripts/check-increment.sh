#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
. ./scripts/go-env.sh
go test -race ./internal/...
go vet ./...
go build -o .workspace/flowgate ./cmd/flowgate
scripts/build-windows.sh
# Sequential: the namespace test clients use the private .workspace/run sockets.
scripts/lab.sh python3 scripts/wine-increment.py
scripts/lab.sh python3 scripts/wine-boundary.py
scripts/lab.sh python3 scripts/scope-retention.py
# Original native regressions remain available through scripts/check.sh.

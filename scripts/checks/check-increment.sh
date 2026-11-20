#!/bin/sh
set -eu
cd "$(dirname "$0")/../.."
. ./scripts/go-env.sh
go test -race ./internal/...
go vet ./...
go build -o build/flowgate ./cmd/flowgate
scripts/build.sh windows
# Sequential: the namespace test clients use the private .workspace/run sockets.
scripts/lab.sh python3 scripts/acceptance/wine-increment.py
scripts/lab.sh python3 scripts/acceptance/wine-boundary.py
scripts/lab.sh python3 scripts/acceptance/scope-retention.py
# Original native regressions remain available through scripts/check.sh.

#!/bin/sh
# The evaluator is never run against the real host by this check.
set -eu
cd "$(dirname "$0")/.."
. ./scripts/go-env.sh
export PYTHONDONTWRITEBYTECODE=1 XDG_CACHE_HOME="$PWD/.workspace/desktop-cache"
scripts/build-desktop.sh
go test -race ./internal/daemon ./internal/hostfirewall ./internal/monitor
go vet ./cmd/flowgate ./internal/daemon ./internal/hostfirewall ./internal/monitor
scripts/lab.sh python3 scripts/check-control-bridge.py
QT_QPA_PLATFORM="${QT_QPA_PLATFORM:-offscreen}" .workspace/desktop/unified-test

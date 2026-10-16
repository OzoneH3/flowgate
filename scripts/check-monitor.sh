#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
. ./scripts/go-env.sh
export PYTHONDONTWRITEBYTECODE=1 XDG_CACHE_HOME="$PWD/.workspace/desktop-cache"
scripts/build-desktop.sh
mkdir -p .workspace/monitor-fixtures/a .workspace/monitor-fixtures/b
cc -Wall -Wextra -O2 fixtures/monitor.c -o .workspace/monitor-fixtures/a/fixture
cp .workspace/monitor-fixtures/a/fixture .workspace/monitor-fixtures/b/fixture
go test -race ./internal/identity ./internal/daemon ./internal/monitor
go vet ./...
python3 scripts/monitor-test.py
QT_QPA_PLATFORM="${QT_QPA_PLATFORM:-offscreen}" .workspace/desktop/monitor-test
# Small real Allow-to-receiver regression for the shared API/window changes.
QT_QPA_PLATFORM="${QT_QPA_PLATFORM:-offscreen}" .workspace/desktop/desktop-test allowOnce

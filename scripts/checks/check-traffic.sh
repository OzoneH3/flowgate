#!/bin/sh
set -eu
cd "$(dirname "$0")/../.."
. ./scripts/go-env.sh
export PYTHONDONTWRITEBYTECODE=1 XDG_CACHE_HOME="$PWD/.workspace/desktop-cache"
scripts/build.sh desktop
mkdir -p .workspace/traffic-fixtures/a .workspace/traffic-fixtures/b
cc -Wall -Wextra -O2 fixtures/traffic/traffic.c -o .workspace/traffic-fixtures/a/fixture
cp .workspace/traffic-fixtures/a/fixture .workspace/traffic-fixtures/b/fixture
go test -race ./internal/identity ./internal/monitor ./internal/daemon
go vet ./...
python3 scripts/acceptance/traffic-test.py
QT_QPA_PLATFORM="${QT_QPA_PLATFORM:-offscreen}" .workspace/desktop/traffic-test

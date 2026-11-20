#!/bin/sh
set -eu
cd "$(dirname "$0")/../.."
. ./scripts/go-env.sh
export PYTHONDONTWRITEBYTECODE=1
mkdir -p .workspace/ownership-fixtures/a .workspace/ownership-fixtures/b .workspace/traffic-fixtures/a .workspace/traffic-fixtures/b
cc -Wall -Wextra -O2 -pthread fixtures/ownership/leader-exit.c -o .workspace/ownership-fixtures/leader-exit
cc -Wall -Wextra -O2 fixtures/ownership/shared.c -o .workspace/ownership-fixtures/a/shared
cp .workspace/ownership-fixtures/a/shared .workspace/ownership-fixtures/b/shared
cc -Wall -Wextra -O2 fixtures/traffic/traffic.c -o .workspace/traffic-fixtures/b/fixture
go build -o build/flowgate ./cmd/flowgate
go test -race ./internal/identity ./internal/monitor ./internal/daemon
go vet ./...
python3 scripts/acceptance/ownership-test.py

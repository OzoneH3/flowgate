#!/bin/sh
set -eu
cd "$(dirname "$0")/../.."
. ./scripts/go-env.sh
export PYTHONDONTWRITEBYTECODE=1 XDG_CACHE_HOME="$PWD/.workspace/desktop-cache"
scripts/build.sh desktop
mkdir -p .workspace/clients
cc -Wall -Wextra -O2 fixtures/client/client.c -o .workspace/clients/alpha
cp .workspace/clients/alpha .workspace/clients/beta
go test -race ./internal/daemon ./internal/policy ./internal/queue ./internal/store ./internal/hostfirewall
go vet ./cmd/flowgate ./internal/daemon ./internal/policy ./internal/queue ./internal/store ./internal/hostfirewall
run="$PWD/.workspace/outgoing-check-$$"
scripts/lab.sh python3 scripts/acceptance/host-lab.py "$run" --both --outgoing-suite
QT_QPA_PLATFORM="${QT_QPA_PLATFORM:-offscreen}" build/desktop/outgoing-test

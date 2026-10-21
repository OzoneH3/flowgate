#!/bin/sh
# All firewall mutations are confined to disposable namespaces.
set -eu
cd "$(dirname "$0")/../.."
. ./scripts/go-env.sh
scripts/build.sh desktop
go test -race ./internal/daemon ./internal/policy ./internal/queue ./internal/store ./internal/hostfirewall
go vet ./internal/daemon ./internal/policy ./internal/queue ./internal/store ./internal/hostfirewall ./cmd/flowgate
run="$PWD/.workspace/host-check-$$"
scripts/lab.sh python3 scripts/acceptance/host-lab.py "$run" --suite
scripts/lab.sh python3 scripts/acceptance/host-lab.py "$run-bootstrap" --bootstrap-only
.workspace/desktop/host-test

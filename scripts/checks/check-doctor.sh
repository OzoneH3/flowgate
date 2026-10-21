#!/bin/sh
set -eu
cd "$(dirname "$0")/../.."
. ./scripts/go-env.sh
export PYTHONDONTWRITEBYTECODE=1
go build -o .workspace/flowgate ./cmd/flowgate
go test -race ./internal/readiness ./internal/diagnostics ./internal/hostfirewall ./internal/udpaccount ./internal/daemon ./cmd/flowgate
go vet ./...
# Compile metadata-bearing helper only; this does not load/attach programs.
scripts/build.sh udp
scripts/lab.sh python3 scripts/acceptance/doctor-isolated.py

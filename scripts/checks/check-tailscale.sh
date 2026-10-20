#!/bin/sh
set -eu
cd "$(dirname "$0")/../.."
. ./scripts/go-env.sh
export PYTHONDONTWRITEBYTECODE=1
go test -race ./internal/readiness ./internal/diagnostics ./internal/hostfirewall ./internal/daemon ./cmd/flowgate
go vet ./...
go build -o .workspace/flowgate ./cmd/flowgate
scripts/lab.sh python3 scripts/acceptance/tailscale-isolated.py

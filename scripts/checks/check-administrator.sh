#!/bin/sh
set -eu
cd "$(dirname "$0")/../.."
. ./scripts/go-env.sh
export PYTHONDONTWRITEBYTECODE=1
go test -race ./internal/daemon ./internal/store ./internal/hostfirewall ./cmd/flowgate
go vet ./...
go build -o build/flowgate ./cmd/flowgate
scripts/lab.sh python3 scripts/acceptance/administrator-isolated.py

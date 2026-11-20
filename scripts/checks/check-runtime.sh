#!/bin/sh
# Run once for system Wine; set FLOWGATE_TEST_PROTON and FLOWGATE_TEST_STEAM
# to repeat against an already-initialized installed Proton workspace prefix.
set -eu
cd "$(dirname "$0")/../.."
. ./scripts/go-env.sh
go test -race ./internal/...
go vet ./...
go build -o build/flowgate ./cmd/flowgate
scripts/build.sh windows
scripts/build.sh wine-table
# Sequential: all three tests use the private run socket; each creates a namespace.
for script in wine-duplication-test runtime-attachment-test wine-ipv6-test; do
    scripts/lab.sh python3 "scripts/acceptance/$script.py"
done

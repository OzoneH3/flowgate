#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
. ./scripts/go-env.sh
go test -race ./internal/daemon ./internal/identity ./internal/policy
go vet ./internal/daemon ./internal/identity ./internal/policy ./cmd/flowgate
# Never replace the running root monitor's executable.
go build -o .workspace/flowgate-creation ./cmd/flowgate
export FLOWGATE_TEST_BINARY="$PWD/.workspace/flowgate-creation"
scripts/lab.sh python3 scripts/host-lab.py "$PWD/.workspace/observed-rule-receiver-$$" --observed-creation-suite

#!/bin/sh
set -eu
cd "$(dirname "$0")/../.."
. ./scripts/go-env.sh
# New output path only: leave the running monitor and its executable untouched.
go test -race ./internal/daemon ./internal/policy
go vet ./internal/daemon ./internal/policy ./cmd/flowgate
go build -o .workspace/flowgate-policy ./cmd/flowgate
go test -count=1 -run '^TestPolicyContractAuthenticatedNativeActivity$' -v ./internal/daemon

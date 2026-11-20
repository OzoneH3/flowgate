#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
. scripts/go-env.sh
mkdir -p build/socket-auth
clang -g -O2 -target bpf -c experiments/socket-auth/gate.bpf.c -o build/socket-auth/gate.bpf.o
bpftool gen skeleton build/socket-auth/gate.bpf.o > build/socket-auth/gate.skel.h
go test -race ./internal/socketgrant ./internal/daemon -run 'TestSocketAuthorization|TestHardDeadline|TestPolicyEditDuringVerificationAndExpiry|TestSocketAndDestination|TestRevocationFailure|TestNetlinkCookieEqualsSocketCookie|TestForAWhile'
# Preserve the exact already-tested iterator loader; this experiment changes
# packet authorization, not the descriptor-enumeration implementation.
go build -tags socketprototype -ldflags '-X main.holderIteratorSHA256=91e62cdc339fd58fcc13b09bd9f88017226d93ca92650675c127ebc4554e55e8' -o build/socket-auth/flowgate ./cmd/flowgate
sha256sum build/socket-auth/flowgate build/socket-auth/gate.bpf.o

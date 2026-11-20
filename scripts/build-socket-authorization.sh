#!/bin/sh
# Generate embedded programs for an explicitly socketprototype-tagged build.
# No kernel load, hook, host configuration or installation occurs here.
set -eu
cd "$(dirname "$0")/.."
mkdir -p build/socket-auth build/socket-route-build
clang -g -O2 -target bpf -c experiments/socket-auth/gate.bpf.c -o build/socket-auth/gate.bpf.o
bpftool gen skeleton build/socket-auth/gate.bpf.o > build/socket-auth/gate.skel.h
clang -g -O2 -target bpf -c internal/socketgrant/bpf/route_gate.bpf.c -o build/socket-route-build/route_gate.bpf.o
bpftool gen skeleton build/socket-route-build/route_gate.bpf.o > build/socket-route-build/route_gate.skel.h

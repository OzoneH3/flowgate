#!/bin/sh
# Optional build, never part of ordinary desktop startup.
set -eu
cd "$(dirname "$0")/.."
mkdir -p .workspace/udp-build
command -v bpftool >/dev/null
pkg-config --exists libbpf
bpftool btf dump file /sys/kernel/btf/vmlinux format c > .workspace/udp-build/vmlinux.h
clang -g -O2 -target bpf -I .workspace/udp-build -c collectors/udp/udp.bpf.c -o .workspace/udp-build/udp.bpf.o
bpftool gen skeleton .workspace/udp-build/udp.bpf.o > .workspace/udp-build/udp.skel.h
cc -Wall -Wextra -O2 -I .workspace/udp-build collectors/udp/collector.c -o .workspace/udp-collector $(pkg-config --cflags --libs libbpf)

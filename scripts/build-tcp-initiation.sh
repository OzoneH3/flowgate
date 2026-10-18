#!/bin/sh
# Optional collection-only native helper; never part of ordinary GUI startup.
set -eu
cd "$(dirname "$0")/.."
mkdir -p .workspace/tcp-initiation-build
bpftool btf dump file /sys/kernel/btf/vmlinux format c > .workspace/tcp-initiation-build/vmlinux.h
clang -g -O2 -target bpf -I .workspace/tcp-initiation-build -c collectors/tcp-initiation/initiation.bpf.c -o .workspace/tcp-initiation-build/initiation.bpf.o
bpftool gen skeleton .workspace/tcp-initiation-build/initiation.bpf.o > .workspace/tcp-initiation-build/initiation.skel.h
cc -Wall -Wextra -Werror -O2 -I .workspace/tcp-initiation-build collectors/tcp-initiation/collector.c -o .workspace/tcp-initiation-collector $(pkg-config --cflags --libs libbpf)

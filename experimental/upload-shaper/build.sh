#!/bin/sh
# Compile only; never activates traffic control. Run inside the project's build caps.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
out=${1:-"$root/.workspace/shaping-m1"}
case "$out" in "$root"/.workspace/*) ;; *) echo 'output must be inside repository .workspace' >&2; exit 2;; esac
mkdir -p "$out" "$root/.workspace/tmp"
cd "$root"
export GOMAXPROCS=2 GOTOOLCHAIN=local
export GOCACHE="$root/.workspace/backend-go/cache" GOPATH="$root/.workspace/go"
export GOTMPDIR="$root/.workspace/tmp" TMPDIR="$root/.workspace/tmp"
CGO_ENABLED=0 go build -p=1 -trimpath -o "$out/probe" ./experimental/upload-shaper/probe
CGO_ENABLED=0 go build -p=1 -trimpath -o "$out/inspect" ./experimental/upload-shaper/tests/inspect
clang -O2 -g -target bpf -c experimental/upload-shaper/classify.bpf.c -o "$out/classify.bpf.o"
cc -O2 -Wall -Wextra -Werror experimental/upload-shaper/kernel.c -o "$out/kernel" -lbpf
cc -O2 -Wall -Wextra -Werror experimental/upload-shaper/tests/sender.c -o "$out/sender"
cp experimental/upload-shaper/controller.py "$out/controller.py"

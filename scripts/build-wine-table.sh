#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
export TMPDIR="$PWD/.workspace/tmp"
mkdir -p "$TMPDIR" .workspace/windows
clang --target=x86_64-windows-gnu -fuse-ld=lld -fno-stack-protector -nostdlib -nostdinc -I/usr/include/wine/msvcrt -I/usr/include/wine/windows experiments/wine-table/probe.c -L/usr/lib/wine/x86_64-windows -liphlpapi -lws2_32 -lkernel32 -Wl,--entry,mainCRTStartup -o .workspace/windows/table-probe.exe

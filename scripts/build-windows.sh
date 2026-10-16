#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
export TMPDIR="$PWD/.workspace/tmp"
mkdir -p "$TMPDIR" .workspace/windows
clang --target=x86_64-windows-gnu -fuse-ld=lld -fno-stack-protector -nostdlib -nostdinc -I/usr/include/wine/msvcrt -I/usr/include/wine/windows fixtures/windows-pe.c -L/usr/lib/wine/x86_64-windows -lws2_32 -lkernel32 -Wl,--entry,mainCRTStartup -o .workspace/windows/alpha.exe
cp .workspace/windows/alpha.exe .workspace/windows/beta.exe
file .workspace/windows/alpha.exe
clang --target=x86_64-windows-gnu -fuse-ld=lld -fno-stack-protector -nostdlib -nostdinc -I/usr/include/wine/msvcrt -I/usr/include/wine/windows fixtures/windows-lifecycle.c -L/usr/lib/wine/x86_64-windows -lws2_32 -lkernel32 -Wl,--entry,mainCRTStartup -o .workspace/windows/alpha-dup.exe
cp .workspace/windows/alpha-dup.exe .workspace/windows/beta-dup.exe

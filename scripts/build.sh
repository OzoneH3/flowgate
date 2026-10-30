#!/bin/sh
# Build selected targets only; never install or start host protection.
set -eu
cd "$(dirname "$0")/.."
usage() { echo 'Usage: scripts/build.sh TARGET [TARGET ...]'; echo 'Targets: desktop electron windows wine-table tcp-initiation udp holder-iterator'; }
if [ "$#" -eq 1 ] && [ "$1" = --help ]; then usage; exit 0; fi
[ "$#" -gt 0 ] || { usage >&2; exit 2; }
# Reject the complete request before starting any build.
for target in "$@"; do
 case "$target" in desktop|electron|windows|wine-table|tcp-initiation|udp|holder-iterator) ;; *) usage >&2; exit 2 ;; esac
done
. ./scripts/go-env.sh
export npm_config_cache="$PWD/.workspace/npm-cache" XDG_CACHE_HOME="$PWD/.workspace/cache" electron_config_cache="$PWD/.workspace/electron-cache"
for target in "$@"; do
 case "$target" in
 desktop)
  go build -o .workspace/flowgate ./cmd/flowgate
  go build -o .workspace/flowgate-demo-receiver ./fixtures/native
  cmake -S desktop -B .workspace/desktop -DCMAKE_BUILD_TYPE=Debug
  cmake --build .workspace/desktop -j2
  ;;
 electron)
  mkdir -p "$TMPDIR" "$XDG_CACHE_HOME"
  if [ ! -f electron/node_modules/electron/package.json ]; then
    (cd electron && npm ci)
  fi
  node electron/node_modules/electron/install.js
  (cd electron && npm run build)
  go build -o .workspace/electron-observer ./cmd/flowgate
  cp .workspace/electron-observer .workspace/electron-backend
  ;;
 windows)
  export TMPDIR="$PWD/.workspace/tmp"
  mkdir -p "$TMPDIR" .workspace/windows
  clang --target=x86_64-windows-gnu -fuse-ld=lld -fno-stack-protector -nostdlib -nostdinc -I/usr/include/wine/msvcrt -I/usr/include/wine/windows fixtures/windows-pe.c -L/usr/lib/wine/x86_64-windows -lws2_32 -lkernel32 -Wl,--entry,mainCRTStartup -o .workspace/windows/alpha.exe
  cp .workspace/windows/alpha.exe .workspace/windows/beta.exe
  file .workspace/windows/alpha.exe
  clang --target=x86_64-windows-gnu -fuse-ld=lld -fno-stack-protector -nostdlib -nostdinc -I/usr/include/wine/msvcrt -I/usr/include/wine/windows fixtures/windows-lifecycle.c -L/usr/lib/wine/x86_64-windows -lws2_32 -lkernel32 -Wl,--entry,mainCRTStartup -o .workspace/windows/alpha-dup.exe
  cp .workspace/windows/alpha-dup.exe .workspace/windows/beta-dup.exe
  ;;
 wine-table)
  export TMPDIR="$PWD/.workspace/tmp"
  mkdir -p "$TMPDIR" .workspace/windows
  clang --target=x86_64-windows-gnu -fuse-ld=lld -fno-stack-protector -nostdlib -nostdinc -I/usr/include/wine/msvcrt -I/usr/include/wine/windows experiments/wine-table/probe.c -L/usr/lib/wine/x86_64-windows -liphlpapi -lws2_32 -lkernel32 -Wl,--entry,mainCRTStartup -o .workspace/windows/table-probe.exe
  ;;
 tcp-initiation)
  mkdir -p .workspace/tcp-initiation-build
  bpftool btf dump file /sys/kernel/btf/vmlinux format c > .workspace/tcp-initiation-build/vmlinux.h
  # Kernel BTF is an external generated header; keep project diagnostics enabled.
  clang -g -O2 -target bpf -isystem .workspace/tcp-initiation-build -c collectors/tcp-initiation/initiation.bpf.c -o .workspace/tcp-initiation-build/initiation.bpf.o
  bpftool gen skeleton .workspace/tcp-initiation-build/initiation.bpf.o > .workspace/tcp-initiation-build/initiation.skel.h
  cc -Wall -Wextra -Werror -O2 -I .workspace/tcp-initiation-build collectors/tcp-initiation/collector.c -o .workspace/tcp-initiation-collector $(pkg-config --cflags --libs libbpf)
  ;;
 holder-iterator)
  mkdir -p .workspace/holder-iterator-build
  bpftool btf dump file /sys/kernel/btf/vmlinux format c > .workspace/holder-iterator-build/vmlinux.h
  clang -g -O2 -target bpf -isystem .workspace/holder-iterator-build -c collectors/holder-iterator/fds.bpf.c -o .workspace/holder-iterator-build/fds.bpf.o
  bpftool gen skeleton .workspace/holder-iterator-build/fds.bpf.o > .workspace/holder-iterator-build/fds.skel.h
  cc -Wall -Wextra -O2 -I .workspace/holder-iterator-build collectors/holder-iterator/loader.c -o .workspace/holder-iterator $(pkg-config --cflags --libs libbpf)
  ;;
 udp)
  mkdir -p .workspace/udp-build
  command -v bpftool >/dev/null
  pkg-config --exists libbpf
  bpftool btf dump file /sys/kernel/btf/vmlinux format c > .workspace/udp-build/vmlinux.h
  # Kernel BTF is an external generated header; keep project diagnostics enabled.
  clang -g -O2 -target bpf -isystem .workspace/udp-build -c collectors/udp/udp.bpf.c -o .workspace/udp-build/udp.bpf.o
  bpftool gen skeleton .workspace/udp-build/udp.bpf.o > .workspace/udp-build/udp.skel.h
  cc -Wall -Wextra -O2 -I .workspace/udp-build collectors/udp/collector.c -o .workspace/udp-collector $(pkg-config --cflags --libs libbpf)
  ;;
 esac
done

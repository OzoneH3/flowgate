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
export npm_config_cache="$PWD/build/npm-cache" XDG_CACHE_HOME="$PWD/build/cache" electron_config_cache="$PWD/build/electron-cache"
source_map="-ffile-prefix-map=$PWD=/usr/src/flowgate"

# For collectors with large kernel type graphs, give the BPF backend normalized
# IR. In a direct C-to-BPF build Clang can assign different BTF forward type IDs
# across checkout paths even after debug paths have been mapped.
compile_core_collector() {
  source=$1
  build_dir=$2
  object=$3
  clang "$source_map" -g -O2 -target bpf -isystem "$build_dir" -emit-llvm -c "$source" -o "$build_dir/$object.bc"
  clang -O2 -target bpf -c "$build_dir/$object.bc" -o "$build_dir/$object.o"
}
for target in "$@"; do
 case "$target" in
 desktop)
  go build -o build/flowgate ./cmd/flowgate
  go build -o build/flowgate-demo-receiver ./fixtures/native
  cmake -S desktop -B build/desktop -DCMAKE_BUILD_TYPE=Debug
  cmake --build build/desktop -j2
  ;;
 electron)
  mkdir -p "$TMPDIR" "$XDG_CACHE_HOME" build/desktop-session
  scripts/ensure-electron.sh electron
  (cd electron && npm run build)
  go build -o build/electron-observer ./cmd/flowgate
  cp build/electron-observer build/electron-backend
  ;;
 windows)
  export TMPDIR="$PWD/build/tmp"
  mkdir -p "$TMPDIR" build/windows
  clang --target=x86_64-windows-gnu -fuse-ld=lld -fno-stack-protector -nostdlib -nostdinc -I/usr/include/wine/msvcrt -I/usr/include/wine/windows fixtures/windows-pe.c -L/usr/lib/wine/x86_64-windows -lws2_32 -lkernel32 -Wl,--entry,mainCRTStartup -o build/windows/alpha.exe
  cp build/windows/alpha.exe build/windows/beta.exe
  file build/windows/alpha.exe
  clang --target=x86_64-windows-gnu -fuse-ld=lld -fno-stack-protector -nostdlib -nostdinc -I/usr/include/wine/msvcrt -I/usr/include/wine/windows fixtures/windows-lifecycle.c -L/usr/lib/wine/x86_64-windows -lws2_32 -lkernel32 -Wl,--entry,mainCRTStartup -o build/windows/alpha-dup.exe
  cp build/windows/alpha-dup.exe build/windows/beta-dup.exe
  ;;
 wine-table)
  export TMPDIR="$PWD/build/tmp"
  mkdir -p "$TMPDIR" build/windows
  clang "$source_map" --target=x86_64-windows-gnu -fuse-ld=lld -fno-stack-protector -nostdlib -nostdinc -I/usr/include/wine/msvcrt -I/usr/include/wine/windows experiments/wine-table/probe.c -L/usr/lib/wine/x86_64-windows -liphlpapi -lws2_32 -lkernel32 -Wl,--entry,mainCRTStartup -o build/windows/table-probe.exe
  ;;
 tcp-initiation)
  mkdir -p build/tcp-initiation-build
  bpftool btf dump file /sys/kernel/btf/vmlinux format c > build/tcp-initiation-build/vmlinux.h
  # Kernel BTF is an external generated header; keep project diagnostics enabled.
  clang "$source_map" -g -O2 -target bpf -isystem build/tcp-initiation-build -c collectors/tcp-initiation/initiation.bpf.c -o build/tcp-initiation-build/initiation.bpf.o
  bpftool gen skeleton build/tcp-initiation-build/initiation.bpf.o > build/tcp-initiation-build/initiation.skel.h
  cc "$source_map" -Wall -Wextra -Werror -O2 -I build/tcp-initiation-build collectors/tcp-initiation/collector.c -o build/tcp-initiation-collector $(pkg-config --cflags --libs libbpf)
  ;;
 holder-iterator)
  mkdir -p build/holder-iterator-build
  bpftool btf dump file /sys/kernel/btf/vmlinux format c > build/holder-iterator-build/vmlinux.h
  compile_core_collector collectors/holder-iterator/fds.bpf.c build/holder-iterator-build fds.bpf
  bpftool gen skeleton build/holder-iterator-build/fds.bpf.o > build/holder-iterator-build/fds.skel.h
  cc "$source_map" -Wall -Wextra -O2 -I build/holder-iterator-build collectors/holder-iterator/loader.c -o build/holder-iterator $(pkg-config --cflags --libs libbpf)
  ;;
 udp)
  mkdir -p build/udp-build
  command -v bpftool >/dev/null
  pkg-config --exists libbpf
  bpftool btf dump file /sys/kernel/btf/vmlinux format c > build/udp-build/vmlinux.h
  # Kernel BTF is an external generated header; keep project diagnostics enabled.
  compile_core_collector collectors/udp/udp.bpf.c build/udp-build udp.bpf
  bpftool gen skeleton build/udp-build/udp.bpf.o > build/udp-build/udp.skel.h
  cc "$source_map" -Wall -Wextra -O2 -I build/udp-build collectors/udp/collector.c -o build/udp-collector $(pkg-config --cflags --libs libbpf)
  ;;
 esac
done

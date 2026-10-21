#!/bin/sh
# Real Wine/Proton runtime-census saturation with concurrent native traffic,
# entirely inside private user/network/PID namespaces. No host changes.
# Required: FLOWGATE_TEST_PROTON (installed Proton dir), FLOWGATE_TEST_UMU_RUNTIME
# (installed steamrt3/4), FLOWGATE_TEST_PREFIX_SOURCE (initialized workspace compat dir).
# Optional: FLOWGATE_TEST_LWP, FLOWGATE_SATURATION_ARGS (extra harness flags).
set -eu
cd "$(dirname "$0")/../.."
. ./scripts/go-env.sh
export PYTHONDONTWRITEBYTECODE=1
proton=${FLOWGATE_TEST_PROTON:?select installed Proton}
runtime=${FLOWGATE_TEST_UMU_RUNTIME:?select installed steamrt runtime}
prefix=${FLOWGATE_TEST_PREFIX_SOURCE:?select initialized workspace prefix}
lwp=${FLOWGATE_TEST_LWP:-$(command -v lwp || true)}
test -n "$lwp" || { echo 'lwp launcher not found; set FLOWGATE_TEST_LWP' >&2; exit 1; }
test -f "$proton/proton"
test -f "$runtime/umu"
test -f "$prefix/pfx/system.reg"
run=$(mktemp -d "$PWD/.workspace/wine-saturation-XXXXXX")
mkdir -p "$run/data/umu"
cp -a --reflink=auto "$runtime" "$run/data/umu/$(basename "$runtime")"
cp -a --reflink=auto "$proton" "$run/proton"
# Consolidated build entry point when present (scripts/build.sh TARGET).
if test -f scripts/build.sh; then sh scripts/build.sh wine-table; else sh scripts/build-wine-table.sh; fi
go build -o "$run/flowgate" ./cmd/flowgate
clang --target=x86_64-windows-gnu -fuse-ld=lld -fno-stack-protector -nostdlib -nostdinc \
 -I/usr/include/wine/msvcrt -I/usr/include/wine/windows fixtures/windows-udp-saturation.c \
 -L/usr/lib/wine/x86_64-windows -lws2_32 -lkernel32 \
 -Wl,--entry,mainCRTStartup -Wl,--subsystem,windows -o "$run/saturation.exe"
FLOWGATE_PARENT_NETNS=$(readlink /proc/self/ns/net)
export FLOWGATE_PARENT_NETNS
printf 'Evidence directory: %s\n' "$run"
# shellcheck disable=SC2086
exec unshare --user --map-current-user --keep-caps --net --pid --fork --mount-proc \
 sh -c 'set -e; ip link set lo up; exec "$@"' sh \
 python3 scripts/acceptance/wine-saturation.py \
 --binary "$run/flowgate" --helper "$PWD/.workspace/windows/table-probe.exe" --run "$run/evidence" \
 --proton "$run/proton" --data "$run/data" --prefix-source "$prefix" --pe "$run/saturation.exe" --lwp "$lwp" \
 ${FLOWGATE_SATURATION_ARGS:-}

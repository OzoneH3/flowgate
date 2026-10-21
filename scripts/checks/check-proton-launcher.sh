#!/bin/sh
# Verify real lwp/UMU/Proton attribution and receiver control, entirely in a lab.
# Required: FLOWGATE_TEST_PROTON (installed Proton directory),
# FLOWGATE_TEST_UMU_RUNTIME (installed steamrt3 or steamrt4),
# FLOWGATE_TEST_PREFIX_SOURCE (initialized workspace Proton compat directory).
set -eu
cd "$(dirname "$0")/../.."
. ./scripts/go-env.sh
export PYTHONDONTWRITEBYTECODE=1
proton=${FLOWGATE_TEST_PROTON:?select installed Proton}
runtime=${FLOWGATE_TEST_UMU_RUNTIME:?select installed steamrt3 or steamrt4}
prefix=${FLOWGATE_TEST_PREFIX_SOURCE:?select initialized workspace prefix}
lwp=${FLOWGATE_TEST_LWP:-$(command -v lwp)}
test -f "$proton/proton"
test -f "$runtime/umu"
test -f "$prefix/pfx/system.reg"
run=$(mktemp -d "$PWD/.workspace/proton-launcher-XXXXXX")
mkdir -p "$run/data/umu"
runtime_name=$(basename "$runtime")
case "$runtime_name" in steamrt3|steamrt4) ;; *) echo "Expected steamrt3 or steamrt4 runtime directory" >&2; exit 2;; esac
cp -a --reflink=auto "$runtime" "$run/data/umu/$runtime_name"
cp -a --reflink=auto "$proton" "$run/proton"
sh scripts/build.sh wine-table
go build -o "$run/flowgate" ./cmd/flowgate
clang --target=x86_64-windows-gnu -fuse-ld=lld -fno-stack-protector -nostdlib -nostdinc \
 -I/usr/include/wine/msvcrt -I/usr/include/wine/windows fixtures/windows-proton-connect.c \
 -L/usr/lib/wine/x86_64-windows -lws2_32 -lkernel32 \
 -Wl,--entry,mainCRTStartup -Wl,--subsystem,windows -o "$run/client.exe"
export FLOWGATE_PARENT_NETNS=$(readlink /proc/self/ns/net)
printf 'Evidence directory: %s\n' "$run"
unshare --user --map-current-user --keep-caps --net --pid --fork --mount-proc \
 sh -c 'ip link set lo up; exec "$@"' sh \
 python3 scripts/acceptance/proton-launcher-regression.py \
 --verify --burst --protocol "${FLOWGATE_TEST_PROTOCOL:-tcp}" --helper "$PWD/.workspace/windows/table-probe.exe" --binary "$run/flowgate" --run "$run/evidence" --proton "$run/proton" \
 --data "$run/data" --prefix-source "$prefix" --pe "$run/client.exe" --lwp "$lwp"

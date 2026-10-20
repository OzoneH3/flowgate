#!/bin/sh
# Default exercises denied BPF in a disposable user/net namespace. --kernel asks
# sudo only for the disposable initial-user-namespace BPF/TUN test environment.
# --reuse-build skips tests/build when the existing workspace artifacts are wanted.
# --hold [--traffic] keeps the owned isolated daemon for UI attachment (see DAEMON-UDP.md).
set -eu
cd "$(dirname "$0")/../.."
. ./scripts/go-env.sh
kernel= sudo_n= reuse= hold=
for arg; do
 case "$arg" in
  --kernel) kernel=1;;
  --noninteractive) sudo_n=-n;;
  --reuse-build) reuse=1;;
  --hold) hold="$hold --hold";;
  --traffic) hold="$hold --traffic";;
  *) echo "unknown argument: $arg" >&2; exit 2;;
 esac
done
if [ -z "$reuse" ]; then
 go test -race ./internal/udpaccount ./internal/daemon ./internal/identity ./internal/monitor ./internal/readiness
 go vet ./internal/udpaccount ./internal/daemon ./internal/identity ./internal/monitor ./cmd/flowgate
 go build -o .workspace/flowgate-udp-daemon ./cmd/flowgate
 scripts/build-udp.sh
 mkdir -p .workspace/udp-fixtures
 cc -Wall -Wextra -O2 fixtures/udp/fixture.c -o .workspace/udp-fixtures/alpha
 cp .workspace/udp-fixtures/alpha .workspace/udp-fixtures/beta
fi
for f in .workspace/flowgate-udp-daemon .workspace/udp-collector .workspace/udp-fixtures/alpha; do
 [ -x "$f" ] || { echo "missing $f; rerun without --reuse-build" >&2; exit 1; }
done
run="$PWD/.workspace/daemon-udp-$(date +%s)-$$"
mkdir -m 755 "$run"
sha256sum .workspace/flowgate-udp-daemon .workspace/udp-collector .workspace/udp-fixtures/alpha >"$run/artifacts.sha256"
if [ -n "$kernel" ]; then
 # shellcheck disable=SC2086
 exec sudo $sudo_n unshare --net --pid --mount --fork --mount-proc --propagation private \
  env FLOWGATE_PARENT_NETNS="$(readlink /proc/self/ns/net)" \
  python3 "$PWD/scripts/acceptance/daemon-udp-isolated.py" --run "$run" --uid "$(id -u)" --gid "$(id -g)" --kernel $hold
fi
# shellcheck disable=SC2086
exec scripts/lab.sh python3 scripts/acceptance/daemon-udp-isolated.py --run "$run" --uid 0 --gid 0 $hold

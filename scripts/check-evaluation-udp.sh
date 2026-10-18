#!/bin/sh
# One real BPF continuity case in disposable network/PID/mount namespaces.
# Does not use, replace, restart or attach collection to the host daemon.
set -eu
cd "$(dirname "$0")/.."
. ./scripts/go-env.sh
sudo_n=
case "${1:-}" in --noninteractive) sudo_n=-n;; '') ;; *) echo 'usage: scripts/check-evaluation-udp.sh [--noninteractive]' >&2; exit 2;; esac
go build -o .workspace/flowgate-eval-udp ./cmd/flowgate
for f in .workspace/udp-collector .workspace/udp-fixtures/alpha; do
 [ -x "$f" ] || { echo "Missing $f; build with scripts/build-udp.sh or cc -O2 fixtures/udp/fixture.c -o .workspace/udp-fixtures/alpha" >&2; exit 1; }
done
run="$PWD/.workspace/evaluation-udp-$(date +%s)-$$"
mkdir -m 755 "$run"
git rev-parse HEAD >"$run/source.sha"
sha256sum .workspace/flowgate-eval-udp .workspace/udp-collector .workspace/udp-fixtures/alpha >"$run/artifacts.sha256"
echo "EVIDENCE $run"
# Word splitting is intentional for the fixed optional sudo flag only.
exec sudo $sudo_n unshare --net --pid --mount --fork --mount-proc --propagation private \
 env FLOWGATE_PARENT_NETNS="$(readlink /proc/self/ns/net)" \
 python3 "$PWD/scripts/daemon-udp-isolated.py" --run "$run" --uid "$(id -u)" --gid "$(id -g)" \
 --kernel --evaluation-continuity --binary "$PWD/.workspace/flowgate-eval-udp"

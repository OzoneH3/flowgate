#!/bin/sh
# Initial-namespace BPF credentials, collection strictly filtered to a fresh netns.
set -eu
for option in "$@"; do
  case "$option" in --observe-shared|--failure-only) ;; *)
    echo "usage: scripts/check-tcp-initiation.sh [--observe-shared] [--failure-only]" >&2; exit 2;;
  esac
done
cd "$(dirname "$0")/.."
. scripts/go-env.sh
run="$PWD/.workspace/tcp-initiation-$(date +%s)-$$"
mkdir -m 700 -p "$run"
scripts/build-tcp-initiation.sh
cp .workspace/tcp-initiation-collector "$run/collector"
go build -o "$run/flowgate" ./cmd/flowgate
go build -o "$run/native" ./fixtures/tcp-initiation
git rev-parse HEAD > "$run/source.sha"
git diff --binary > "$run/source-working.diff"
sha256sum "$run/flowgate" "$run/collector" "$run/native" > "$run/artifacts.sha256"
printf 'EVIDENCE %s\n' "$run"
parent=$(readlink /proc/self/ns/net)
parent_mnt=$(readlink /proc/self/ns/mnt)
exec sudo unshare --net --pid --mount --fork --mount-proc --propagation private env PYTHONDONTWRITEBYTECODE=1 FLOWGATE_PARENT_NETNS="$parent" FLOWGATE_PARENT_MNTNS="$parent_mnt" python3 scripts/tcp-initiation-isolated.py --run "$run" --binary "$run/flowgate" --helper "$run/collector" --native "$run/native" "$@"

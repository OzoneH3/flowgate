#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
export PYTHONDONTWRITEBYTECODE=1
mkdir -p .workspace/run
chmod 700 .workspace/run
parent=$(readlink /proc/self/ns/net)
exec unshare --user --map-root-user --net --pid --fork --mount-proc sh -c '
 set -eu
 ip link set lo up
 export FLOWGATE_PARENT_NETNS="$1"
 shift
 exec "$@"
' sh "$parent" "${@:-sh}"

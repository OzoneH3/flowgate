#!/bin/sh
# Deliberate privileged test command only, never run by the desktop launcher.
set -eu
cd "$(dirname "$0")/.."
parent=$(readlink /proc/self/ns/net)
exec sudo unshare --net --pid --fork --mount-proc \
 env FLOWGATE_PARENT_NETNS="$parent" python3 scripts/udp-isolated-test.py --run "$PWD/.workspace/udp-privileged-$(date +%s)"

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
 if [ "${FLOWGATE_LAB_PRIVATE_ROOT:-0}" = 1 ]; then
  # A user namespace maps host root-owned ancestors to the overflow UID.
  # Give security-sensitive filesystem tests a namespace-owned root without
  # changing the host filesystem or relaxing their ownership checks.
  project=$PWD
  root="$project/.workspace/tmp/lab-root"
  mkdir -p "$root"
  mount --make-rprivate /
  mount -t tmpfs -o mode=755 tmpfs "$root"
  mkdir -p "$root/usr" "$root/etc" "$root/dev" "$root/proc" "$root$project" "$root/t"
  chmod 700 "$root/t"
  for dir in usr etc dev proc; do mount --rbind "/$dir" "$root/$dir"; done
  mount --bind "$project" "$root$project"
  for dir in bin lib lib64 sbin; do ln -s "usr/$dir" "$root/$dir"; done
  export TMPDIR=/t GOTMPDIR=/t
  exec chroot "$root" /bin/sh -c '\''cd "$1"; shift; exec "$@"'\'' sh "$project" "$@"
 fi
 exec "$@"
' sh "$parent" "${@:-sh}"

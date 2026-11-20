#!/bin/sh
# No arguments: launch/reuse installed GUI; no update or daemon restart.
# --update (or explicit update options): install the approved pinned release.
# Usage: scripts/update-and-start.sh [--launch | --dry-run]
# Update: scripts/update-and-start.sh --update [--dry-run] [--no-gui] [--autostart]
#        [--profile preserve|monitoring|incoming|both] [--wine-discovery] [--recover-stopped] [--local] [--acknowledge-outgoing-blocking]
# Valid rules and Wine observer configuration are preserved. Daemon startup
# archives expired rules and confirmed replaced native versions. Builds and sudo
# authentication finish before stopping protection; failed installs stop safely.
set -eu
cd "$(dirname "$0")/.."
root=$PWD
if [ "$#" -eq 1 ] && [ "$1" = "--dry-run" ]; then
  exec python3 scripts/lib/launch_installed.py --dry-run
fi
if [ "$#" -eq 0 ] || { [ "$#" -eq 1 ] && [ "$1" = "--launch" ]; }; then
  exec python3 scripts/lib/launch_installed.py
fi
dry=0 gui=1 profile=preserve wine_discovery=0 recover_stopped=0 local_source=0 autostart=0 acknowledge_outgoing=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --update) shift;;
    --acknowledge-outgoing-blocking) acknowledge_outgoing=1; shift;;
    --profile) [ "$#" -gt 1 ] || { echo "--profile needs preserve, monitoring, incoming or both" >&2; exit 2; }; profile=$2; shift 2;;
    --local) local_source=1; shift;;
    --recover-stopped) recover_stopped=1; shift;;
    --wine-discovery) wine_discovery=1; shift;;
    --dry-run) dry=1; shift;;
    --autostart) autostart=1; shift;;
    --no-gui) gui=0; shift;;
    -h|--help) sed -n '2,7p' scripts/update-and-start.sh; exit 0;;
    *) echo "unknown option: $1" >&2; exit 2;;
  esac
done
if [ "$autostart" = 1 ] && [ "$gui" = 0 ]; then
  echo "--autostart requires GUI switching" >&2; exit 2
fi
case $profile in preserve|monitoring|incoming|both) ;; *) echo "Invalid protection profile: $profile" >&2; exit 2;; esac

say() { printf '==> %s\n' "$*"; }
run() { if [ $dry = 1 ]; then printf '    (dry run) %s\n' "$*"; else "$@"; fi; }

# --- source -------------------------------------------------------------------
test "$(git branch --show-current)" = master || { echo "Not on master; switch first." >&2; exit 1; }
if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "Uncommitted changes in $root; commit or set them aside first (a bundle is built from a clean HEAD)." >&2
  exit 1
fi
if [ "$local_source" = 1 ]; then
  say "Using local master (--local); upstream was not checked"
elif git rev-parse --abbrev-ref --symbolic-full-name '@{u}' >/dev/null 2>&1; then
  say "Fetching upstream (60-second limit)"
  ssh_command=${GIT_SSH_COMMAND:-$(git config --get core.sshCommand || printf '%s' "${GIT_SSH:-ssh}")}
  if run env GIT_TERMINAL_PROMPT=0 GIT_SSH_COMMAND="$ssh_command -oBatchMode=yes -oConnectTimeout=10 -oConnectionAttempts=1" timeout --kill-after=5s 60s git -c credential.interactive=false pull --ff-only; then
    :
  else
    result=$?
    echo "Upstream update failed or timed out (exit $result); no installation or protection action taken." >&2
    echo "Check Git connectivity/authentication, or use --local to explicitly use the current local master." >&2
    exit "$result"
  fi
else
  say "No upstream configured; using local master"
fi
say "Source HEAD: $(git rev-parse HEAD)"
IFS= read -r rev < deployment/default-release
case "$rev" in ''|*[!0-9a-f]*) echo "Invalid approved release pin" >&2; exit 1;; esac
[ "${#rev}" = 40 ] || { echo "Invalid approved release SHA" >&2; exit 1; }
bundle="$root/build/automatic-zone-releases/$rev"
backend="$root/build/daily-releases/$rev"
say "Approved release: $rev (HEAD is not implicitly approved)"

# --- bundle -------------------------------------------------------------------
if [ -f "$bundle/matched-manifest.json" ] && [ -f "$backend/manifest.json" ]; then
  say "Bundle ready: $bundle"
else
  say "Preparing bundle for $rev (build + isolated release checks; takes a few minutes)"
  echo "Approved release artifacts missing; prepare that exact revision separately. No build/install from HEAD." >&2
  exit 1
fi

# The Python coordinator verifies immutable manifests and handles typed control
# transitions without replaying lost acknowledgements. --dry-run stays read-only.
set -- --root "$root" --revision "$rev"
[ "$dry" = 0 ] || set -- "$@" --dry-run
[ "$gui" = 1 ] || set -- "$@" --no-gui
[ "$autostart" = 0 ] || set -- "$@" --autostart
[ "$recover_stopped" = 0 ] || set -- "$@" --recover-stopped
[ "$wine_discovery" = 0 ] || set -- "$@" --wine-discovery
[ -z "$profile" ] || set -- "$@" --profile "$profile"
[ "$acknowledge_outgoing" = 0 ] || set -- "$@" --acknowledge-outgoing-blocking
exec python3 scripts/lib/update_and_start.py "$@"

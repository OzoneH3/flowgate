#!/bin/sh
# Prepare/install the latest master, start Both protection, switch matching GUI.
# Usage: scripts/update-and-start.sh [--dry-run] [--no-gui]
#        [--profile preserve|monitoring|incoming|both] [--wine-discovery] [--recover-stopped]
# Valid rules and Wine observer configuration are preserved. Daemon startup
# archives expired rules and confirmed replaced native versions. Builds and sudo
# authentication finish before stopping protection; failed installs stop safely.
set -eu
cd "$(dirname "$0")/.."
root=$PWD
dry=0 gui=1 profile=both wine_discovery=0 recover_stopped=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --profile) [ "$#" -gt 1 ] || { echo "--profile needs preserve, monitoring, incoming or both" >&2; exit 2; }; profile=$2; shift 2;;
    --recover-stopped) recover_stopped=1; shift;;
    --wine-discovery) wine_discovery=1; shift;;
    --dry-run) dry=1; shift;;
    --no-gui) gui=0; shift;;
    -h|--help) sed -n '2,7p' scripts/update-and-start.sh; exit 0;;
    *) echo "unknown option: $1" >&2; exit 2;;
  esac
done
case $profile in preserve|monitoring|incoming|both) ;; *) echo "Invalid protection profile: $profile" >&2; exit 2;; esac

say() { printf '==> %s\n' "$*"; }
run() { if [ $dry = 1 ]; then printf '    (dry run) %s\n' "$*"; else "$@"; fi; }

# --- source -------------------------------------------------------------------
test "$(git branch --show-current)" = master || { echo "Not on master; switch first." >&2; exit 1; }
if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "Uncommitted changes in $root; commit or set them aside first (a bundle is built from a clean HEAD)." >&2
  exit 1
fi
if git rev-parse --abbrev-ref --symbolic-full-name '@{u}' >/dev/null 2>&1; then
  say "Fetching upstream"
  run git pull --ff-only
else
  say "No upstream configured; using local master"
fi
rev=$(git rev-parse HEAD)
bundle="$root/.workspace/automatic-zone-releases/$rev"
backend="$root/.workspace/daily-releases/$rev"
say "Latest: $(git log -1 --format='%h %s')"

# --- bundle -------------------------------------------------------------------
if [ -f "$bundle/matched-manifest.json" ] && [ -f "$backend/manifest.json" ]; then
  say "Bundle ready: $bundle"
else
  say "Preparing bundle for $rev (build + isolated release checks; takes a few minutes)"
  run scripts/prepare-automatic-zone-release.sh
fi

# The Python coordinator verifies immutable manifests and handles typed control
# transitions without replaying lost acknowledgements. --dry-run stays read-only.
set -- --root "$root" --revision "$rev"
[ "$dry" = 0 ] || set -- "$@" --dry-run
[ "$gui" = 1 ] || set -- "$@" --no-gui
[ "$recover_stopped" = 0 ] || set -- "$@" --recover-stopped
[ "$wine_discovery" = 0 ] || set -- "$@" --wine-discovery
[ -z "$profile" ] || set -- "$@" --profile "$profile"
exec python3 scripts/lib/update_and_start.py "$@"

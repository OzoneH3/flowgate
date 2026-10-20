#!/bin/sh
# Update FlowGate to the latest master and start the GUI.
#
#   scripts/update-and-start.sh            prepare, install if newer (sudo prompt), start GUI
#   scripts/update-and-start.sh --dry-run  show what would happen; change nothing
#   scripts/update-and-start.sh --no-gui   update only
#
# 1. Fast-forwards master from its upstream when one is configured.
# 2. Prepares the matched bundle for HEAD (scripts/prepare-automatic-zone-release.sh)
#    unless it already exists.
# 3. When the installed release differs from HEAD, installs it with the
#    MONITORING-ONLY installer (one sudo prompt). Stored rules are preserved and
#    protection is never activated. If protection is active the update stops:
#    run `flowgate-control stop` yourself first; this script never stops it.
# 4. Starts the GUI from the same bundle against the system daemon.
set -eu
cd "$(dirname "$0")/.."
root=$PWD
dry=0 gui=1
for a in "$@"; do
  case $a in
    --dry-run) dry=1 ;;
    --no-gui) gui=0 ;;
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
    *) echo "unknown option: $a" >&2; exit 2 ;;
  esac
done
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

# --- installed daemon ---------------------------------------------------------
installed=$(basename "$(readlink /usr/local/lib/flowgate/current 2>/dev/null || echo none)")
if [ "$installed" = "$rev" ]; then
  say "Installed daemon already at $rev"
else
  say "Installed daemon: $installed -> updating to $rev (monitoring-only)"
  if [ -x /usr/local/sbin/flowgate-control ]; then
    state=$(/usr/local/sbin/flowgate-control status 2>/dev/null |
      python3 -c 'import json,sys;r=json.load(sys.stdin);print((r.get("protection")or{}).get("state","stopped"),(r.get("enforcement")or{}).get("state","stopped"))' 2>/dev/null || echo "unknown unknown")
    case $state in
      "stopped stopped") ;;
      "unknown unknown") say "Daemon status unavailable; the installer checks it again" ;;
      *) echo "FlowGate protection is active ($state). Stop it explicitly with 'flowgate-control stop', then rerun. Nothing was changed." >&2; exit 1 ;;
    esac
  fi
  run sudo python3 "$backend/install-monitoring.py" --bundle "$backend"
fi

# --- GUI ----------------------------------------------------------------------
[ $gui = 1 ] || exit 0
# A GUI from an earlier bundle would keep running beside the new one (two
# permission windows); close it first. The daemon and protection are unaffected.
old=$(pgrep -u "$(id -u)" -f "$root/.workspace/automatic-zone-releases/[^ ]*/runtime/electron --ozone-platform" || true)
if [ -n "$old" ]; then
  say "Closing running FlowGate GUI ($(echo $old | tr '\n' ' '))"
  if [ $dry = 0 ]; then
    kill $old 2>/dev/null || true
    i=0; while [ $i -lt 50 ] && kill -0 $old 2>/dev/null; do sleep 0.1; i=$((i+1)); done
  fi
fi
say "Starting FlowGate GUI ($rev)"
if [ $dry = 1 ]; then
  printf '    (dry run) %s\n' "$bundle/launch-ui --observer /run/flowgate-api/daemon.sock.monitor --control /run/flowgate-api/daemon.sock"
  exit 0
fi
exec "$bundle/launch-ui" --observer /run/flowgate-api/daemon.sock.monitor --control /run/flowgate-api/daemon.sock

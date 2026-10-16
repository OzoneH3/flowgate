#!/bin/sh
# EXPLICIT host activation. Never called by run-desktop.sh or the GUI.
# This script is prepared for user review/execution; implementation tests use lab.sh.
set -eu
cd "$(dirname "$0")/.."
if [ "$(id -u)" = 0 ]; then
  echo 'Run as your desktop user; only the daemon is elevated.' >&2
  exit 1
fi
scripts/build-desktop.sh
printf '%s\n' 'Explicit incoming-first HOST enforcement evaluation, automatic stop after 5 minutes.' \
 'New incoming TCP/UDP may wait or be blocked. Existing tracked connections are preserved; outgoing is allowed.' \
 'The GUI stays unprivileged. In another terminal run:' \
 '.workspace/desktop/flowgate-desktop --socket /run/flowgate-api/control.sock' \
 'Stop: sudo .workspace/flowgate host-stop --state /run/flowgate' \
 'Recovery after daemon loss: sudo .workspace/flowgate host-recover --state /run/flowgate'
exec sudo "$PWD/.workspace/flowgate" host-session --action start \
  --uid "$(id -u)" --duration 5m --timeout 30s

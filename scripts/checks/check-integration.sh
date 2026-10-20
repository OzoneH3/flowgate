#!/bin/sh
# Focused integrated Wayland smoke; only disposable namespace enforcement.
set -eu
cd "$(dirname "$0")/../.."
export PYTHONDONTWRITEBYTECODE=1
scripts/build-desktop.sh
scripts/build-electron.sh
cc -Wall -Wextra -O2 fixtures/traffic/traffic.c -o .workspace/electron-traffic-fixture
QT_QPA_PLATFORM=wayland .workspace/desktop/exactjson-test
QT_QPA_PLATFORM=wayland .workspace/desktop/host-test persistedDecision
node electron/test/integration.mjs

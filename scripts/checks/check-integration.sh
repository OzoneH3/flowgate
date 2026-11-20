#!/bin/sh
# Focused integrated Wayland smoke; only disposable namespace enforcement.
set -eu
cd "$(dirname "$0")/../.."
export PYTHONDONTWRITEBYTECODE=1
scripts/build.sh desktop
scripts/build.sh electron
cc -Wall -Wextra -O2 fixtures/traffic/traffic.c -o .workspace/electron-traffic-fixture
QT_QPA_PLATFORM=wayland build/desktop/exactjson-test
QT_QPA_PLATFORM=wayland build/desktop/host-test persistedDecision
node electron/test/integration.mjs

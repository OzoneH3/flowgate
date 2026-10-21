#!/bin/sh
# Real isolated-controller/KDE background checks, plus labelled presentation fixtures.
# No host enforcement or UDP collector verification.
set -eu
cd "$(dirname "$0")/../.."
export PYTHONDONTWRITEBYTECODE=1
scripts/build.sh electron
(cd electron && npm test)
node electron/test/background.mjs
node electron/test/attribution.mjs

#!/bin/sh
# Rules/evaluation in disposable namespaces; terminal authentication simulated.
# UDP collector lifecycle assertions are synthetic: no privileged UDP collection.
set -eu
cd "$(dirname "$0")/../.."
export PYTHONDONTWRITEBYTECODE=1
scripts/build-electron.sh
(cd electron && npm test)
node electron/test/workflows.mjs

#!/bin/sh
# Desktop user builds/coordinates; only the disposable namespace uses sudo.
set -eu
if [ "$(id -u)" -eq 0 ]; then echo "Run as your desktop user; this script requests sudo only for the disposable namespace." >&2; exit 1; fi
cd "$(dirname "$0")/../.."
. ./scripts/go-env.sh
scripts/build.sh desktop
go build -o .workspace/udp-test-driver ./fixtures/udpdriver
mkdir -p .workspace/udp-fixtures
cc -Wall -Wextra -O2 fixtures/udp/fixture.c -o .workspace/udp-fixtures/alpha
cp .workspace/udp-fixtures/alpha .workspace/udp-fixtures/beta
if [ ! -x build/udp-collector ]; then scripts/build.sh udp; fi
exec python3 scripts/acceptance/udp-verification.py "$@"

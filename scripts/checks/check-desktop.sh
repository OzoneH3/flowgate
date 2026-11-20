#!/bin/sh
set -eu
cd "$(dirname "$0")/../.."
. ./scripts/go-env.sh
export PYTHONDONTWRITEBYTECODE=1 XDG_CACHE_HOME="$PWD/.workspace/desktop-cache"
scripts/build.sh desktop
go test -race ./internal/daemon ./internal/policy
go vet ./...
# Explicitly choose wayland (with WAYLAND_DISPLAY) or offscreen at invocation.
export QT_QPA_PLATFORM="${QT_QPA_PLATFORM:-offscreen}"
exec build/desktop/desktop-test

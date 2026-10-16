#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
base="$PWD/.workspace"
runtime="${FLOWGATE_TEST_PROTON:?set the inspected installed Proton directory}"
verb=runinprefix
if [ "${1:-}" = --init ]; then
    set -- "$base/windows/table-probe.exe"
    verb=getcompatpath
fi
case "${1:-}" in "$base/windows/"*.exe) ;; *) echo 'workspace PE fixture required' >&2; exit 2;; esac
export PYTHONDONTWRITEBYTECODE=1
export TMPDIR="$base/proton-tmp" XDG_CACHE_HOME="$base/proton-cache" XDG_CONFIG_HOME="$base/proton-config" XDG_DATA_HOME="$base/proton-data"
test_prefix=$(realpath -m "${FLOWGATE_TEST_PREFIX:-$base/proton-prefix}")
case "$test_prefix" in "$base/"*) ;; *) echo 'workspace test prefix required' >&2; exit 2;; esac
export STEAM_COMPAT_DATA_PATH="$test_prefix" WINEPREFIX="$test_prefix/pfx" PROTONPATH="$runtime"
export STEAM_COMPAT_CLIENT_INSTALL_PATH="${FLOWGATE_TEST_STEAM:?set the existing Steam client directory}"
export PROTONFIXES_DISABLE=1 PROTON_LOG_DIR="$base" WINEDEBUG=-all WINEDLLOVERRIDES='mscoree,mshtml='
export SteamAppId=0 SteamGameId=0 DISPLAY= WAYLAND_DISPLAY=
mkdir -p "$STEAM_COMPAT_DATA_PATH" "$TMPDIR" "$XDG_CACHE_HOME" "$XDG_CONFIG_HOME" "$XDG_DATA_HOME"
exec python3 "$runtime/proton" "$verb" "$@"

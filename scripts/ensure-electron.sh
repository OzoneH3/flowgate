#!/bin/sh
# Install the locked desktop dependencies and runtime in the selected build tree.
set -eu
cd "$1"
version=$(node -p 'require("./package-lock.json").packages["node_modules/electron"].version')
pin=$(node -p 'require("./package.json").devDependencies.electron')
if [ "$pin" != "$version" ]; then
  echo 'Electron package pin and lockfile disagree.' >&2
  exit 1
fi
lock=$(sha256sum < package-lock.json)
stamp=node_modules/.flowgate-lock-sha256
module=node_modules/electron
if [ ! -f "$stamp" ] || [ "$(cat "$stamp")" != "$lock" ] ||
   [ ! -f "$module/package.json" ] || [ "$(node -p 'require("./node_modules/electron/package.json").version')" != "$version" ]; then
  ELECTRON_SKIP_BINARY_DOWNLOAD=1 npm ci
fi
env -u ELECTRON_OVERRIDE_DIST_PATH -u ELECTRON_SKIP_BINARY_DOWNLOAD node "$module/install.js"
if [ ! -x "$module/dist/electron" ] || [ "$(cat "$module/dist/version")" != "$version" ]; then
  echo "Electron runtime does not match the locked version $version." >&2
  exit 1
fi
printf '%s\n' "$lock" > "$stamp"

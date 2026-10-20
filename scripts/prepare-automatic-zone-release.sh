#!/bin/sh
# Prepare matched artifacts only. No daemon installation or protection action.
set -eu
cd "$(dirname "$0")/.."
. ./scripts/go-env.sh
export npm_config_cache="$PWD/.workspace/npm-cache" XDG_CACHE_HOME="$PWD/.workspace/cache"
test "$(git branch --show-current)" = master
git diff --quiet
git diff --cached --quiet
revision=$(git rev-parse HEAD)
bundle="$PWD/.workspace/automatic-zone-releases/$revision"
test ! -e "$bundle" || { echo "Release already exists: $bundle"; exit 1; }
(cd electron && npm run build)
if [ ! -f ".workspace/daily-releases/$revision/manifest.json" ]; then
 scripts/prepare-daily-release.sh
fi
mkdir -p "$bundle/electron" "$bundle/.workspace/cache" "$bundle/docs" "$bundle/evidence"
cp -a ".workspace/daily-releases/$revision" "$bundle/backend"
cp -a electron/dist "$bundle/electron/dist"
cp electron/package.json "$bundle/electron/package.json"
cp -a electron/node_modules/electron/dist "$bundle/runtime"
cp docs/PROTON-LAUNCHER-REGRESSION.md "$bundle/docs/"
cp docs/AUTOMATIC-ZONES.md "$bundle/docs/backend-zones.md"
cp electron/AUTOMATIC-ZONES.md "$bundle/docs/electron-zones.md"
cp electron/PROMPT-PRESENTATION.md electron/REMEMBER-REVALIDATION.md "$bundle/docs/"
for f in proton-fix-discovery-receiver.log proton-fix-race.log proton-fix-ui-tests.log proton-fix-root-scratch.log proton-fix-ui-real-data.log auto-zones-integrated-go.log auto-zones-final-race.log auto-zones-vet.log auto-zones-integrated-ui-tests.log auto-zones-integrated-receiver.log cgnat-parity-go.log cgnat-parity-race.log cgnat-parity-ui-tests.log automatic-zone-migration-preview.json; do
 test ! -f ".workspace/$f" || cp ".workspace/$f" "$bundle/evidence/$f"
done
cat > "$bundle/launch-ui" <<'LAUNCH'
#!/bin/sh
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
export TMPDIR="$here/.workspace" XDG_CACHE_HOME="$here/.workspace/cache"
exec "$here/runtime/electron" --ozone-platform=wayland "$here/electron" "$@"
LAUNCH
chmod 755 "$bundle/launch-ui"
python3 - "$bundle" "$revision" <<'PY'
import hashlib,json,pathlib,sys
b=pathlib.Path(sys.argv[1]);revision=sys.argv[2]
files={str(p.relative_to(b)):hashlib.sha256(p.read_bytes()).hexdigest()for p in sorted(b.rglob('*'))if p.is_file()}
m=dict(source=revision,prepared_only=True,host_installed=False,host_protection_activated=False,classification_model='automatic-peer-v1',registry_version=json.loads(pathlib.Path('internal/identity/data/iana-special.json').read_text())['version'],files=files)
(b/'matched-manifest.json').write_text(json.dumps(m,indent=2)+'\n')
print('PREPARED',b)
print('UI:',str(b/'launch-ui'),'--observer /run/flowgate-api/daemon.sock.monitor --control /run/flowgate-api/daemon.sock')
print('Backend monitoring rollout is a separate deliberate action; no command was executed.')
PY

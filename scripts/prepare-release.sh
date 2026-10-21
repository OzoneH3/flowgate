#!/bin/sh
# Prepare matched artifacts only. No daemon installation or protection action.
set -eu
cd "$(dirname "$0")/.."
backend_only=0
case "${1:-}" in
 '') [ "$#" -eq 0 ] || exit 2 ;;
 --backend-only) [ "$#" -eq 1 ] || exit 2; backend_only=1 ;;
 --help) [ "$#" -eq 1 ] || exit 2; echo 'Usage: scripts/prepare-release.sh [--backend-only]'; exit 0 ;;
 *) echo 'Usage: scripts/prepare-release.sh [--backend-only]' >&2; exit 2 ;;
esac
. ./scripts/go-env.sh
export PYTHONDONTWRITEBYTECODE=1 npm_config_cache="$PWD/.workspace/npm-cache" XDG_CACHE_HOME="$PWD/.workspace/cache"
test "$(git branch --show-current)" = master
git diff --quiet
git diff --cached --quiet
revision=$(git rev-parse HEAD)
backend="$PWD/.workspace/daily-releases/$revision"
bundle="$PWD/.workspace/automatic-zone-releases/$revision"
verify_existing() {
 python3 - "$1" "$2" "$revision" <<'PYVERIFY'
import pathlib,sys
sys.path.insert(0,str(pathlib.Path.cwd()/'scripts/lib'))
from update_and_start import verify_bundle
verify_bundle(pathlib.Path(sys.argv[1]),sys.argv[2],sys.argv[3])
PYVERIFY
}
if [ "$backend_only" -eq 0 ] && [ -f "$bundle/matched-manifest.json" ] && [ -f "$backend/manifest.json" ]; then
 verify_existing "$backend" manifest.json
 verify_existing "$bundle" matched-manifest.json
 cmp "$backend/manifest.json" "$bundle/backend/manifest.json" || { echo "Backend and GUI bundles differ" >&2; exit 1; }
 echo "Bundle ready: $bundle"
 exit 0
fi
if [ -f "$backend/manifest.json" ]; then
 verify_existing "$backend" manifest.json
 echo "Backend bundle ready: $backend"
else
 mkdir -p "$backend"
go build -trimpath -ldflags "-X main.sourceRevision=$revision" -o "$backend/flowgate" ./cmd/flowgate
go build -trimpath -o "$backend/native" ./fixtures/process-rule
cp "$backend/native" "$backend/native-other"
scripts/build.sh wine-table
cp .workspace/windows/table-probe.exe "$backend/wine-owner-observer.exe"
# Build collectors from this checkout, rather than accepting workspace leftovers.
scripts/build.sh tcp-initiation
scripts/build.sh udp
cp .workspace/tcp-initiation-collector "$backend/tcp-initiation"
cp .workspace/udp-collector "$backend/udp-collector"
# Current source checks. These do not claim live-kernel collector acceptance.
ordinary_peer_tests='^(TestDecisionLogAPIOnReadOnlyEndpoint|TestObservedCreationAuthorizationAndPersistence|TestTrafficAPIPermissionsAndProjection)$'
scripts/lab.sh go test -race ./... -skip "$ordinary_peer_tests" > "$backend/go-race.log" 2>&1
go test -race ./internal/daemon -run "$ordinary_peer_tests" >> "$backend/go-race.log" 2>&1
go vet ./... > "$backend/go-vet.log" 2>&1
cp deployment/launch deployment/control.py deployment/recover.py deployment/uninstall.py "$backend/"
cp deployment/systemd/* "$backend/"
cp scripts/install-monitoring.py "$backend/install-monitoring.py"
cp scripts/host-daily-acceptance.py "$backend/host-acceptance.py"
python3 - "$backend" "$revision" <<'PY'
import hashlib,json,pathlib,sys
b=pathlib.Path(sys.argv[1]);revision=sys.argv[2]
evidence=[b/'go-race.log',b/'go-vet.log']
executables=['flowgate','native','native-other','tcp-initiation','udp-collector','launch','control.py','recover.py','uninstall.py','install-monitoring.py','host-acceptance.py']
names=[*executables,'wine-owner-observer.exe','flowgate.service','flowgate-guard.service','50-flowgate-guard.conf',*[p.name for p in evidence]]
m={'release':revision,'source':revision,'isolated_passed':True,'checks':['go-race','go-vet','isolated-native-api-receiver'],'live_kernel_collectors_verified':False,'evidence':[p.name for p in evidence],'executables':executables,'files':{name:hashlib.sha256((b/name).read_bytes()).hexdigest()for name in names}}
(b/'manifest.json').write_text(json.dumps(m,indent=2))
print('PREPARED',b)
print('AUTHENTICATED MONITORING-ONLY INSTALL (one command; does not activate protection):')
print('python3 scripts/install-prepared.py --bundle '+str(b))
PY
fi
[ "$backend_only" -eq 0 ] || exit 0
test ! -e "$bundle" || { echo "Incomplete GUI bundle exists; inspect it before rebuilding: $bundle" >&2; exit 1; }
(cd electron && npm run build)
mkdir -p "$bundle/electron" "$bundle/.workspace/cache" "$bundle/docs" "$bundle/evidence"
cp -a ".workspace/daily-releases/$revision" "$bundle/backend"
cp -a electron/dist "$bundle/electron/dist"
cp electron/package.json "$bundle/electron/package.json"
cp -a electron/node_modules/electron/dist "$bundle/runtime"
cp docs/PROTON-LAUNCHER-REGRESSION.md "$bundle/docs/"
cp docs/AUTOMATIC-ZONES.md "$bundle/docs/backend-zones.md"
cp electron/AUTOMATIC-ZONES.md "$bundle/docs/electron-zones.md"
cp electron/PROMPT-PRESENTATION.md electron/REMEMBER-REVALIDATION.md "$bundle/docs/"
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

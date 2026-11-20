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
export PYTHONDONTWRITEBYTECODE=1 npm_config_cache="$PWD/build/npm-cache" XDG_CACHE_HOME="$PWD/build/cache"
test "$(git branch --show-current)" = master
git diff --quiet
git diff --cached --quiet
revision=$(git rev-parse HEAD)
backend="$PWD/build/daily-releases/$revision"
bundle="$PWD/build/automatic-zone-releases/$revision"
logs="$PWD/build/build-logs/$revision"
steps=10
[ "$backend_only" -eq 0 ] || steps=8
build_step() {
 step=$1 label=$2 logfile=$3
 shift 3
 python3 scripts/lib/build_progress.py --step "$step" --total "$steps" --label "$label" --log "$logfile" -- "$@"
}
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
build_step 1 "Build daemon and holder iterator" "$logs/build-daemon.log" sh -c '
 scripts/build.sh holder-iterator
 python3 scripts/build-matched-daemon.py --revision "$1" --loader build/holder-iterator --output "$2/flowgate"
 cp build/holder-iterator "$2/holder-iterator"
' sh "$revision" "$backend"
build_step 2 "Build receiver fixtures" "$logs/build-fixtures.log" go build -trimpath -o "$backend/native" ./fixtures/process-rule
cp "$backend/native" "$backend/native-other"
build_step 3 "Build Wine observer" "$logs/build-wine.log" scripts/build.sh wine-table
cp build/windows/table-probe.exe "$backend/wine-owner-observer.exe"
# Build collectors from this checkout, rather than accepting workspace leftovers.
build_step 4 "Build TCP collector" "$logs/build-tcp.log" scripts/build.sh tcp-initiation
build_step 5 "Build UDP collector" "$logs/build-udp.log" scripts/build.sh udp
cp build/tcp-initiation-collector "$backend/tcp-initiation"
cp build/udp-collector "$backend/udp-collector"
# Current source checks. These do not claim live-kernel collector acceptance.
ordinary_peer_tests='^(TestDecisionLogAPIOnReadOnlyEndpoint|TestObservedCreationAuthorizationAndPersistence|TestTrafficAPIPermissionsAndProjection)$'
# Kernel fixtures share one lab namespace; serialize packages even if GOFLAGS
# requests parallelism, so their firewall tables/queues cannot interfere.
build_step 6 "Isolated race and receiver checks" "$backend/go-race.log" env FLOWGATE_LAB_PRIVATE_ROOT=1 scripts/lab.sh go test -race -p=1 ./... -skip "$ordinary_peer_tests"
build_step 7 "API permission checks" "$logs/go-peer-race.log" go test -race ./internal/daemon -run "$ordinary_peer_tests"
cat "$logs/go-peer-race.log" >> "$backend/go-race.log"
build_step 8 "Go static checks" "$backend/go-vet.log" go vet ./...
cp deployment/launch deployment/control.py deployment/recover.py deployment/uninstall.py "$backend/"
cp deployment/systemd/* "$backend/"
cp scripts/install-monitoring.py "$backend/install-monitoring.py"
cp scripts/host-daily-acceptance.py "$backend/host-acceptance.py"
python3 - "$backend" "$revision" <<'PY'
import hashlib,json,pathlib,sys
b=pathlib.Path(sys.argv[1]);revision=sys.argv[2]
evidence=[b/'go-race.log',b/'go-vet.log']
executables=['flowgate','holder-iterator','native','native-other','tcp-initiation','udp-collector','launch','control.py','recover.py','uninstall.py','install-monitoring.py','host-acceptance.py']
names=[*executables,'wine-owner-observer.exe','flowgate.service','flowgate-guard.service','50-flowgate-guard.conf',*[p.name for p in evidence]]
import subprocess
v=json.loads(subprocess.run([str(b/'flowgate'),'version'],check=True,capture_output=True,text=True,timeout=10).stdout)
schema=v.get('max_rule_schema')
if type(schema)is not int or not 1<=schema<=64:sys.exit('Built daemon does not declare a valid max_rule_schema')
m={'max_rule_schema':schema,'release':revision,'source':revision,'isolated_passed':True,'checks':['go-race','go-vet','isolated-native-api-receiver'],'live_kernel_collectors_verified':False,'evidence':[p.name for p in evidence],'executables':executables,'files':{name:hashlib.sha256((b/name).read_bytes()).hexdigest()for name in names}}
(b/'manifest.json').write_text(json.dumps(m,indent=2))
print('PREPARED',b)
print('AUTHENTICATED MONITORING-ONLY INSTALL (one command; does not activate protection):')
print('python3 scripts/install-prepared.py --bundle '+str(b))
PY
fi
[ "$backend_only" -eq 0 ] || exit 0
test ! -e "$bundle" || { echo "Incomplete GUI bundle exists; inspect it before rebuilding: $bundle" >&2; exit 1; }
build_step 9 "Build Electron UI" "$logs/build-electron.log" npm --prefix electron run build
printf '[#########-] 10/10 Package matched release — running\n'
mkdir -p "$bundle/electron" "$bundle/docs" "$bundle/evidence"
cp -a "build/daily-releases/$revision" "$bundle/backend"
cp -a electron/dist "$bundle/electron/dist"
cp electron/package.json "$bundle/electron/package.json"
cp -a electron/node_modules/electron/dist "$bundle/runtime"
cp docs/PROTON-LAUNCHER-REGRESSION.md "$bundle/docs/"
cp docs/AUTOMATIC-ZONES.md "$bundle/docs/backend-zones.md"
cp electron/AUTOMATIC-ZONES.md "$bundle/docs/electron-zones.md"
cp electron/PROMPT-PRESENTATION.md electron/REMEMBER-REVALIDATION.md "$bundle/docs/"
cp electron/fontconfig_isolation.py "$bundle/fontconfig_isolation.py"
cat > "$bundle/launch-ui" <<'LAUNCH'
#!/bin/sh
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cache="${XDG_CACHE_HOME:-$HOME/.cache}/flowgate"
mkdir -p "$cache"
# Private, runtime-versioned Fontconfig cache for Electron's bundled Fontconfig
# (keeps system fonts/rules; respects a user FONTCONFIG_FILE/FONTCONFIG_PATH).
fontconfig=$(python3 "$here/fontconfig_isolation.py" "$cache" "$here/runtime" || true)
if [ -n "$fontconfig" ]; then export FONTCONFIG_FILE="$fontconfig"; fi
exec "$here/runtime/electron" --ozone-platform=wayland "$here/electron" "$@"
LAUNCH
chmod 755 "$bundle/launch-ui"
python3 - "$bundle" "$revision" <<'PY'
import datetime,hashlib,json,pathlib,sys
b=pathlib.Path(sys.argv[1]);revision=sys.argv[2]
# Packaging time of this bundle (UTC); a reused bundle keeps its manifest unchanged.
built_at=datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace('+00:00','Z')
files={str(p.relative_to(b)):hashlib.sha256(p.read_bytes()).hexdigest()for p in sorted(b.rglob('*'))if p.is_file()}
m=dict(source=revision,prepared_only=True,host_installed=False,host_protection_activated=False,classification_model='automatic-peer-v1',registry_version=json.loads(pathlib.Path('internal/identity/data/iana-special.json').read_text())['version'],built_at=built_at,files=files)
(b/'matched-manifest.json').write_text(json.dumps(m,indent=2)+'\n')
print('PREPARED',b)
print('UI:',str(b/'launch-ui'),'--observer /run/flowgate-api/daemon.sock.monitor --control /run/flowgate-api/daemon.sock')
print('Backend monitoring rollout is a separate deliberate action; no command was executed.')
PY
printf '[##########] 10/10 Package matched release — done\n'

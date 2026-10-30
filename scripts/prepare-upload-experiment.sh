#!/bin/sh
# Prepare only. Never installs, authorizes an update, or starts a daemon.
set -eu
cd "$(dirname "$0")/.."
. scripts/go-env.sh
export GOMAXPROCS=2 GOFLAGS=-p=1 PYTHONDONTWRITEBYTECODE=1
revision=$(git rev-parse HEAD)
[ -z "$(git status --porcelain)" ] || { echo 'Commit tracked changes first' >&2; exit 1; }
out="$PWD/.workspace/experimental-upload-bundles/$revision"
[ ! -e "$out" ] || { echo 'Bundle already exists' >&2; exit 1; }
mkdir -p "$out/backend" "$out/electron"
scripts/build.sh holder-iterator
digest=$(sha256sum .workspace/holder-iterator | cut -d " " -f1)
cp .workspace/holder-iterator "$out/backend/holder-iterator"
go build -trimpath -ldflags "-X main.sourceRevision=$revision -X main.holderIteratorSHA256=$digest" -o "$out/backend/flowgate" ./cmd/flowgate
experimental/upload-shaper/build.sh "$out/helpers"
npm --prefix electron run build
cp -r electron/dist "$out/electron/dist"
cp electron/package.json "$out/electron/package.json"
cp docs/UPLOAD-EXPERIMENTAL-TRIAL.txt "$out/TRIAL.txt"
cp docs/TRAFFIC-PRIORITY.txt "$out/TRAFFIC-PRIORITY.txt"
cp docs/ZONE-SHAPING.txt "$out/ZONE-SHAPING.txt"
printf '\nPinned experimental release: %s\n' "$revision" >> "$out/TRIAL.txt"
cat > "$out/launch-ui" <<'EOF'
#!/bin/sh
set -eu
: "${FLOWGATE_ELECTRON:?Set absolute path to trusted Electron executable}"
[ "$#" -eq 2 ] || { echo 'Usage: launch-ui MONITOR_SOCKET CONTROL_SOCKET' >&2; exit 2; }
mkdir -p "$(dirname "$0")/.workspace/tmp"
export TMPDIR="$(dirname "$0")/.workspace/tmp"
exec "$FLOWGATE_ELECTRON" --ozone-platform=wayland "$(dirname "$0")/electron" --observer "$1" --control "$2"
EOF
chmod +x "$out/launch-ui"
[ "$(git rev-parse HEAD)" = "$revision" ] && [ -z "$(git status --porcelain)" ] || { echo "Source changed during build; bundle is incomplete" >&2; exit 1; }
python3 - "$out" "$revision" <<'PY'
import pathlib,sys,json,hashlib,datetime
p=pathlib.Path(sys.argv[1]);r=sys.argv[2]
m={'source':r,'built_at':datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z'),'prepared_only':True,'host_installed':False,'source_revision':r,'backend_revision':r,'gui_revision':r,'experimental':True,'install_authorized':False,'default_update_eligible':False,'runtime':'Use existing trusted Electron 44.9.0; runtime tree not copied','files':{str(f.relative_to(p)):hashlib.sha256(f.read_bytes()).hexdigest() for f in p.rglob('*') if f.is_file()}}
(p/'matched-manifest.json').write_text(json.dumps(m,indent=2)+'\n')
PY
printf '%s\n' "$out"

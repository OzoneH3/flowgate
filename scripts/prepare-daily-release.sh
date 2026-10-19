#!/bin/sh
# Build a matched, hash-bound release. No privileged command, installation or host action.
set -eu
cd "$(dirname "$0")/.."
. ./scripts/go-env.sh
test "$(git branch --show-current)" = master
git diff --quiet
git diff --cached --quiet
revision=$(git rev-parse HEAD)
bundle="$PWD/.workspace/daily-releases/$revision"
mkdir -p "$bundle"
test ! -f "$bundle/manifest.json" || { echo "Bundle exists; inspect it instead of overwriting" >&2; exit 1; }
go build -trimpath -ldflags "-X main.sourceRevision=$revision" -o "$bundle/flowgate" ./cmd/flowgate
go build -trimpath -o "$bundle/native" ./fixtures/process-rule
cp "$bundle/native" "$bundle/native-other"
# Reuse exact accepted native collector binaries; do not reopen kernel acceptance.
test "$(sha256sum .workspace/tcp-initiation-collector | cut -d' ' -f1)" = 86b6e8844ac8f73c357673471e726e4fdeff5b5edbc59e4331e2ab5e1c5312b3
cp .workspace/tcp-initiation-collector "$bundle/tcp-initiation"
cp .workspace/udp-collector "$bundle/udp-collector"
cp deployment/launch deployment/control.py deployment/recover.py deployment/uninstall.py "$bundle/"
cp deployment/systemd/* "$bundle/"
cp scripts/install-daily.py "$bundle/install.py"
cp scripts/install-monitoring.py "$bundle/install-monitoring.py"
cp scripts/host-daily-acceptance.py "$bundle/host-acceptance.py"
python3 - "$bundle" "$revision" <<'PY'
import hashlib,json,pathlib,sys
b=pathlib.Path(sys.argv[1]);revision=sys.argv[2]
# These paths intentionally point to preserved exact acceptance, not a broad rerun.
root=pathlib.Path.cwd();component=root/'.workspace/continuous-component-f4fozgp6/result.json';adapter=root/'.workspace/daily-adapter-ri9_sdjq/acceptance/result.json';failure=root/'.workspace/daily-adapter-kxiw4xhv/failure-result.json';stop_crash=root/'.workspace/daily-adapter-ofl4hfcl/stop-crash-result.json'
assert all(json.loads(p.read_text())['passed']for p in [component,adapter,failure,stop_crash])
executables=['flowgate','native','native-other','tcp-initiation','udp-collector','launch','control.py','recover.py','uninstall.py','install.py','install-monitoring.py','host-acceptance.py']
m={'release':revision,'source':revision,'isolated_passed':True,'evidence':list(map(str,[component,adapter,failure,stop_crash])),'executables':executables,'files':{p.name:hashlib.sha256(p.read_bytes()).hexdigest()for p in b.iterdir()if p.is_file()}}
(b/'manifest.json').write_text(json.dumps(m,indent=2))
print('PREPARED',b)
# install.py (receiver acceptance activates protection) is retained only for a
# later separately approved protection stage. The rollout command is monitoring-only.
print('AUTHENTICATED MONITORING-ONLY INSTALL (one command; does not activate protection):')
print('sudo python3 '+str(b/'install-monitoring.py')+' --bundle '+str(b))
PY

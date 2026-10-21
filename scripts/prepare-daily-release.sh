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
scripts/build-wine-table.sh
cp .workspace/windows/table-probe.exe "$bundle/wine-owner-observer.exe"
# Build collectors from this checkout, rather than accepting workspace leftovers.
scripts/build-tcp-initiation.sh
scripts/build-udp.sh
cp .workspace/tcp-initiation-collector "$bundle/tcp-initiation"
cp .workspace/udp-collector "$bundle/udp-collector"
# Current source checks. These do not claim live-kernel collector acceptance.
ordinary_peer_tests='^(TestDecisionLogAPIOnReadOnlyEndpoint|TestObservedCreationAuthorizationAndPersistence|TestTrafficAPIPermissionsAndProjection)$'
scripts/lab.sh go test -race ./... -skip "$ordinary_peer_tests" > "$bundle/go-race.log" 2>&1
go test -race ./internal/daemon -run "$ordinary_peer_tests" >> "$bundle/go-race.log" 2>&1
go vet ./... > "$bundle/go-vet.log" 2>&1
cp deployment/launch deployment/control.py deployment/recover.py deployment/uninstall.py "$bundle/"
cp deployment/systemd/* "$bundle/"
cp scripts/install-daily.py "$bundle/install.py"
cp scripts/install-monitoring.py "$bundle/install-monitoring.py"
cp scripts/host-daily-acceptance.py "$bundle/host-acceptance.py"
python3 - "$bundle" "$revision" <<'PY'
import hashlib,json,pathlib,sys
b=pathlib.Path(sys.argv[1]);revision=sys.argv[2]
evidence=[b/'go-race.log',b/'go-vet.log']
executables=['flowgate','native','native-other','tcp-initiation','udp-collector','launch','control.py','recover.py','uninstall.py','install.py','install-monitoring.py','host-acceptance.py']
m={'release':revision,'source':revision,'isolated_passed':True,'checks':['go-race','go-vet','isolated-native-api-receiver'],'live_kernel_collectors_verified':False,'evidence':[p.name for p in evidence],'executables':executables,'files':{p.name:hashlib.sha256(p.read_bytes()).hexdigest()for p in b.iterdir()if p.is_file()}}
(b/'manifest.json').write_text(json.dumps(m,indent=2))
print('PREPARED',b)
# install.py (receiver acceptance activates protection) is retained only for a
# later separately approved protection stage. The rollout command is monitoring-only.
print('AUTHENTICATED MONITORING-ONLY INSTALL (one command; does not activate protection):')
print('python3 scripts/install-prepared.py --bundle '+str(b))
PY

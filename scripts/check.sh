#!/bin/sh
set -eu
invocation_directory=$PWD
cd "$(dirname "$0")/.."
. ./scripts/go-env.sh
export PYTHONDONTWRITEBYTECODE=1

receiver_checks() {
 case "$#" in
  0)
   go build -o build/flowgate ./cmd/flowgate
   daemon="$PWD/build/flowgate"
   ;;
  2)
   case "$2" in
    /*) input=$2 ;;
    *) input="$invocation_directory/$2" ;;
   esac
   case "$1" in
    --binary) daemon=$input ;;
    --archive)
     daemon="$PWD/$(mktemp -d build/receiver-release.XXXXXX)/flowgate"
     python3 - "$input" "$daemon" <<'PYTHON'
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tarfile

archive, daemon = sys.argv[1], Path(sys.argv[2])
with tarfile.open(archive, "r:*") as bundle:
    manifest = json.load(bundle.extractfile("release.json"))
    member = bundle.getmember("backend/flowgate")
    if not member.isfile():
        raise SystemExit("Release backend/flowgate must be a regular file")
    with bundle.extractfile(member) as source, daemon.open("wb") as output:
        shutil.copyfileobj(source, output)
with daemon.open("rb") as source:
    if hashlib.file_digest(source, "sha256").hexdigest() != manifest["files"][member.name]["sha256"]:
        raise SystemExit("Release backend/flowgate SHA-256 does not match release.json")
daemon.chmod(0o755)
PYTHON
     ;;
    *) echo 'Usage: scripts/check.sh --receivers [--binary PATH | --archive PATH]' >&2; return 2 ;;
   esac
   ;;
  *) echo 'Usage: scripts/check.sh --receivers [--binary PATH | --archive PATH]' >&2; return 2 ;;
 esac
 FLOWGATE_TEST_BINARY=$(realpath -e -- "$daemon")
 export FLOWGATE_TEST_BINARY
 if [ ! -f "$FLOWGATE_TEST_BINARY" ] || [ ! -x "$FLOWGATE_TEST_BINARY" ]; then
  echo "Daemon must be an executable file: $FLOWGATE_TEST_BINARY" >&2
  return 2
 fi
 mkdir -p .workspace
 go build -o .workspace/native-a ./fixtures/native
 cp .workspace/native-a .workspace/native-b
 for fixture in protection-refusal localhost integration outgoing; do
  rm -f ".workspace/run/$fixture-binary.json"
  scripts/lab.sh python3 "scripts/acceptance/$fixture.py"
  test -s ".workspace/run/$fixture-binary.json"
 done
}

if [ "${1:-}" = "--receivers" ]; then
 shift
 receiver_checks "$@"
 exit
fi

go vet ./...
# Real socket fixtures must not be blocked by the host's active application policy.
ordinary_peer_tests='^(TestDecisionLogAPIOnReadOnlyEndpoint|TestObservedCreationAuthorizationAndPersistence|TestTrafficAPIPermissionsAndProjection)$'
# Packages share this lab namespace. Serialize their kernel fixtures so one
# package's protection queue cannot change another package's baseline traffic.
# The explicit flag also overrides an inherited GOFLAGS package count.
scripts/lab.sh go test -race -p=1 ./... -skip "$ordinary_peer_tests"
# These three fixtures intentionally require a non-root Unix peer.
go test -race ./internal/daemon -run "$ordinary_peer_tests"
for check in test-passwordless-update test-update-and-start test-install-monitoring test-install-rollback test-release-preparation test-deployment-recovery test-deployment-uninstall test-script-hardening test-essential-networking test-apply-essentials test-electron-fontconfig test-clear-rules; do
 python3 "scripts/checks/$check.py"
done
FLOWGATE_ESSENTIAL_PLAN="$PWD/.workspace/essential-policy-fixture.json" go test -race ./internal/policy -run '^TestEssentialDNSReviewFiltersAndPersistence$'
# Each package owns its own netns: firewall fixture tables must not interfere.
for package in identity daemon hostfirewall; do
 scripts/lab.sh sh -c 'export FLOWGATE_TEST_PRIVATE_MOUNT=1 FLOWGATE_RUNTIME_NAMESPACE_TEST=1 FLOWGATE_ESSENTIAL_PRIVATE_NETNS="$FLOWGATE_PARENT_NETNS"; exec go test -race "$1" -run "Test(ServicePrivateMount|Observed.*Namespace|RuntimeBackingLiveNamespace|Essential)"' sh "./internal/$package"
done
(cd electron && npm run build && npm test)
scripts/build.sh desktop
QT_QPA_PLATFORM=offscreen build/desktop/desktop-test
QT_QPA_PLATFORM=offscreen build/desktop/snapshot-test
# These require separate namespace/host fixtures; never report them as covered.
echo 'Additional opt-in coverage: --wine; subordinate-ID user namespace coverage (FLOWGATE_USERNS_SCRATCH) requires a separate UID-mapping fixture.'
receiver_checks
if [ "${1:-}" = "--wine" ]; then
 scripts/build.sh windows
 scripts/lab.sh python3 scripts/acceptance/wine-integration.py
fi

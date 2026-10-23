#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
. ./scripts/go-env.sh
export PYTHONDONTWRITEBYTECODE=1
go vet ./...
# Real socket fixtures must not be blocked by the host's active application policy.
ordinary_peer_tests='^(TestDecisionLogAPIOnReadOnlyEndpoint|TestObservedCreationAuthorizationAndPersistence|TestTrafficAPIPermissionsAndProjection)$'
scripts/lab.sh go test -race ./... -skip "$ordinary_peer_tests"
# These three fixtures intentionally require a non-root Unix peer.
go test -race ./internal/daemon -run "$ordinary_peer_tests"
for check in test-update-and-start test-install-monitoring test-install-rollback test-release-preparation test-deployment-recovery test-deployment-uninstall test-script-hardening test-essential-networking test-apply-essentials test-electron-fontconfig; do
 python3 "scripts/checks/$check.py"
done
FLOWGATE_ESSENTIAL_PLAN="$PWD/.workspace/essential-policy-fixture.json" go test -race ./internal/policy -run '^TestEssentialDNSReviewFiltersAndPersistence$'
# Each package owns its own netns: firewall fixture tables must not interfere.
for package in identity daemon hostfirewall; do
 scripts/lab.sh sh -c 'export FLOWGATE_TEST_PRIVATE_MOUNT=1 FLOWGATE_RUNTIME_NAMESPACE_TEST=1 FLOWGATE_ESSENTIAL_PRIVATE_NETNS="$FLOWGATE_PARENT_NETNS"; exec go test -race "$1" -run "Test(ServicePrivateMount|Observed.*Namespace|RuntimeBackingLiveNamespace|Essential)"' sh "./internal/$package"
done
(cd electron && npm run build && npm test)
scripts/build.sh desktop
QT_QPA_PLATFORM=offscreen .workspace/desktop/desktop-test
QT_QPA_PLATFORM=offscreen .workspace/desktop/snapshot-test
# These require separate namespace/host fixtures; never report them as covered.
echo 'Additional opt-in coverage: --wine; subordinate-ID user namespace coverage (FLOWGATE_USERNS_SCRATCH) requires a separate UID-mapping fixture.'
go build -o .workspace/flowgate ./cmd/flowgate
go build -o .workspace/native-a ./fixtures/native
cp .workspace/native-a .workspace/native-b
scripts/lab.sh python3 scripts/acceptance/localhost.py
scripts/lab.sh python3 scripts/acceptance/integration.py
scripts/lab.sh python3 scripts/acceptance/outgoing.py
if [ "${1:-}" = "--wine" ]; then
 scripts/build.sh windows
 scripts/lab.sh python3 scripts/acceptance/wine-integration.py
fi

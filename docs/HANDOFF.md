# Continuation handoff

## Current: persistent firewall decision log (backend; not rolled out)

Capability `decision-log-v1`: decision-time records (pending/final/gap) from enforcing
host and isolated-lab daemons, stored in a separate `decisions.db` beside the rule
database (rules.db unchanged), 1 s durability window, 20,000 records/30 days, cursor
API `decision-log`/`decision-log-get` with admin/self visibility. See
[DECISION-LOG.md](DECISION-LOG.md). Real isolated demo
`scripts/decision-log-isolated.py` (run `.workspace/decision-log-1792272647`).
Separate test binary `.workspace/decisionlog-build/flowgate-decisionlog`; host
monitor, its database and collector state untouched. UI presentation is UI-owned.

## Current: host monitor runs daemon-owned UDP (collector disabled)

Root monitor PID 2152405, generation 4e18ec0723edb676c156a6b0ae4e9db9, source
ea13560 (executable SHA256 f9c446c1..., helper 118a8877...), same database and
UID1000 administrator plus `--udp-helper .../.workspace/udp-collector
--allow-traffic-control`. Collector **disabled** until the user Enables UDP in
Activity; enforcement stopped; rules unchanged (empty). Launch
`scripts/run-electron.sh --daemon /run/flowgate-api/daemon.sock`. Exact launch,
Stop, rollback and evidence: INTEGRATION.md "Daemon-owned UDP rollout". UI agent
owns the brief desktop acceptance. No host BPF, firewall or service changes.

## Integrated: daemon-owned UDP accounting + Electron consumer

Backend `15d6e1a` (daemon-udp-monitor-v1) merged with released UI
frontend/electron `66a0c02` as `611e221` (electron/ only, no conflicts). Build,
focused 18/18 and full Electron 45/45 tests pass (`.workspace/integration-611e221.log`);
Go unchanged. Kernel-backed isolated UI evidence (UI worktree `.workspace/
daemon-udp-ui-bVpoWV`, `daemon-udp-ui-KKXSTR`): real UDP4/6 Activity matched
receiver counts, Stop shows gaps with TCP continuing, restart gap without spike,
GUI exit leaves daemon/collector intact. Fixtures cleaned up. The running host
monitor PID2095594 lacks this capability (legacy path, no collection) until a
deliberate generation-checked restart per INTEGRATION.md; none was performed.

## Daemon-owned optional UDP accounting

The root `serve` daemon now supports explicit optional UDP helper ownership and
measurement delivery via existing Activity. Capability `daemon-udp-monitor-v1`
adds traffic-status/start/stop, explicit `can_control_traffic`, and daemon+collector
generation guards. Root-configured selected administrator delegation requires
`--allow-traffic-control`; rule/decision permissions do not grant it. Startup is
still non-enforcing and collection-disabled; TCP/rules survive collector failure.
See [DAEMON-UDP.md](DAEMON-UDP.md) for exact API, privacy, semantics, compatibility
and test commands. Build `.workspace/flowgate-udp-daemon` is separate; the running
host monitor is unchanged. Authenticated isolated kernel acceptance passed
(`.workspace/daemon-udp-1792270674-2133903`): receiver-backed UDP4/UDP6 bytes,
lifecycle/restart/crash, privacy projection, continuous TCP, unchanged firewall/
routes. Consolidated UDP display in the UI still needs its isolated Wayland check.

## Current: integrated Electron and updated root monitor

Full released frontend history through02554da757942887f3dff8b4c633bcd0f824a1b9
is merged with backend8ef90cd (mergee2ef7f7, no conflicts). Actual isolated
sandboxed Wayland creation/edit/conditional-delete/policy refresh passed. Controlled
non-enforcing monitor restart is complete: PID2095594, generation
 a0109011f97dad19dd723e7e483d7860, same database, UID1000 administrator, unchanged
empty rule inventory, enforcement stopped. Host Wayland Activity + native preview
only passed; GUI exit leaves daemon running. No host test rules were saved.

Launch `scripts/run-electron.sh --daemon /run/flowgate-api/daemon.sock`.
[INTEGRATION.md](INTEGRATION.md) records full included commits, exact Stop,
rollback/evidence and remaining live-enforcement limits. Earlier no-restart/old-API
entries below describe their original increment; this rollout supersedes them.
Qt/default read-only launchers remain available. Frontend polish remains UI-owned.

## Observed-application creation increment

Primary capability `observed-rule-create-v1` adds generation/principal/draft-bound
30-second preview and save from a freshly verified single-holder native Activity
context. Explicit protocol/direction/address/ports/absolute expiry; identity comes
only from backend inspection. Stored-only monitoring, existing authorization,
SQLite atomic publication and precedence remain. Creation never approves pending
packets; repeated same-token saves are bounded acknowledgements, not duplicate
rules. See [OBSERVED-RULES.md](OBSERVED-RULES.md) for schema, examples, errors,
reconciliation and native/namespace limitations. New `.workspace/flowgate-creation`
build leaves the root monitor/executable untouched; eventual restart unexecuted.
Focused race/vet/API/shared-FD/SQLite checks and isolated receiver Allow->Block
passed. No frontend integration or broader matrix rerun.

## Policy summaries/explanations increment

Started5b66323, backend/API/tests/docs only; no frontend integration. Capability
policy-explanations-v1 primary-only. POLICY-EXPLANATIONS.md has exact shape/errors,
string versions/order tokens, actual Unix API examples and limitations. App summary
is configured inventory plus conservative uniform proof; recorded-event explanation
uses current evaluator, not live/historical admission. No creation authority.

Root monitor1973082/gen5a559274aa006090cdc4bb5cd8faed47 was preserved on old code;
no restart or executable-path replacement. New build .workspace/flowgate-policy.
An eventual deliberate restart is needed to expose the API. Tests reproduce with
scripts/check-policy-view.sh; reuse settled receiver/accounting/coexistence/UI
results because no verdict path changed. UI agent owns consumer independently;
observed-app creation is now supplied by the separate observed-rule-create-v1
workflow above, never by the read-only associations.

## Tailscale coexistence increment

Started4859df5. Backend/CLI/isolated fixtures/docs only. No frontend integration.
COEXISTENCE.md is authoritative for exact supported profile, current host findings,
read-only tailscale-inspect/doctor flags and future explicit monitor->evaluation
handoff. Root monitor1973082/gen5a559274aa006090cdc4bb5cd8faed47 is preserved;
no host enforcement/Stop/BPF/network mutation was performed. Incoming+administrator
profile inspection now passes; outgoing/both and unsafe mark/routing modes refuse.
Actual TUN/kernel/receiver evidence uses emulated metadata and userspace L3 relay,
not an actual tailscaled instance. Foreign config changes are not continuously
revalidated. New policy_database_owned refusal protects the DB; active controller
companion is host-monitor/backend_mode host-enforcement/read-only for existing UI.
Reuse .workspace/tailscale-verification.log and tailscale-daemon-tests.log; no UDP
accounting/Wine/full frontend matrix rerun. UI branch remains separately owned.

## Authorized live root monitoring setup

Continued 08a4112. Fixed-path `monitor-setup` validates or creates only
/run/flowgate-api (0711) and /var/lib/flowgate (0700). Both already existed and
were preserved. Root `serve` actually running PID1973082, generation
5a559274aa006090cdc4bb5cd8faed47, UID1000 admin, enforcement stopped. Keep it
running as user requested. Exact commands/stop token in AUTHORIZATION.md.
Actual UID1000 API and sandboxed Wayland Electron verified machine-visible
Activity and readonly rejection. Root-only generation-checked monitor-stop is
exposed by non-enforcing daemon only; the companion uses host-monitor mode plus
backend_mode for compatibility. Main daemon-monitor permission-aware frontend
integration remains UI-owned follow-up; no visual branch was integrated.
Root service, live enforcement and BPF were not activated. The earlier root
architecture handoff below describes its historical pre-activation snapshot.

## Root architecture increment

Started 2752e1046cc36e2e9459453e5f49ab2070376551. Backend/CLI/fixtures/docs only;
frontend graph/visual branch remains separate and unintegrated. Read
AUTHORIZATION.md and API.md for explicit-administrator-v1, `serve` non-enforcing
mode, secure path requirements, self projection and writer lock. Existing desktop
launchers retain the selected-user prototype. UDP remains a separate prototype;
do not claim one-daemon accounting is complete. User authorized sudo -n absolute
backend for read-only host checks; doctor/sockets ran, no root host endpoint or
collection/enforcement activated. At that checkpoint Tailscale/marks refused;
the current coexistence increment supersedes that blanket refusal.

## Doctor increment

Started ffa5c45; backend/CLI/check fixtures/docs only. No frontend integration or
Electron/Qt presentation/auth-script changes. Read DIAGNOSTICS.md for schema 1,
shared startup checks, reason codes, read-only guarantees, exact privileged
inspection command and the historical tailscale0/tun refusal. Existing UDP helper needs
metadata rebuild; no accounting event/byte semantics changed. Reuse kernel/GUI
evidence; only focused diagnostics/race/vet/namespace checks ran.

The frontend session owns graph/visual work on frontend/electron; its released
cc9ce4e graph commit was not integrated in this task. Preserve that work separately.
No privileged host operations or automatic activation were performed.

## Integrated runnable checkout

Backend starting snapshot `1729c292e29e5feef73b286864aa44bf4d551fcb`; frontend final
release `297fe09bd4c1b29076a74fb3a51897673104db54` fully merged as `838871f8dd9705ded3574e930468e03eb02ce9fb`.
Qt migration checkpoints `e3890cb`/`b006898` plus final strict acknowledgement check
are retained. No default launcher change: run `scripts/run-electron.sh` for Electron
or `scripts/run-desktop.sh` for Qt. Both normally read-only. Both clients migrated
conditional Delete; read API.md for exact tokens and Electron uint64 limits.

Main integrated smoke and Qt focused checks passed; current STATUS records logs,
screenshot and scope. `scripts/check-integration.sh` reproduces only these focused
paths. Actual KDE tray activation was exercised; Quit confirmation response was
simulated. Authentication, host coexistence and privileged Electron UDP activation
are not established. No live host enforcement/collection was performed. Frontend
ownership was released before integration; do not restart feature-branch integration.

## Previous backend conditional deletion increment

Started dbe651f. Read API.md for `conditional-rule-delete-v1`, exact requests,
structured outcomes and legacy compatibility. Electron/Qt adopted the new operation in the integration above; frontend files and branches were not touched/integrated. Backend Save
stale/missing/authorization/persistence codes are additive. Native ownership and
UDP evidence remain reusable. Focused API/CLI/race/SQLite and isolated UDP receiver
checks passed; no live-host enforcement. No database migration.

## Native ownership increment

Started at a48ee2b; backend observation-only changes and native fixtures. Read
ATTRIBUTION.md for additive API fields, worker/TGID identity, bounded sample counts
and focused checks. Electron/Qt/shared authentication and enforcement are untouched.
Do not integrate frontend/electron as part of this task. No privileged host
collection was activated. Reuse settled UDP acceptance below.

## Completed UDP acceptance

The user-authenticated `.workspace/udp-verified-o2oghdyo` run passed the complete
isolated native UDP4/6 accounting/lifecycle suite and unprivileged Wayland 3/3.
Inspect its logs/result metadata and real measured-rate screenshots before doing
more work. No privileged rerun is needed for documentation or fixture cleanup.
Current STATUS and UDP.md state the exact coverage, byte definitions, overhead and
remaining limits. Production counter/BPF code did not need a verifier fix.
A small post-acceptance change makes a dormant fixture child exit quietly on
barrier EOF; it does not change counted operations. Qt confirmation copy now
reflects the completed isolated validation. Preserve these results and TCP/
Unidentified behavior. Live-host collection remains separately opt-in/unverified.

## Historical continuation before the successful expanded run

Start was clean c631a70de97390966a2e83e159ebd5eb38adcc6f on milestone/backend.
User's authenticated `.workspace/udp-privileged-1792255664` run passed real UDP4/6
baseline checks. The collector log confirms successful loading/attachment. Reuse
that evidence; do not claim it covers all lifecycle/GUI cases.

Implemented native alpha/beta wildcard/shared/reuseport/rebind fixtures, a broader
root-namespace receiver harness with desktop-UID processes, and an outside-namespace
unprivileged Wayland measured-rate test. Fixed UDP Activity identity changing on
connect by omitting endpoints from the socket-lifetime key. Source counter logic
and TCP/firewall behavior did not change.

Still needs desktop authentication: `scripts/check-udp-isolated.sh` (one command,
no outer sudo). The only agent noninteractive attempt refused authentication; do
not retry it repeatedly. The script builds its prerequisites, then starts only a
disposable namespace and captures all receiver/Wayland/CPU/RSS/loss evidence in
`.workspace/udp-verified-*`. Review any actual failure before broadening tests.
Current passing native smoke is not BPF proof. No live-host collection was started.

## Historical: optional UDP experiment and original privilege blocker

Started clean at1c3b1b23b62af30332a063d9ac2ea59dbe076761 on milestone/backend.
The BPF source/helper, collection-only authenticated API, normal observer adapter,
monotonic UDP rates and explicit Activity Enable/Stop are implemented, but no BPF
program could be loaded in the available user namespace (EPERM). sudo requires
interactive authentication. Basic TCP/Unidentified regressions and real Wayland
failure states passed. This is not receiver-verified UDP support.

Read UDP.md before further work. Next action is `scripts/check-udp-isolated.sh`
after reviewing/authorizing its exact sudo/unshare operation; build prerequisites
are listed there and already present. It loads only namespace/UID-filtered probes
inside a fresh test namespace, without host firewall/route/security changes.
After obtaining verifier/receiver evidence, fix any demonstrated issue and finish
shared/reuseport/restart/loss and real unprivileged Wayland UDP-rate checks. Do not
activate host collection to substitute for isolated verification. No game work.

## Latest: TCP Activity metrics and Unidentified presentation group

Started from clean 3634fdadba706cd48bb560092176112a703116ba on milestone/backend.
Read TRAFFIC.md for counter meaning, supported TCP4/6 and explicit UDP limitation.
Normal launch `scripts/run-desktop.sh` requires no activation. Default refresh is
now 1 second plus collection. No privileged collector/enforcement was started.

Reproduce with `QT_QPA_PLATFORM=wayland WAYLAND_DISPLAY=wayland-0 scripts/check-traffic.sh`.
Current evidence is at the top of STATUS.md. Remaining useful step: choose a narrow
optional UDP accounting source, with explicit authentication/collection-only API,
if UDP rates are required; do not repurpose NFQUEUE admission counters or queue
occupancy. Keep existing firewall lifecycle and deferred game detection unchanged.

## Latest increment: outgoing profile and atomic rule editing

Actual starting checkout was `9235954c8e983bd5e31062ec79f3dcd97cff71e5`.
Despite the task premise, it lacked the structured prompt and editor, so these
were implemented alongside outgoing control. Final SHA is in the delivery report;
verify HEAD rather than resetting. All changes are local, no host enforcement.

Run `scripts/run-desktop.sh`. Choose the evaluation profile before Start; incoming
is default. Create from a current pending request, edit stored rules, and use
backend previews. See RULES.md for version/duplicate/overlap semantics.
Focused runner and evidence are at the top of STATUS.md. Both profiles share the
existing queue/retention and identity pipeline. No Wine work is needed next.

Next smallest step: review the optional outgoing profile's fail-closed impact on
other-UID services and short-lived UDP sockets before separately authorizing any
live host evaluation. No new authorization is needed to run isolated checks.

Continue in /home/flowgate-user/Apps/flowgate, branch milestone/backend. Verify HEAD and
preserve unrelated work. Read applicable AGENTS.md, README, PLAN, STATUS, SEMANTICS
and VISUAL. Source scripts/go-env.sh before Go commands. Scratch outputs belong
under .workspace; check its coordination notes.

## Running program

Normal command: `scripts/run-desktop.sh`. This starts a private unprivileged host
observer and the existing native Qt Activity view. No synthetic traffic, firewall
hooks, Wine helpers, service installation or host protection. Close the window or
press Ctrl+C in its terminal to stop its observer. Duplicate launches are independent.
A separately managed `flowgate observe --socket PATH` survives client closure.

The user accepted the original prompt demo. Keep `scripts/demo-desktop.sh` separate:
it enforces the original isolated native test traffic. The new host-control tests
exercise a separate incoming-first profile in disposable veth namespaces. Its GUI can close while enforcement
continues; q/Ctrl+C in its terminal tears down that lab.

## Sources and verification

The bounded collector/cache/state evidence lives in internal/identity/activity*.go;
internal/monitor owns one serial worker and latest snapshot. Host list API returns
activity and always rejects decisions. Existing enforcement matching is preserved.
The Activity widget is part of the existing frontend, not another application.
Shared sockets appear once; Unknown initiation is never inferred from ports.

Focused runner: `QT_QPA_PLATFORM=wayland WAYLAND_DISPLAY=wayland-0 scripts/check-monitor.sh`.
It checks host loopback TCP/UDP v4/v6, SYN-sent/established/listening states, shared
holders, path identities, exit, API mutation denial, Qt interaction and one lab
Allow smoke. Reuse existing accepted desktop and Wine evidence; no full matrix
unless changed behavior warrants it. Offscreen runs must be labelled as such.

STATUS.md indexes host/go/launcher logs; VISUAL.md indexes design captures and
Wayland evidence. Screenshots filter to workspace fixtures, avoiding unrelated
host metadata. TCP observed rates/totals now have bounded coverage (TRAFFIC.md); no history
completeness, real-game or host-protection claims.

## Design coordination and integration

Runnable checkpoint before concurrent design:
883db80dd457591e0fa12af49f4d9ab1e9332020.
Design branch frontend/netlimiter-design at .workspace/worktrees/netlimiter-design.
Complete design consists of 77286d286faa169a81f455426dac933ee13a8b81 followed by
2f375035cb43b2210d8c64d9411d09085d0070d7; the tip alone is not the full design.
The internal designer stopped at the first commit; external session
01a1465b-dadc-7010-91ad-6230a47cda24 then exclusively refined and released ownership.
Root reviews/cherry-picks both and runs focused integration smoke. Final report
names the integrated SHA without a self-referential commit update.

Backend/API/scripts/tests/main docs belong to integration. During concurrent work,
desktop presentation and VISUAL.md belong to design. Coordinate functional changes
explicitly and use the Yacwu relay for the external session. No competing rewrites.

The desktop uses compact Activity and permission views.
Use own Qt components/assets and FlowGate branding: dense tree, compact menus,
toolbar/tabs, right Info/rules panel, lower chart region. Missing measurements and
controls stay explicitly unavailable. Plain-text details, generic icons and other
remaining differences are acknowledged in VISUAL.md; do not claim pixel identity.

## Current increment: coherent desktop evaluation

Normal command remains `scripts/run-desktop.sh`: one window, Activity read-only by
default, independent control endpoint. Start 5-minute evaluation explains the profile,
opens Konsole/system sudo and attaches only after authenticated matching-generation
readiness. Stop and Status/recovery also use terminal sudo. GUI policy authorization
was not extended to global Stop. No live evaluator was run during development.

New code: desktop/observation.* and evaluation.* keep the small connection/terminal
bridges separate; Window owns the current state, stored rules and notifications.
The terminal bridge is scripts/desktop-control.py. Root host-session safely snapshots
the executing binary under /run/flowgate; the watchdog uses that snapshot. Existing
host-start/status/stop/recover commands remain available without Qt.

Reproduce focused evidence with
`QT_QPA_PLATFORM=wayland WAYLAND_DISPLAY=wayland-0 scripts/check-unified.sh`.
It uses real namespace enforcement/receiver traffic and read-only observation,
with an explicit authentication test seam. The separate bridge check simulates sudo
in that namespace. Reuse the accepted broader native/Wine evidence. STATUS indexes
logs and the Qt log prints the current controlled-fixture capture directory.

Remaining validation: explicit user-run real-host terminal authentication and
coexistence; notifications depend on desktop settings. No sudoers/service/autostart
installation, host firewall/network/VPN/security change, game/runtime/prefix or
launcher changes. Do not activate live enforcement during further development.

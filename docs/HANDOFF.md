# Continuation handoff

## Current: Activity round 5 (menus, display Units and chart presentation)

Exact clean UI release **f2f9ae43a1d0313fc7c420c46cee0c2107568f78**, based on
**4422cfa**, is fast-forward integrated with full prior history. Explicit source and
Windows ownership release was verified first. Backend/API remains **6c68f8c**;
no privileged deployment or new collection was needed.

Changes: File/Tools/Window/Help use existing operations; persistent display Units
(byte/bit, explicit decimal SI) are independent of TCP/UDP accounting Source and
raw sorting. Connection labels use compact endpoints while state/direction evidence
remains in glyphs/details. Chart legend uses source-specific unique-socket totals;
rate axes, timestamps, bounded10min window and sample details preserve unavailable,
partial, restart and discontinuity semantics. This is bounded client observation
history, not persistent statistics or connection lifecycle history. No incompatible
TCP/UDP totals, guessed zero counters or historical per-application inventory.

New main-checkout build/typecheck and **18 focused asset/units/history/model tests**
pass (`.workspace/ui-r5-integration-{build,tests}.log`). Reused exact-release sandboxed
Wayland real isolated menu/units/pause/selection/popup/narrow journey and real TCP
socket/application/shared-socket chart comparison. Rule journey evidence in UI
worktree `.workspace/round5-journey-yNI5mm/` includes `metadata-correction.txt`:
its original fixture description was stale; the run actually created application
In Allow and process Out Block via existing preview/save, then exact conditional
Delete restored0rules. Original results/screenshots are preserved, not silently
rewritten. TCP chart evidence: UI `.workspace/gr-RBo9Jd/`.

Fixture ownership was explicit: UI alone drove rsf-c780 until DONE. Backend verified
actual generation dabcebbbaf2bf66829b04c0d416edfa9, daemon-monitor and empty rules,
then sent only that fixture's quit command. Its supervisor logged CLEANED for daemon,
instances and peer; both API sockets are removed. TCP fixture/observer/UI cleanup was
reported by the UI owner. WinBoat Units/Rate/root selection restored, viewer closed,
preferences restored. No host daemon, UDP collector, policy or networking action.
The host root API remains unavailable after reboot; no host acceptance claimed.

Before/reference/after complete-window images (native scale, distinct controlled
Linux versus Windows content):
`.workspace/netlimiter-reference/rule-status-r5/01-before-reference-after.png`;
process-popup, real-chart and narrow captures are adjacent. Full account and exact
remaining work: `electron/ACTIVITY-PARITY-R5.md`. No visual completion score.
Undock needs a separately bounded shared-selection/window/mutation ownership design;
chart pan/zoom and richer one-second history remain different. Stored Ask stays
explicitly deferred; no new capability or working Ask control. Browser fault cause
is still unproven; readonly monitoring recorded faults even without Electron, with
no recorded OOM/GPU reset. No browser restart/profile changes were performed.

Basic launch: `scripts/run-electron.sh`. To use the root API after separately
authorized restoration: `scripts/run-electron.sh --daemon /run/flowgate-api/daemon.sock`.
This task neither restores it nor activates enforcement.

## Current: Activity round 4 and verified font delivery

Integrated exact released checkpoint **652dab3fdec0941698bc3d92b4b4f31849197c05**
by fast-forward from57cfd86, preserving complete UI2 release **f803ce3**, accepted
review fixes **01e3ab5**, and UI owner's font-delivery correction **652dab3**.
Backend remains **6c68f8c**; no API, policy, accounting or host deployment changes.
UI ownership transferred from UI2 to flowgate ui01a1465b at the user's direction;
the new owner explicitly released this immutable checkpoint before integration.
It may continue the next visual round independently; do not merge its moving branch.

Whole-window corrections: grouped toolbar and source/layout controls; default
four-column Status table with optional Details; Rate/Total view; unified footer;
chart options in its menu with pause/resume; compact Rules columns and popup scope.
Before-click direction, application/process target, protocol, lifetime and endpoint
scope remain visible; version, preview and uncertain-response safeguards remain.
The follow-up fixes preserve current selection on chart resume and reject stale
in-flight redraws. Stored Ask remains deferred; no working Ask control was added.

Font evidence now distinguishes intended and actual delivery: NetLimiter declares
Segoe UI explicitly; licensed Selawik is bundled as its metric-compatible alternative.
The original round4 protocol returned404 for the fonts. UI652dab3 serves exactly
three known font files with font/ttf and retains sandbox/CSP. Actual sandboxed
400/600/700 document.fonts.load failed before and succeeds after. Original round4
screenshots predate this fix and must not be cited as proof of Selawik rendering.
Corrected native-scale reference/before/after comparison:
`.workspace/round4-integrated/reference-before-after.png` (fixture content differs).

Reused UI2 build/typecheck,77 unit, synthetic normal/narrow, real private popup
journey, and populated real TCP chart evidence. New owner's read-only01e3 check
passed pane close/reopen, presets, Rate/Total, Status/Details, chart source/window,
pause-selection-resume (legend matches selection), and outside dismissal. Evidence
in UI worktree `.workspace/rs/r3-panes/result.json`; font probes/screenshots in
`.workspace/round5/`. New main-checkout build/typecheck and **8 focused tests** pass
(`.workspace/ui-r4-integration-{build,tests}.log`). No receiver/UDP/watchdog matrix
was repeated. Fixture rsf-c780 is intentionally retained under the new UI owner's
exclusive lifecycle responsibility for the next isolated round, not claimed cleaned.
WinBoat settings/Units/Rate restored and viewer closed by that owner.

Host daemon API remains unavailable after the external reboots; host acceptance
was not possible. No root daemon restoration, collector action, rule write or
network change was performed. A separate read-only Firefox investigation observed
faults with no Electron sampled; that does not establish an Electron cause or
prove launch safety. No browser restart/profile change was performed here.

Remaining visual differences include menu semantics, connection labels, missing
filter objects/unsupported rule families, no Undock, and Linux font rasterization.
No fidelity percentage or design-complete claim. Details: `electron/ACTIVITY-PARITY-R4.md`.
Basic unprivileged launch: `scripts/run-electron.sh`; daemon-connected launch needs
separately authorized monitor restoration before using
`scripts/run-electron.sh --daemon /run/flowgate-api/daemon.sock`.

## Current: UI2 Activity fidelity round 3 (released and integrated)

Released UI **fbe9737e7c65e25743007151ff46545a812a4c99** (including checkpoint
97b20af, based on aea5f1a) is integrated at **197ddece88fc61b871846f3134f39bf08232da5b**.
Clean release and explicit ownership release were verified before merging. The
stored-Ask dependency note in **0d0a2be** is retained; backend production code
remains **6c68f8cd0627bce69f15f4e995a3cf68fa161215**, with no API change this round.

Changes: Deny presentation still sends API action `block`; Ask/unsupported actions
remain neutral and read-only. Hover/selection rule-family icons, popup anchoring,
Priority composition, expanders, chart legend and local pane Open Window/Close
controls follow the inspected reference. Pane preferences do not change collection
or enforcement. Stored Ask remains deferred. Font family is unverified; this is
not a claim of complete NetLimiter fidelity. Details: `electron/ACTIVITY-PARITY-R3.md`.

Reused exact-release evidence: UI build/typecheck and **77 unit tests**; real private
fixture popup/exit journey (`electron` worktree `.workspace/rule-status-real-mkoDhk`);
pane/hover run (`.workspace/rs/r3-panes/result.json` in that worktree). UI owner
reported rsf-c778 orderly cleanup; earlier private fixtures died in the external
reboots. Backend owned no new fixture. New integrated checks: Electron
build/typecheck and **6 focused rule-chip/editor-presentation tests** passed; logs
`.workspace/ui2-r3-build.log` and `.workspace/ui2-r3-tests.log`. No kernel, UDP,
firewall or Go matrix was repeated for these presentation-only changes.

**Runtime correction after external reboots:** the previously deployed root daemon
is no longer available: `/run/flowgate-api/daemon.sock` and its runtime directory
are absent, and historical PID2847094 is gone. Thus the previous active UDP state
is historical, not current verified collection. The root storage directory remains;
no database mutation, daemon restoration, collector attachment or host networking
change was performed in this round. Host UI acceptance was **unavailable**, not
passed. Older deployment sections below describe historical state.

Basic unprivileged Activity launch from the main checkout: `scripts/run-electron.sh`
(owns a read-only observer). The daemon-connected command remains
`scripts/run-electron.sh --daemon /run/flowgate-api/daemon.sock`, but requires a
separately authorized restoration of the root monitor first; this integration does
not restore it or activate enforcement.

## Current integration: UI2 floating Rule Status and explicit TCP+UDP

Full released UI **09b56426a8a97677ce9489a0aaa0098a7208e646** (UI2 c772f7c2) is
fast-forward integrated atop clean backend/test/docs **77f7e6d**, preserving0989411
and all prior history. Explicit clean release and Electron ownership release were
verified first. Backend production release **6c68f8cd0627bce69f15f4e995a3cf68fa161215**
adds only the requested `observed-rule-any-protocol-v1`: explicit `*` means TCP+UDP
in one application/process rule, never all IP protocols. Validation, pure matching,
overlap, summaries, previews, history and persistence agree. Existing scope,
principal/identity, process tiers, versioned edits/Delete and replay rules remain.
Legacy implicit wildcard narrowing is rejected `protocol_scope_changed`.
Exact contract: [OBSERVED-RULES.md](OBSERVED-RULES.md#tcpudp-observed-creation-extension).

UI adds a floating quick-set popup, rule-family matrix, Info View composition and
compact cells. One click uses the displayed exact scope, backend preview and same
draft save; verified differences/errors/uncertainty stop the chain. Multiple rules
still require an exact selection; edits preserve target/filter/expiry/version,
stale Delete does not recreate anything. Current old-cap host keeps the explicit
TCP|UDP choice. Limit/priority/quota rows are **static unavailable**, not new policy
features. No Ask action, shaping, bandwidth allocation or new enforcement behavior.
Visual differences/measurements are recorded in `electron/RULE-STATUS.md`; this is
not a claim of complete NetLimiter fidelity.

Evidence reused: UI release real popup/creation, 76 unit checks, synthetic and
read-only host acceptance; earlier process/UDP/watchdog/coexistence evidence.
New bounded backend race/vet checks pass; `.workspace/ap-receiver` real namespace
TCP/UDP IPv4/6 both-direction Allow/Block, process override and sibling/app fallback,
uniform summary, wildcard decision snapshot and owned-only cleanup pass. Scoped
address/port restrictions and scoped/mixed summaries have focused regression tests.
Separate `.workspace/flowgate-any-protocol` source6c68f8c SHA256
`7b8fbbe065001c78641eb2157b747d085a93359eab045fdffe478eb70ab83893`;
no running executable was overwritten. The legacy-edit guard does not change the
receiver-tested wildcard matching path.

Main checkout build/typecheck, **14 focused consumer tests** and sandboxed synthetic
normal/narrow process presentation pass. Logs `.workspace/ui2-r2-{build,tests,presentation}.log`;
synthetic captures `.workspace/pp-28APSb`.
One additional real sandboxed Wayland journey was warranted by the UI release's
inactive-popup Delete fix (then only synthetically tested):
`FLOWGATE_TEST_READY=<fresh fixture>/ready.json FLOWGATE_EXIT_ALPHA=1 node electron/test/rule-status-workflow.mjs`.
It **passes** at exact UI09b5642/backend6c68f8c, including one-click wildcard creation,
process-only target/sibling independence, exact edit/disable/stale-delete/conditional
Delete, narrow view, actual alpha exit, inactive-popup Delete and GUI exit preserving
private daemon. Evidence `.workspace/rule-status-real-qxV6RE`, log
`.workspace/ui2-r2-real-exit.log`. This closes the specific live gap in the UI release
note; no firewall/accounting/expiry matrix was repeated.

Fixture ownership was explicit: UI alone drove `.workspace/ap-ui` until DONE;
backend then cleaned it. Main follow-up used a fresh `.workspace/ap-final-exit` with
one driver. Both supervisors exited0, daemon/instances/peer cleaned and primary+
companion sockets removed. Offline disposable DB/evidence retained only in workspace.

Host read-only before/after summaries match exactly: PID2847094,
generatione47c8938265ebf19cacc1fee5a681c8c, UDPac3056b3b8f3299dce5dc2b57985808f active,
enforcement stopped, rules0. No host restart/upgrade, policy write, collector action,
BPF attachment or networking change in this support round. Deployed60d35a3 already
supports process rules but **does not expose the new wildcard capability**. A later
separately authorized daemon upgrade is required for TCP+UDP one-click mode there;
current normal UI uses the explicit per-protocol fallback. Retained Qt has no
wildcard selector and is guarded against implicit narrowing, not fully migrated.
Normal launch from the main checkout remains:
`scripts/run-electron.sh --daemon /run/flowgate-api/daemon.sock`.

## Current integration: Activity Rule Status quick-set (UI 897cd43)

Released UI **897cd43f937998bb2b9ff4a810cf628caf19b36b** (UI2 c772f7c2, parent 99b13fc)
fast-forwarded; electron-only, no backend/API change. Cells show glyph+action+scope;
process rows show own rules or dimmed backend `application_*` fallback; inline
setter: Allow/Block click runs the existing preview, inline "Draft · not saved"
review, explicit Save; one applicable rule edits that exact id/version, several
require a pick; expired token needs "Review again"; duplicates/errors shown
verbatim. Contract, discrepancies and remaining gaps: `electron/RULE-STATUS.md`.

Reused UI exact-release evidence (backend 60d35a3 isolated fixtures rsf-c772/c773,
both cleaned): real `rule-status-workflow.mjs` process CRUD/exit journey, synthetic
presentation runners. New here: main-checkout build/typecheck and 76/76 unit tests
(`.workspace/rulestatus-integration.log`). No combined smoke: integrated tree equals
the released tree. Host read-only check (`.workspace/rulestatus-host/`): sandboxed
Wayland UID1000 with the launcher's exact arguments; app/process/connection
selection drives Rule Status, process tier + app fallback rendered, existing host
sockets explicitly Unknown/Listening/Unconnected, a stalled local loopback SYN shows
known Outgoing (→). Fast loopback handshakes stay Unknown by design (not sampled).
Normal `scripts/run-electron.sh --daemon …` rendered sandboxed Wayland and exited0.
No host rules, previews, collector, evaluation or daemon actions. After: same PID
2847094/generation/collector ac3056b3…, enforcement stopped, rules0.

Remaining: inline panel vs NetLimiter floating popup; deliberate review step;
target rows vs NetLimiter rule-family rows; Info View order/Tools; fonts/icons;
no stored Ask/weights/limits/quotas; host direction known only for sampled handshakes.
Older runners activity-rules/creation/policy/process-rules-workflow.mjs still use the
removed setter selectors and need updating before reuse. UI2 round 2 (NetLimiter
popup composition) is in progress separately; integration owner: backend 01a145f0.

## Deployed: process-instance rules on the host monitor

Root monitor now runs exact-release **60d35a3** (SHA256 `882556c5…ebd05`), PID
**2847094**, generation **e47c8938265ebf19cacc1fee5a681c8c**, same sockets/database/
arguments/UID1000 administrator grants; `can_control_evaluation:false` (no new grant).
`process-instance-rules-v1` and `activity-initiation-v1` are now live on the host.
UDP restored active (collector `ac3056b3b8f3299dce5dc2b57985808f`, helper2847108,
fresh baseline). Enforcement **stopped**, rules0. First attempt auto-rolled back on
an over-strict permission check (real rollback exercise); second attempt succeeded.
Stored process-rule documents and inactive inventory are durable data even though
enforcement is session-bound: once any exist, do not downgrade to an executable
that rejects schema3 and do not delete them as a rollback step; a downgrade needs a
reviewed data-preserving migration/restore plan first. The saved inventory JSON is
an empty API snapshot, not a SQLite backup. Exact record, rollback limits and
evidence: [INTEGRATION.md](INTEGRATION.md). Host-state statements in older
sections below ("deployed1732584 lacks process-instance-rules-v1") are superseded.
Host UI acceptance stays read-only. Launch:
`scripts/run-electron.sh --daemon /run/flowgate-api/daemon.sock`.

## Current integration: native process-instance rules

Backend **60d35a366ae0104f9131f36916ff4172ef71ce71** and explicitly released UI
**a73276ea4c846f5ea757bd01922a5455787b170a** are fully integrated by fast-forward,
retaining e2f3f29 and all earlier frontend history. UI worktree was clean and
ownership released before integration. No competing frontend edits were made.

Primary `process-instance-rules-v1`: server-issued pidfd/native/session binding,
process tier before application fallback; existing priority/ID order inside each.
Exact contract, permissions, schema3/inactive restart behavior and same-executable
exec limitation: [PROCESS-RULES.md](PROCESS-RULES.md). No PID-only permission or
implicit application widening; process lifetime is session-bound, not persistent.
Preview/save revalidation, versioned edits and conditional Delete retain full target.
Policy-view separates own instance rules and app fallback; Decision Log preserves
immutable actual-target snapshots. Creation never approves existing sockets.

Focused Go race tests pass for identity/policy/daemon/Decision Log/store; vet passes
for those plus hostfirewall/cmd. Real disposable receiver evidence `.workspace/pr-guard`
passes incoming/outgoing TCP/UDP IPv4/6 process Allow/Block versus sibling,
application override/fallback, disable/enable/delete, actual exit/different-executable
exec, inactive restart persistence and historical target snapshots. Exact-release
binary `.workspace/flowgate-process` source60d35a3 SHA256
`882556c5c977765b678c4dd09521bef6dc596e4532f6af223fcca073ea4ebd05`.
Final source adds application metadata labels only after receiver run; actual
verdict logic is unchanged. PID reuse is simulated generation coverage, not an
actual forced PID-wrap experiment. Fork/thread identity cases are deterministic;
no BPF/UDP accounting/watchdog matrix was repeated.

Exact60d35a3 held fixture `.workspace/pr-ui-release` was exclusively driven by UI:
real sandboxed Wayland first process Allow, distinct sibling/parent, application
Block fallback, exact edit/disable/enable/Delete preserving app rules, recreate,
alpha exit, inactive target/stale draft and input focus, GUI exit preserving daemon.
Evidence UI worktree `.workspace/process-rules-real-rbmfwl`; final surviving beta
narrow capture shows fallback only. UI explicitly sent DONE before backend cleanup;
supervisor exited0, both sockets removed, both instances/peer gone. Disposable
inactive/app records remain only in ignored offline evidence DB. UI initial runner
association-settling failure was corrected; only its final passing run is accepted.

Main-checkout build/typecheck, **23 focused frontend checks**, and sandboxed
**synthetic** process presentation pass (normal/narrow, exit, input/focus, no mutations).
Logs `.workspace/process-integration-{build,tests,presentation}.log`, captures
`.workspace/pp-nf0PUV`. Exact real UI/receiver evidence reused; no additional matrix.
This proves scope correctness, not overall NetLimiter visual fidelity or support
for its unsupported policy families. UI intentionally permits inactive Delete only;
backend also permits disabling inactive records, never re-enabling/rebinding them.

Read-only host check: same PID2201352/generation0840f7c256126f1708702f27c5b26551,
UDP43a091abb81a09901be2c9b460080ee1 active, enforcement stopped, rules0. No host
restart, executable replacement, policy write, collector interruption or BPF attach.
The deployed1732584 build **does not expose process-instance-rules-v1**. A future
separately authorized daemon upgrade is required; current host UI explicitly gates
this workflow rather than approximating process-only with application-wide scope.
Normal main-checkout launch remains:
`scripts/run-electron.sh --daemon /run/flowgate-api/daemon.sock`.

## Current integration: Activity rules and initiation

Released UId3268a4 fully integrated atop backendb9840d0, retaining4105194.
`activity-initiation-v1` provides bounded observed TCP initiation; no new policy
engine or permission authority. Existing APIs supply complete relevant-rule lists,
first-rule creation, quick edits and conditional Delete. Process-instance scope is
an explicit PLAN follow-up, not implemented as an application-wide approximation.
Focused race/vet, real TCP4/6/API and exact-release Wayland journey passed;
integrated build+18 focused tests+synthetic presentation passed. Fixture CLEANED
only after UI DONE. Host same daemon/active UDP/stopped enforcement/rules0; its old
build lacks the new initiation capability and requires a future authorized rollout.
Exact source/hash/evidence and limitations: [INTEGRATION.md](INTEGRATION.md).
Normal launch: `scripts/run-electron.sh --daemon /run/flowgate-api/daemon.sock`.

## Backend UI support: observed Activity initiation

New additive `activity-initiation-v1`: rows carry initiation state/direction/source/
reason/last handshake observation. Bounded SYN-state evidence retained only by
current kernel-cookie continuity; no guessing from ports/bytes, no new BPF or
policy authority. Exact UI-agreed contract in [API.md](API.md#activity-initiation-evidence).
Separate binary `.workspace/flowgate-direction`; host daemon/executable untouched.
Focused identity/daemon race tests and vet pass. Real disposable TCP4/6 handshake
fixture `.workspace/direction-check-4` passes known incoming/outgoing after
establishment; preexisting TCP unknown, listener/UDP neutral, read-only capability,
owned nft cleanup. Early fixture selector/timestamp comparisons were corrected;
no acceptance claim is based on those failing runs. Rules inventory already exists
in policy-view; no new inventory mutation/query was needed. UI owns its consumer
and matching real Wayland fixture check; no active frontend branch integrated here.

## UI support integration: Activity composition and launcher separation

Released frontend **85364c94f170f88eede9fc79111ab98143f4ba48** is integrated in full
by fast-forward from backend bridge release **29436689afdaf86a8021558c27284e2c7c4bb3e7**,
retaining7020db0. Explicit clean checkpoint/ownership release verified. Adds an
observation-only overview, separate compatible TCP/UDP source totals/history,
compact policy/details composition and launcher diagnostics/Wayland graphics fix.
No new policy, attribution or accounting API was necessary. Shared bridges now
accept only the fixed --backend enum; Qt defaults unchanged. Normal Electron
builds electron-backend instead of overwriting the host-approved flowgate path.

Main-checkout build/typecheck,14 focused frontend checks,4 mocked bridge checks
and sandboxed Wayland measured presentation journey passed. Presentation fixture
is **synthetic**, not new kernel/receiver evidence; settled real evidence reused.
Logs: .workspace/ui-support-integration-{build,tests}.log,
ui-support-bridge-tests.log and ui-support-integrated-visual.log; captures in
.workspace/ui-support-integrated-visual/after. UI exact-release normal-host launch,
hardware/sandbox and exit evidence are in electron/ACTIVITY-COMPOSITION.md and
LAUNCH-DIAGNOSTICS.md. This does not prove overall NetLimiter fidelity.
No host daemon/collector lifecycle or host-policy operation was performed; deployed
source remains1732584 with active UDP/stopped enforcement. No rollout in this task.
Backend remains available for concrete UI dependencies; larger shaping/history/
quota/filter features need separate scoped proposals. Launch from main checkout:
`scripts/run-electron.sh --daemon /run/flowgate-api/daemon.sock`.

## Current integration: real UDP continuity passed; measured UI released

Visual UI1a53e355 integrated as11316c52 atop backendb4aaf82; preserves full evaluation
UI81c0aaa and referencebf3b79d. User-run real kernel evidence
`.workspace/evaluation-udp-1792313673-2574300` passed stable IDs/baselines/helper/
collector generation and exact UDP4/6 totals across evaluation Start/Allow/Block/Stop,
TCP/Decision Log availability and foreign-rule/route preservation. Inspected and
reused; no suite rerun. Combined build/typecheck and synthetic sandboxed Wayland
measured-Activity checks pass. See [INTEGRATION.md](INTEGRATION.md) for exact SHAs,
source/hash pairing, host state and concrete future rollout/rollback commands.
Host remains unchanged on1732584 with active UDP and stopped enforcement; this
combined build is prepared, not deployed. UI ownership released for integration.

## New backend: daemon-owned incoming evaluation (not deployed)

Backend release **bfa93b6a695fb1928b0f7d55b4aff5cd1d71f626**; separate clean
binary `.workspace/flowgate-evaluation-release`. Implemented `daemon-evaluation-v1`
on the existing root daemon: asynchronous
readiness/Start/Stop, explicit independent activation grant, five-minute/session
CAS, pinned watchdog, owned cleanup, Activity/rules/Decision Log/UDP independence.
No second policy daemon or database owner. Real isolated receiver/Stop and actual
300s disconnected expiry passed; Tailscale-shaped component/refusal and partial
activation cleanup passed. See [DAEMON-EVALUATION.md](DAEMON-EVALUATION.md) for
exact API, reproducible fixtures, evidence and future host procedure.
The running host monitor and active UDP collector are untouched; no host activation
or rollout occurred. Released frontend81c0aaa and referencebf3b79d are now integrated at90cbac5;
the newer UI visual pass remains separately owned. Its
exact-release sandboxed Wayland Start/Allow/Block/log/active-GUI-exit/reconnect/Stop
journey passed; fixture CLEANED after DONE. Details and binary hash in
[DAEMON-EVALUATION.md](DAEMON-EVALUATION.md).

## Current: Decision Log integrated and running in non-enforcing root monitor

Running source **1732584b7ba181ceeffb06fb92cdbbd8aa10b078**, full released UI
**ba4862b065dc7e092ccba253a0afc591f8e81afd** integrated. Preserves backend028ca809,
correctness fixef1d237, prior UI18ca65a and durability/capacity semantics.
Root daemon **PID2201352**, generation **0840f7c256126f1708702f27c5b26551**;
UID1000 explicit administrator and collector control retained. Rules database and
empty inventory preserved. Enforcement **stopped**.

Decision Log capability available, health **ok**, `recording:false`, empty history
(expected in monitoring mode). User-enabled UDP restored **active**, one helper
PID2201368, generation **43a091abb81a09901be2c9b460080ee1**. The restart introduced
a collection gap/fresh accounting baseline; no byte continuity is claimed.
TCP observation and measurements remain available.

```sh
scripts/run-electron.sh --daemon /run/flowgate-api/daemon.sock
```

New build/typecheck, 11 focused model tests and synthetic Wayland navigation pass;
actual UID1000 host API and sandboxed Wayland Activity/Decision Log empty-state
smoke pass. GUI exit preserves daemon/collector. Reused real isolated284-record
acceptance and focused Go race/vet; no broad matrices rerun.

**Single current rollout record:** [INTEGRATION.md](INTEGRATION.md), including exact
binary/helper hashes, Stop/launch, backup/rollback, evidence and remaining limits.
Artifact `.workspace/decision-log-rollout/flowgate-running-previous` preserves the
old running executable. Startup succeeded; rollback not exercised. No firewall,
Tailscale, routing, service or sudoers changes. Live enforcement remains unverified.

## Historical milestones (runtime identities below are superseded)

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

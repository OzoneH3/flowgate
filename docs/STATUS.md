# Current status

## Integrated evaluation UI; kernel continuity authentication pending

Full releases81c0aaa +bf3b79d are integrated with backendbfa93b6 at90cbac5.
Integrated build/typecheck and8 evaluation tests pass. The focused real-BPF
continuity fixture is implemented, but its concrete `sudo -n unshare` launch
required authentication before any fixture execution. Run
`scripts/check-evaluation-udp.sh` once interactively from this checkout. No real-BPF
continuity result is claimed yet. Host daemon/active collector remain unchanged;
no deployment or activation. See [INTEGRATION.md](INTEGRATION.md) for exact evidence,
current host state, future deployment versus activation and rollback procedure.

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

## Current: first rule directly from native Activity

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

## Current: authoritative policy summaries and recorded-context explanations

Primary API capability policy-explanations-v1 provides one bounded native Activity
policy batch, separate In/Out configured scopes/defaults/coverage, exact rule
versions and coherent policy/order tokens. Current-policy event explanation calls
the unchanged evaluator; it is never historical admission evidence. Unknown,
shared and display-only associations gain no authority. Companion requests reject.

Focused race/vet + actual UID1000 Unix/native Activity/SQLite fixture passed,
including privacy, precedence, expiry/edit/delete/order, persistence failure,
maximum uint64 and read-only denial. See POLICY-EXPLANATIONS.md and
.workspace/policy-view-verification.log. Verdict/retention/accounting paths and
storage schema unchanged; no enforcement/coexistence/UDP/UI matrix rerun.
Build .workspace/flowgate-policy leaves the running monitor's executable alone.
The existing root monitor remains running on its old API and eventually needs
an explicitly authorized restart; not performed. UI consumption is separately
owned, and observed-app first-rule creation remains unsupported by this read API.

## Current: bounded Tailscale coexistence path tested

Actual root read-only evidence identifies CLI/daemon1.104.1, iptables-nft,
masked packet/conntrack copies0x00ff0000 and routing5210/5230/5250/5270. No exit
node/subnet mode. Host profile checks now pass for incoming-only + explicit
administrator; combined/outgoing, other builds/backends and unsafe mark/routing
variants refuse. No port/interface/root-UID transport exemption is added.

Focused parser/race/vet and real kernel TUN/NFQUEUE receiver tests passed for
IPv4/IPv6 TCP/one-shot UDP decisions, replies, mark/routing preservation, foreign
Drop, exclusive DB handoff/new generation and owned Stop/recovery. Tailscale
metadata/transport is emulated: no live tailnet interception or encrypted traffic
validation. Foreign configuration is checked at preflight, not continuously.
See COEXISTENCE.md and .workspace/tailscale-verification.log.

Root monitor1973082/generation5a559274aa006090cdc4bb5cd8faed47 remains running,
non-enforcing; its DB was not opened by a competing host writer. No host BPF,
firewall/Tailscale/routes/services changed. The exact future user-triggered
five-minute procedure and monitor handoff are in COEXISTENCE.md, not executed.

## Current: authorized root monitor running

Root native monitor was actually started, PID **1973082**, socket
`/run/flowgate-api/daemon.sock`, UID1000 explicitly delegated administrator.
Enforcement remains **stopped**. Fixed root paths validated without modifying
existing data. Actual UID1000 authenticated requests saw machine Activity,
including root services; the read-only companion rejected all tested mutations.
Generation-scoped root-only Stop passed in isolation. See AUTHORIZATION.md for
exact launch/Stop commands and actual live-generation token.

Sandboxed UID1000 Wayland Electron connected to `.monitor` and showed real rows;
its test instance exited without stopping the daemon. Permission-aware primary
control/rule connection remains a frontend follow-up. No live enforcement,
BPF attachment, Tailscale/routing change, service installation or autostart.
Evidence `.workspace/root-monitor-live-verification.json`, `root-monitor-ui.log`,
`root-monitor-ui-header.png`, `root-monitor-isolated.log`.

## Current: root-daemon foundation and explicit administrator authorization

Native Activity and stored policy can share a non-enforcing foreground root
`serve` daemon; host controllers now also supply Activity. An explicit privileged
`--administrator` grant to selected `--uid` permits machine-visible service policy;
ordinary clients retain self scope on privileged endpoints. Permission metadata is
additive; private socket/peer authentication is retained. Shared ownership remains
conservative. SQLite authoritative writers exclude a second daemon.

Focused role/privacy/real Unix peer/race/vet, isolated stored-service-rule checks
and a controller conditional-delete receiver smoke
passed; read AUTHORIZATION.md for evidence and the delegated-host-UID test limit.
Authorized root host diagnostics observed 95 sockets, 0 inaccessible process dirs;
That earlier checkpoint refused Tailscale/marks; the bounded profile above
now passes planned incoming/admin inspection. No host enforcement, BPF
attachment, runtime-directory creation or service installation. Machine-wide UDP
and frontend recognition of the new mode/permissions remain future integration;
existing launchers and the separate selected-UID UDP prototype remain available.

## Current: read-only doctor and actionable startup diagnostics

`.workspace/flowgate doctor` is human-readable; `--json` produces schema 1 checks.
Read-only firewall inspection is shared with startup. Static prerequisites, actual
read-only probes, blockers, optional absence and unattempted privileged operations
are separate; no overall readiness promise. Existing API/bridges remain compatible;
known startup errors gain `[reason_code]` text. Optional helper metadata now needs
a rebuild via `scripts/build-udp.sh`; counter/BPF event semantics are unchanged.

Focused Go race/vet and namespace checks passed without doctor changing rules,
interfaces or fixture state. One UID-1000 host run took 24 ms: visibility partial,
UDP ELF/BTF prerequisites observed, privileged nft/private-state checks incomplete.
This older diagnostic sample refused tailscale0/marks; the current bounded
coexistence profile above supersedes that blanket refusal.
No privileged host collection/diagnostic or enforcement/configuration changes.
See [DIAGNOSTICS.md](DIAGNOSTICS.md) for commands, bounds and exact evidence.

## Current: Electron integrated, Qt retained, conditional Delete in both

Started from backend `1729c292e29e5feef73b286864aa44bf4d551fcb`. Integrated the full
seven-commit frontend history through clean `297fe09bd4c1b29076a74fb3a51897673104db54`
with merge `838871f8dd9705ded3574e930468e03eb02ce9fb`; no conflicts. Qt checkpoint
`e3890cb` plus build-test include fix `b006898` migrated Delete and exact version handling.

Launch `scripts/run-electron.sh`; default/fallback `scripts/run-desktop.sh` is unchanged.
Both are unprivileged/read-only normally. Both Delete controls require the new
capability, freeze displayed tokens and reject stale acknowledgements without retry.
Qt handles full uint64; Electron refuses unsafe-integer versions.

Main-checkout focused Wayland check passed: real TCP counts/ownership details;
Electron Allow delivers held UDP, edit to Block prevents new delivery, conditional
Delete restores Ask; KDE tray hide/reopen/Quit cleans the owned observer and leaves
the independent controller active (native Quit confirmation response simulated).
Evidence `.workspace/integration-electron-final.log`, `.workspace/integrated-ho0t6y/`.
Real Activity screenshot: `integrated-activity.png` there. Qt deletion/stale external
edit check 3/3 and codec/capability checks 4/4 passed; logs `integration-qt-delete.log`
and `integration-qt-exact.log` under `.workspace`.

Focused reproduction: `scripts/check-integration.sh`. Existing frontend rule/editor,
evaluation, notification and ownership evidence is indexed in electron/README.md;
its focused stale-delete evidence is reused. No privileged UDP/ownership/firewall
matrix rerun. No host enforcement, privileged host collection, install, service,
network/security change or push. Live sudo/host coexistence and privileged Electron
monitoring activation remain unverified.

## Current: atomic conditional rule deletion

The authenticated v1 API now advertises `conditional-rule-delete-v1`. New
`rule-delete` requires displayed backend generation and expected rule version;
check, SQLite commit and publication share the edit mutex. Stale/missing/denied/
unavailable/storage errors are structured. The new CLI uses the displayed version.
Legacy API `rule` Delete remains unconditional for compatibility; both clients
have now migrated as described above. See [API contract and migration](API.md).

Deterministic Unix API races, actual transaction rollback, recreation/restart,
response loss and CLI confirmation tests passed, plus focused race/vet checks.
One isolated host-controller UDP receiver check confirmed deletion restores Ask
and subsequent Block prevents delivery. No live-host enforcement or privileged
collection, frontend integration, network/security/service changes or push.

## Current: native observation ownership improvements

Leader-exit worker fallback now identifies real TCP/UDP IPv4/IPv6 sockets that
were previously unknown. FD links are rechecked after inspection; cache checks
include credentials/namespaces. Additive API ownership categories/counts and a
strictly display-only same-native-application association retain every holder.
Enforcement and frontend files are unchanged. See [native attribution](ATTRIBUTION.md)
for supported cases, exact host sample counts, limits and focused evidence.

`scripts/check-ownership.sh` passed native fixture/API checks, relevant race tests
and vet. Before/after host samples each had 29 unresolved nonzero-inode sockets,
all other creation UIDs; none justify exposing privileged other-user metadata.
Basic monitoring remains unprivileged via `scripts/run-desktop.sh`. The one
Unidentified group and settled TCP/UDP accounting behavior are preserved.

## Current: isolated UDP accounting and Wayland acceptance passed

The authenticated `.workspace/udp-verified-o2oghdyo` run passed on x86-64 CachyOS
kernel 7.2.9-2-cachyos. Actual BPF counters matched native IPv4/IPv6 receiver/API
return counts for connected/unconnected/wildcard sockets, multiple peers, repeated
PEEK, truncation and failed sends. Shared FD/parent-exit handoff to beta preserved
cookie totals; final close removed state. Same-port rebinding used a new cookie
without inherited totals. SO_REUSEPORT selected receivers had separate cookies and
receive totals counted once. Controlled Stop/disconnect/restart restored current
sockets with a fresh generation/baseline and no rate spike; idle returned to zero.

Actual unprivileged Wayland UI: **3/3**, UID 1000, outside the namespace, with measured
UDP rates/totals, numeric sort, stable selection, shared Unidentified group and a
narrow-window capture. See `verification.log`, `wayland.log`, `result.json` (kernel,
namespace, UID and binary hashes), `udp-measured-wayland.png` and
`udp-measured-narrow.png` in that directory. No synthetic rates are in these images.

Collector+helper: 3.52s, 0.010s CPU (0.28% one CPU), 14916KiB sum RSS, 85/2048 map rows,
**zero registered-transfer misses**. The total missed-operation counter was 1 from
an intentional pre-registration datagram; partial markers correctly remain visible.
Process CPU excludes BPF probe time charged to callers. This is a short sanity
check, not a throughput guarantee or cross-distribution validation.

No accounting/verifier fix was required after that run. Expected fixture-barrier
EOF during teardown now exits quietly instead of printing `UDP fixture: Success`;
IPv4/IPv6 cleanup smoke passed (`.workspace/udp-cleanup-check.log`). Confirmation
copy no longer incorrectly says isolated validation is pending. Kernel measurement
paths are unchanged; existing TCP/API/UI evidence remains reusable.

Normal launch remains `scripts/run-desktop.sh`; explicitly enable optional UDP
collection from Activity after `scripts/build-udp.sh`, and use Stop extended
monitoring or `.workspace/flowgate udp-stop`. See UDP.md for exact permissions,
API-return byte definitions, socket-level peer scope and first-registration gaps.
Only isolated collection was exercised; live-host authentication/coexistence,
offload/bypass variants and other kernels/distributions remain unverified. Host
firewall, networking, security settings and services were unchanged.

## Current: real TCP traffic and grouped unidentified sockets

`scripts/run-desktop.sh` remains unprivileged/read-only. Activity now includes
Upload, Download, Uploaded and Downloaded, with numeric sorting and selectable
accounting details. TCP IPv4/IPv6 uses real kernel payload counters, observed since
a baseline; upload includes retransmitted data. **Unprivileged UDP metrics remain unavailable unless the optional collector is explicitly enabled**.
No privileged collector or new activation is required. See TRAFFIC.md for semantics.

One initially collapsed Unidentified group holds unknown/shared sockets, preserves
per-socket measurements and selection on reassociation, and sums known counters
once with partial-coverage markers. Ownership limitations now distinguish observed
metadata/visibility failures and inode-zero kernel states without guessing owners.

Focused evidence: `.workspace/traffic-receiver-final.log` (known TCP4/6 payload
counts, idle, two executable paths, shared/hidden owners, visibility restoration,
restart/closure and overhead); `.workspace/traffic-ui-final.log` (actual Wayland),
`.workspace/traffic-go.log` (race/vet), `.workspace/traffic-monitor-api.log` and
`.workspace/traffic-monitor-ui.log` (existing Activity/search/filter/reconnect).
Measured bounded run: 5.82s, 0.070s observer CPU (1.20% of one core),
15064KiB RSS, 10ms collection. This is not a general performance guarantee.
Final race/vet evidence: `.workspace/traffic-go-final.log`; normal read-only
Wayland launch: `.workspace/traffic-normal-launch.log`.
Screenshots (actual controlled traffic): `.workspace/traffic-ui-1485300/real-traffic.png`
and `real-traffic-narrow.png` in the same directory. The regrouping unit fixture
is synthetic and is reported separately in the Qt log.
No host firewall/network configuration, Wine, profiles or rules were changed.

## Current: optional outgoing control and editable saved rules

Normal launch remains `scripts/run-desktop.sh` (read-only). Before starting an
explicit five-minute evaluation choose **Incoming connections** (default) or
**Incoming and outgoing connections**. The active profile is fixed for that run.
No live host enforcement was activated in development.

Prompts now use selectable structured application/executable/PID, direction,
protocol, remote/local address and port, attribution and lifetime fields.
**Create rule…** opens a real editor with backend scope preview. Saved rules support
**Edit**, Enable/Disable/Delete, absolute expiry and persistence. Edits use version
checks, backend validation and SQLite commit before policy publication. Exact
scope duplicates are rejected; overlapping rules use highest priority then
lexicographically smallest ID, without implicit Allow/Block preference.

Both profile queues new native outgoing TCP/UDP and retains initial packets;
unknown/ambiguous ownership fails closed. UDP senders must retain an observable
socket until approval. Approved replies and startup-preserved connections do not
prompt again. Incoming-only leaves outgoing traffic exempt, including saved
outgoing Block rules (shown inactive). See SEMANTICS.md and RULES.md.

Focused evidence: `.workspace/outgoing-check-final.log` (Go race/vet, isolated
receiver suite, actual Wayland Qt 5/5); `.workspace/outgoing-unified-smoke.log`
(existing unified UI 4/4). Receiver checks include TCP/UDP v4/v6 Allow/Block,
one-shot UDP, both-direction replies, startup preservation, remembered new source
ports, executable/destination separation, edit-to-Block, stale/failed edits,
restart and daemon death/recovery. Final receiver rerun: `.workspace/outgoing-receiver-final.log` (fresh per-attempt
reply logs). Additional final evidence: `.workspace/outgoing-last-ui.log` (5/5, corrected
narrow field labels), `.workspace/outgoing-last-editor.log` (expired editing and
read-only API), `.workspace/outgoing-last-bridge.log` (both-profile handoff with
simulated authentication), `.workspace/outgoing-normal-launch.log` (actual read-only
Wayland launch). Actual UI tests cover outgoing and default
incoming creation/editing. Reproduce with `QT_QPA_PLATFORM=wayland
WAYLAND_DISPLAY=wayland-0 scripts/check-outgoing.sh`.

Real-traffic captures: `.workspace/outgoing-ui-1188339/outgoing-real-prompt.png`,
`outgoing-real-editor.png`, `incoming-real-prompt.png`. The adjacent
`synthetic-ipv6-long-path.png` is explicitly a presentation fixture.
Wine/Proton was not changed or retested. Live sudo and host coexistence remain
unverified. No dependencies or SQLite table migration were added; rule documents
now contain an optional edit version (old documents load as version zero).

**Live host Activity monitoring is implemented and read-only.**

```sh
scripts/run-desktop.sh
```

The application shows real visible applications/processes/TCP/UDP sockets, without
synthetic traffic or host enforcement. Close its window or press Ctrl+C in the
launching terminal to stop that instance's observer. Independent launches have
separate private sockets. A separately managed observer stays running when a client
closes. Branch: `milestone/backend`; exact snapshot: `git rev-parse HEAD`.

## Current: one coherent desktop workflow

`scripts/run-desktop.sh` opens one native window with separate Activity and control
connections. Normal launch is read-only. Start 5-minute evaluation launches terminal
sudo, waits for matching-generation active health, and enables existing prompts
and rules in the same window. Stop/status/recovery use authenticated terminal
commands; selected-user policy permissions were not widened. Activity continues
when control fails, stops or times out. Closing Qt leaves the evaluation deadline
intact. No host activation was performed during this increment.

Saved rules now show application/action/direction/protocol/endpoints/absolute
expiry/state. Enable/Disable/Delete preserve selection, scope and expiry. Offline
rule rows are explicitly a last-received snapshot. Pending count, native tray and
bounded notifications support minimized use; notifications never Allow traffic.

The evaluator uses a private root-owned executable snapshot for controller and
watchdog, with safe existing-directory validation. The unprivileged terminal bridge
uses bounded private result files; it never collects credentials or adds sudoers.
See HOST-CONTROL.md for the user journey and independent commands.

Actual Wayland tests: `.workspace/unified-notification-final.log`; terminal bridge:
`.workspace/unified-bridge-final.log`; focused Go/race/vet:
`.workspace/unified-go-final.log`; host-monitor smoke:
`.workspace/unified-monitor-smoke.log`; normal launch: `.workspace/unified-launch.log`.
Inspected captures: `.workspace/unified-1160667/unified-activity.png` and
`.workspace/unified-1160667/unified-rules.png`. The UI logs print exact screenshot paths.
Authentication is simulated in a narrow seam; controller start/Stop, UDP receiver
Allow/Block, rule re-enable/unchanged expiry, real preflight refusal, timeout/loss,
and closure under the original deadline use the real namespace backend. Native tray
and message support were available; OS notification click dispatch is tested via Qt.
A final smoke caught stale-notification state interfering with the explicit tray
Open action; those paths are now separate and were rechecked.
Real sudo authentication and live-host coexistence remain untested intentionally.

## Previous host-control milestone (reusable evidence)

Incoming-first host-mode code, saved one-hour/persistent SQLite rules, Rules
Disable/Delete, enforcement health, scoped Stop/recovery and a detached five-minute
evaluation watchdog are implemented. **Real host enforcement has not been activated.**
Review `docs/HOST-CONTROL.md` before the explicit `scripts/evaluate-host.sh` command.
The normal monitor command above remains read-only.

Focused receiver checks use the actual host-start path on an isolated veth topology:
IPv4/IPv6 TCP Allow/Block; one-shot UDP Allow/Block; outbound TCP/UDP replies;
ICMP/ICMPv6; pre-existing TCP; persistence and absolute expiry across restart;
disable/delete; bounded no-listener attempts; duplicate/conflicting startup;
structural degradation; daemon SIGKILL; repeated recovery; scoped automatic stop,
including the independent watchdog after daemon death. Unrelated nft objects survive.

Actual Wayland Qt checks run as UID 1000 outside that namespace: persistent Allow
releases the held datagram, a new source port matches, Disable restores Ask, Block
delivers nothing, Delete removes the rule, and disconnect disables mutations.
Focused Go race tests and vet cover the changed policy/API/storage/queue paths.
Evidence: `.workspace/host-verification-final.log`, `.workspace/host-suite-final.log`,
`.workspace/host-final-ui.log`, `.workspace/host-go-tests.log`,
`.workspace/host-bootstrap.log`, `.workspace/host-lab-regression.log`.
Inspected Wayland captures: `.workspace/host-ui-1113497/host-prompt.png` and
`.workspace/host-ui-1113497/host-rules.png`. Final test logs name their
own isolated run and capture directories. Historical startup failures (unmapped
namespace ancestors) were fixed without relaxing real-host privileged paths.

Limits: conservative VPN/mark/queue conflict refusals; snapshot cutover window;
queued extension headers/fragments unsupported; other-UID services can time out;
Full DHCP lease negotiation and real-host coexistence unverified. API control mode shows decisions;
Activity now shares the same window through an independent read-only connection. Game detection unchanged.

## Available now

- Existing Qt desktop with compact Activity tree, name/path/PID/endpoint search,
  sorting, active/listening filters, expand/collapse, copy actions and full details.
- Applications grouped by supported key/revision; PID/start process identities;
  shared sockets counted once, unknown sockets individually shown.
- TCP listening/connecting/established/closing states, bound versus connected UDP,
  bracketed IPv6 endpoints and diagnosed link-local interface scope. Initiation
  remains Unknown, not inferred from port numbers.
- Partial visibility, timestamps and collection cost; errors/overdue collection
  and disconnect never present a previous successful snapshot as live.
- Observation API always read-only, including direct mutation attempts. Policy
  controls require the separate authenticated controller. Observation creates no Allow/Block decision events.
- Serial periodic snapshots, default two-second delay after completion; bounded
  result/cache sizes, no GUI-triggered collection, Wine helpers or host hooks.
- Unprivileged launcher with private per-instance paths and scoped cleanup; no
  installed service, autostart or broad permission requirement.

The **user-accepted prompt demo** remains `scripts/demo-desktop.sh`. Enforcement is
only inside its disposable namespace. Closing that window does not stop the lab;
q/Ctrl+C in its terminal performs teardown. Existing native/Wine evidence is reused.

## Focused evidence

CachyOS x86-64, Qt 6.12.0, actual Wayland:

- Controlled IPv4/IPv6 listeners correctly identify executable/PID/local endpoint.
  Real TCP exchange appears Established; SYN-sent is observed using an unaccepted
  loopback backlog, without firewall changes. UDP bound/connected labels verified.
- Same basename at different paths yields distinct keys. An inherited listener
  reports both visible holders in one row. Process exit removes current ownership.
  All initiation directions remain Unknown. Direct API Allow is rejected.
- Qt checks passed search, filters, sorting, stable selection, copy, empty results,
  process exit, backend loss and fresh reconnect. One existing prompt Allow-to-
  receiver check passed after shared UI/API changes; no full matrix rerun.
- Focused race tests and vet passed. Two normal launchers had distinct sockets and
  generations; stopping one left the other live. GUI exit stopped its own observer.
- In a local 500 ms interval test: approximately 9–10 ms per collection, 0.05 CPU
  seconds over three wall seconds, 115 visible sockets in that sample. This is
  measured local behavior, not a throughput or zero-overhead claim.

Evidence: `.workspace/monitor-final.log`, `.workspace/monitor-host-final.log`,
`.workspace/monitor-go-final.log`, `.workspace/monitor-launcher.log`; fixture JSON
under the `.workspace/monitor-test-*` path printed by the runner. Qt captures under
`.workspace/monitor-ui-*/host-monitor.png` filter to owned fixtures to avoid unrelated
process metadata. Final design integration evidence is recorded separately;
VISUAL.md describes the desktop layout and its verification.

## Integrated visual checkpoint

Both design commits (77286d2 layout and 2f37503 refinement) were reviewed and
cherry-picked after the runnable host checkpoint and backend hardening, without
conflicts. The final rebuild passed an actual Wayland Activity smoke (3/3) and
isolated prompt Allow-to-receiver smoke (3/3). Broader recorded Wayland design,
monitor and decision suites were reused; no Wine tests were repeated.

Evidence: `.workspace/monitor-integration-build.log`,
`.workspace/monitor-integration-smoke.log`, `.workspace/host-monitor.png`.
The inspected capture uses real controlled fixture activity, not fabricated data.
See VISUAL.md for acknowledged plain-text details, generic icons, unavailable
unsupported measurements and other differences from the NetLimiter 5 reference.

## Visibility and scope limits

About 340 process descriptor directories were inaccessible in the recorded run;
partial visibility is reported. Current network namespace, TCP/UDP and process-
leader descriptor directories only: no other namespace traversal, Unix sockets,
private per-thread FD census or packet history. Short-lived activity can be missed.
Snapshots are non-atomic; visible holders do not prove exclusive ownership or
identify a remote program. Useful partial monitoring requires no root request.

TCP measured rates/observed totals are now available (TRAFFIC.md); UDP metrics,
persistent event history and production service remain unavailable. Normal
monitoring provides no host protection; explicit bounded control is described above. NetLimiter 5 is the authoritative visual target; remaining differences
are documented rather than claimed exact. Game detection remains deferred and its
existing optional adapter preserved. Other distributions, arm64, real games,
full launcher/container integration and VPN coexistence remain unverified.
No host firewall/network/VPN/security/service configuration, installed runtime,
launcher or existing-prefix changes were made.

## Checkpoints and next step

Runnable pre-design checkpoint: `883db80dd457591e0fa12af49f4d9ab1e9332020`.
Design worktree: `.workspace/worktrees/netlimiter-design`, branch
`frontend/netlimiter-design`. Integration owns backend/API/scripts/tests; design
owns presentation. The final report names the integrated commit.

Next: user review/execution of the desktop evaluation workflow; then address
observed coexistence issues before service integration. No hidden activation action.
Continue game detection later.

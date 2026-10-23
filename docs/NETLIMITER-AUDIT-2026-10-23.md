# NetLimiter functionality audit — 23 October 2026

Audited FlowGate source: **0842059**. Reference: official NetLimiter documentation
retrieved on 23 October 2026, including 5.3.28.0 release notes. This is a fresh
source/behavior audit, not a claim that the products are equivalent. No product
code, host firewall, service, installed rules or game prefixes were changed.

**Original audit result (see follow-up status below):** FlowGate implements a substantial application firewall and live
socket monitor, but does not reproduce NetLimiter's complete functionality.
The most urgent problems are contradictory permission explanations, fixed
unmatched defaults, partial localhost semantics, and different capabilities in
the two desktop clients. Rate limiting, bandwidth prioritization and durable
usage accounting are still separate, substantial missing subsystems.

## Follow-up status — 23 October 2026, after installation

The original audit below is a dated baseline at **0842059**, not the current
outstanding-task list. Source reviewed for this follow-up: **3e6fdcf** (including service labels through
8fa7081). Installed
and queried live: **298852b**, protection **active both**. No fresh NetLimiter
experiment was performed for this update; original reference claims are unchanged.

| Finding | Follow-up status | Evidence and remaining boundary |
| --- | --- | --- |
| A01 explanations | Fixed in source and installed | `49aa610`, `8df7d3d`: shared evaluator comparator/sentences and Qt wording drift test. This is explanation correctness, not complete reference parity. |
| A02 unmatched defaults | Deferred feature | Fixed Ask and unsafe-attribution Block remain. |
| A03 localhost | Same-host defect fixed and installed | `9b1684a`: own assigned v4/v6 addresses on verified loopback device/netns; 48 isolated receiver cases for default/Ask/Block. Separate reusable loopback filter remains absent. |
| A04 startup guard | Intentional fail-closed boundary documented | No blanket guard bypass; explicit local Deny must not be lost during failure. |
| A05 weights | Deferred feature/migration | No change to permission ordering or custom-weight support. |
| A06 Qt workflows | Feature gaps remain; Stop race fixed in source | `3e6fdcf`: queue shutdown wakeup no longer reports failure. Four unmodified unified-test runs pass (6/6 cases each); not installed in 298852b. |
| A07 temporary Wine grants | Deferred feature | Native process lease exists; runtime-table Wine lease remains refused. |
| A08 accounting/contention | Accounting gap remains; contention reduced | `7c1fbca`: release broker mutex for process collection, TryLock resume, generation/session rechecks and admission-demand yield. A census slot remains held; no latency guarantee. |
| A09 traffic control | Deferred features | Rate limits, QoS, quotas and recurring schedules remain absent. |
| A10 filters | Deferred features | No general named/composite filter model added. |
| A11 lifecycle history | Gap remains | Decision history is not a complete connection/usage ledger. |
| A12 documentation | Current status and key stale claims reconciled here | Historical matrix evidence is not promoted to equivalence. |
| A13 runtime readiness | Fixed and installed; host capability restored | `9b1684a`, `49aa610`: active Unix-peer probe, module-tree warning, cached runtime checks and Electron advisory display. Host rebooted into 7.3.0-3; probe now passes. |
| A14 VPN integration | Deferred integration | Generic tunnel refusals remain; zone labels do not establish enforcement support. |

Additional outage fix: **f4ae7af + 298852b** repair only unchanged Essential
preset metadata after fresh discovery and permit that exact transition during
installation. The first install rolled back because its verifier rejected the
repair; the second succeeded. Journal: 16 repairs at 11:03:29; a network-sourced
DNS query succeeded in 35.2 ms with both-direction protection active. No new DNS
endpoint or executable permission was approved. The prior 10:55 repair attempt
was rolled back with the previous database; those are not duplicate repairs in
the successful store.

Post-reboot DHCP/veth and kernel fixtures passed (`.workspace/network-postboot-dhcp.log`,
`.workspace/network-postboot-kernel.log`). Real Wine saturation with
continuous Activity annotation passed in `.workspace/wine-saturation-6sgREV`:
native delivery 608/608 in both rounds, p99 19.802/17.841 ms. The allowed Wine
application delivered on all 24 sockets, with deliberate overload shedding;
this does not establish lossless Wine delivery or real-game launch latency.
The final outage full check passed (`.workspace/outage-repair-final-check.log`);
installer follow-up passed 18 installer, 13 rollback, 26 updater and 6 preparation
tests. Earlier optional Qt unified runs were not consistently passing. After `3e6fdcf`,
`.workspace/ui2-unified-final1.log` through `final4.log` each report 6/6 passing.
These are separate from the main check's two Qt binaries.

### Unidentified traffic follow-up

Complete live Activity snapshots showed only ownerless TCP TIME_WAIT rows under
Unidentified; the live port-3000 listener and connections had executable owners.
**424ec14 + 8fa7081** add native named-service display labels while excluding
XDG/D-Bus/autostart launcher units. Display labels never alter executable keys,
UID/prefix scope or permission authority. These two commits are not installed in
298852b; the direct process probe is not a native GUI acceptance test.

The first since-install history capture had four outgoing UDP attempts with no
visible matching socket (three broadcasts, one unicast). A later capture added
two localhost DNS attempts with the same reason. Their historical process owners
cannot be recovered from destination ports or surrounding traffic. A private
namespace probe reproduced the lifetime boundary in 10/10 rounds: an open UDP
socket resolves to its current owner, then closing it makes the same flow return
`no visible matching socket`. This proves the mechanism, **not** the cause or
owner of those historical attempts, nor NFQUEUE delivery behavior. Evidence:
`.workspace/udp-lifetime-probe/{main.go,result.log,history-summary.txt}`.
Shared multicast sockets are separately ambiguous and must not be assigned one
application's permission. Two launch-period capacity bursts (5 and 63 dropped
packets) remain a performance follow-up, not an explanation established for every
unidentified record. No attribution bypass or destination-specific Allow was added.

Remaining correctness work: install and verify the queue cancellation repair;
capture short-lived UDP failures with contemporaneous socket/process evidence; measure
real launch behavior under load. New parity features remain deferred by the user.

## Original audit evidence and limits

- **Code-confirmed:** source path and mechanism checked at the audited commit.
- **Probe-confirmed:** evaluator output or an isolated kernel receiver exercised
  during this audit. A model result is not delivery or native UI evidence.
- **Missing:** no corresponding schema/API/backend/UI implementation found;
  older parity records and feature claims were checked against current code.
- **Reference uncertain:** public docs do not specify enough to establish the
  exact behavior. Historical installed observations are explicitly identified.
- **Platform difference:** Linux identity, namespaces and authorization require
  their own design; Windows service/package behavior is not assumed portable.

Read-only monitoring API inspection found the installed daemon is still
**5967b50**, unmodified, with active `both` protection. It does **not** include
0842059's localhost default. Source and deployed behavior must not be conflated.
No update was installed by this audit. Installing the later source does not itself
repair missing kernel capabilities. Local evidence:
`.workspace/netlimiter-audit-20261023/live-status.json`.

The running kernel is `7.2.11-1-cachyos`; its module directory is absent following
a kernel update. The preceding localhost validation found unavailable `veth`
and Unix socket diagnostics. DHCP namespace and real Wine saturation checks
therefore remain **pending reboot and rerun**, not passed. This audit did not
weaken identity checks or try to load another kernel's modules.

Official docs mix version 4 screenshots and version 5 behavior. The earlier
installed 5.3.28 observations in
`.workspace/coordination/1f879934-netlimiter-permission-observed.md` are useful
historical evidence, but no fresh NetLimiter installation was exercised here.
In particular, a remembered-rule receiver test does not prove ordinary Allow
suppresses future prompts; a submitted verdict does not prove delivery.

## Original findings (follow-up status above supersedes completed work)

### A01 — Permission explanations contradict the actual winner (high)

`internal/daemon/editor.go:90`, `internal/daemon/policy_view.go:452` and
`desktop/ruleeditor.cpp:89` describe priority followed by smallest rule ID.
The evaluator actually compares **target weight, numeric Priority, action rank
Deny/Allow/Ask, user-vs-preset, then ID** (`internal/policy/policy.go:261`).
Users reviewing an overlap cannot rely on those explanations.

The audit probe confirms that a scoped Allow with Priority 1 beats a broad
Deny with Priority 0 at the same target weight; with both priorities zero,
Deny wins. The generated sentence omits the action tie-break. The editor also
says a broad rule covers any address without explaining the new localhost
exemption; that sentence is incomplete for 0842059.

**Next:** one shared, evaluator-derived precedence/scope explanation, used in
preview, policy explanation, both editors and documentation; regression cases
must compare the advertised winner with the actual evaluator. This is a
current correctness-of-explanation defect, independently of parity policy.

### A02 — Unmatched In/Out defaults are not configurable (high parity gap)

NetLimiter documents separate default actions for incoming and outgoing traffic.
FlowGate has a fixed `default-ask` for supported unmatched non-localhost traffic,
and blocks unsafe attribution (`internal/policy/policy.go:177,290`). No stored
per-direction fallback setting or corresponding options/API was found. Start/
Stop changes interception, not this default. Probe-confirmed Ask and Block.

**Next:** explicit, persisted per-direction defaults with a migration review;
keep the unsafe-attribution policy separate. Do not silently turn existing
installations into allow-by-default systems in the name of compatibility.
[Reference: default Blocker actions](https://netlimiter.com/docs/options/service/blocker).

### A03 — Localhost compatibility is partial, including the new change (high)

NetLimiter 5.3.28 release notes include connections to the computer's own IP
addresses in loopback recognition. FlowGate's exemption requires **both**
addresses in 127/8 or ::1 plus a verified loopback device and current netns
(`internal/identity/loopback.go:8`). A connection to the host's assigned LAN IP
is therefore still filtered, even when delivered locally. Probe-confirmed.

FlowGate also infers an explicit localhost rule from a loopback remote IP,
prefix or endpoint (`internal/policy/loopback.go:13`). NetLimiter exposes a
separate loopback filter function. Exact equivalence of an IP-only filter versus
that function is **not established** by the docs. The 2020 release supports the
ordinary-Deny exemption, but does not establish every exception combination.

**Next:** decide the intended same-host scope, add an explicit loopback predicate
and test assigned IPv4/IPv6 addresses, locally routed pairs, address changes,
negative remote/spoofed cases, and broad-vs-loopback filter precedence. Preserve
UID/executable/prefix authority for scoped rules; no launcher-wide exception.
[Current loopback changes](https://netlimiter.com/releases/5-3-28-0),
[historical Deny fix](https://netlimiter.com/releases/4-0-59-0),
[filter functions](https://netlimiter.com/docs/basic-concepts/filters).

### A04 — The startup guard can still block localhost (high operational caveat)

The new default exists in userspace policy. `guardRules` installs earlier
priority-9 TCP-SYN drops and TCP/UDP drops without a loopback exemption
(`internal/hostfirewall/guard.go:74`). The normal host table also rejects INVALID
traffic before userspace policy (`firewall.go:227,242`); a finite NFQUEUE and
scheduler can reject before the default evaluator runs.

**Receiver-confirmed during this audit:** the exact production startup guard
blocks a localhost UDP payload; removing only that private test guard restores
delivery. The probe used a disposable namespace, not host interception. This
proves guard-phase behavior, not a failure of steady-state localhost delivery.

**Next:** make the active/starting/failed contract explicit. If localhost must
survive guard/failure states, design that exception together with explicit local
Deny semantics; do not insert an unconditional bypass that loses those rules.
No claim is made about NetLimiter's undocumented driver-failure behavior.

### A05 — Weights and “Priority” are not NetLimiter's complete model (high)

Default machine/zone/application weights 1/2/3 exist, but custom weights are not
stored or editable. FlowGate's process-instance weight is automatically 4.
Numeric Priority is compared within a weight before action rank, so raising it
can reverse an otherwise winning Deny. That Priority is **not** bandwidth QoS.
See `internal/policy/policy.go:268,308` and `electron/src/workflows.ts:100`.

NetLimiter documents custom Blocker weights above 3. Its public docs do not
establish the precise default weight of the installed Process checkbox; the
old matrix overstates that comparison. Historical installed observations support
Deny > Allow > Ask at equal weight, but that tie rule is not specified on the
public Blocker page itself.

**Next:** separate Blocker weight from legacy Priority and future bandwidth
priority. Provide a reviewed compatibility/migration policy before reordering
stored permissions. A model test alone cannot establish full reference parity.
[Reference: Blocker weights](https://netlimiter.com/docs/basic-concepts/blocker).

### A06 — Qt is not a feature-equivalent fallback (high usability gap)

The Qt editor only offers allow/block and TCP/UDP. It deliberately disables Save
for Ask or TCP+UDP (`desktop/ruleeditor.cpp:32,160`), which are normal Electron
and backend rules. Qt prompt scopes remain Once / one-hour Remember / persistent;
no For-a-while, modern Remember-field selector or application-policy quick-setter
implementation was found in `desktop/`. This is safe refusal, not corruption,
but users switching clients lose workflows on the same daemon.

**Next:** explicitly document a supported-client capability matrix; implement
Qt's missing backend-capability workflows or stop promising functional fallback
parity. This finding is source-confirmed; no fresh on-screen Qt journey was run.

### A07 — “For a while” exists, but not for runtime-table Wine identities (medium)

The old parity matrix incorrectly calls this feature missing. Current native
leases are process-bound, same-direction, in memory, and end on exit or expiry.
However `leaseOwner` rejects every `Attribution.Table != nil`
(`internal/daemon/for_a_while.go:92`), including corroborated Windows identities.
The Electron default is **one hour**, while the legacy backend default is 15 s
(`electron/src/process-lease.ts:8`, `for_a_while.go:25`).

NetLimiter docs describe a short process-scoped interval; historical installed
observations measured roughly 10–18 s once, with no selector. That is not a
universal timing guarantee. Current duration selection is a FlowGate extension.

**Next:** clearly label the native-only boundary and selected duration. For Wine,
require a validated Windows process generation throughout the lease; do not use
wineserver/launcher lifetime as a substitute for the requesting application's
process. [Reference: pending requests](https://netlimiter.com/docs/basic-concepts/blocker/pending-requests).

### A08 — Activity totals are live-socket observations, not usage since Reset (high gap)

NetLimiter's Activity total is measured since Reset. FlowGate bases TCP counters
at first observation, discards absent sockets from its traffic map, and restarts
baselines after observation loss (`internal/identity/traffic.go:128`). Parent
figures are aggregates of currently represented sockets. Closing sockets can
therefore remove their accumulated contribution; restarting loses the session.
There is no matching Reset-total ledger. Existing `TestTrafficLifetimes`
explicitly verifies closed-socket state is removed.

There is also a source-confirmed contention risk: Wine Activity annotation holds
one of two runtime census slots and the broker table mutex across a complete
process/FD collection and up to eight TCP/UDP family snapshots
(`internal/identity/wine_activity.go:108`). Admission uses the same resources.
Repeated full collections per broker can therefore delay packet attribution
while Activity refreshes. This is a risk/mechanism finding, not a freshly
measured launch regression; benchmark with Activity polling before changing
locking, and preserve the two-sided evidence bookend.

TCP payload and optional UDP API-return bytes have different definitions; UDP
socket totals cover all peers and may be partial. Neither is a delivered-byte
or unique Internet-usage guarantee. The separate source selector is truthful,
but is not one unified NetLimiter-style usage total.

**Next:** define accounting semantics, a durable ledger, reset epochs, closed-
socket finalization, ownership transitions and VPN double-counting policy before
building quotas or a cumulative “total”.
[Activity totals](https://netlimiter.com/docs/user-gui-client/child-windows/activity),
[traffic monitoring](https://netlimiter.com/docs/basic-concepts/traffic-monitoring).

### A09 — Major traffic-control families remain unimplemented (high product gap)

No bandwidth-rate rule/enforcer, adaptive bandwidth scheduler, quota counter or
calendar scheduler exists in the rule schema/API. Existing numeric Priority
chooses a firewall verdict; rule expiry only stops a rule matching. Neither is
rate shaping or a recurring schedule. There are also no Ignore Traffic / Ignore
Limits policies or corresponding tags. Supported actions remain allow/block/ask
(`internal/policy/policy.go:162`, `internal/daemon/api.go`).

**Next:** implement and receiver/throughput-test these as real backend subsystems;
UI icons or matching names cannot satisfy them. Accounting and reusable filters
are dependencies. [Limits](https://netlimiter.com/docs/basic-concepts/limits),
[bandwidth priorities](https://netlimiter.com/docs/basic-concepts/priorities),
[quotas](https://netlimiter.com/docs/basic-concepts/quota-rule),
[scheduler](https://netlimiter.com/docs/basic-concepts/rules/scheduler),
[tags](https://netlimiter.com/docs/basic-concepts/filters/tags).

### A10 — Fixed rule filters cannot express the full filter model (medium/high)

FlowGate has direct per-rule predicates, not reusable named/composite filters.
Remote IP/CIDR, exact ports and optional protocol/zone are implemented. General
value lists, port ranges, NOT predicates, multiple applications, path patterns,
domain wildcards, tags, arbitrary custom zones and per-type shaping are absent.
Ordinary user rules cannot generally select a local address/interface; those
fields are reserved for validated schema5 presets. Both direction is not a
stored value; two rules are needed. The generic whole-machine quick blocker is
also missing: zone creation requires explicit Local/Internet.

**Next:** a validated shared expression/filter contract with separate identity
proof and selectors, then editors and named-zone/network inventory. Arbitrary
path/display matches must not become permission authority contrary to AGENTS.
[Filter semantics](https://netlimiter.com/docs/basic-concepts/filters),
[rule editor](https://netlimiter.com/docs/basic-concepts/rules),
[zones](https://netlimiter.com/docs/basic-concepts/zones),
[networks](https://netlimiter.com/docs/basic-concepts/networks).

### A11 — Decision Log is not Connection Log, Connection History or Stats (medium/high)

FlowGate persists pending/final/gap decision records (20,000 records / 30 days),
not a complete socket open/listen/connect/close lifecycle and not durable
application/remote usage statistics (`internal/decisionlog/record.go:15`,
`log.go:21`). It has no general kill-connection operation; changing an application
rule does not terminate admitted TCP. NetLimiter separately documents connection
lifecycle logging, usage history and an Activity context-menu tool set.

The new default-localhost fast path has no application identity. Those events
are not visible to ordinary per-UID event listing, and `RecordPacketOutcome`
skips final rule logging when no stored rule was selected
(`internal/daemon/engine.go:217`, `decisions.go:285`). Do not expect a complete
localhost audit trail from Decision Log. Conversely, the earlier reviewer concern
that every default-localhost packet creates a durable log row is **not supported
by the actual logging code**; optional bounded event history is separate.

**Next:** distinguish the three history products and define their collection,
retention, privacy and delivery claims independently. Add explicit termination
as its own authorized operation if required; do not imply Deny kills existing
TCP based on docs that do not promise that.
[Connection Log](https://netlimiter.com/docs/user-gui-client/child-windows/connection-log),
[Connection History](https://netlimiter.com/docs/user-gui-client/child-windows/connection-history),
[Stats](https://netlimiter.com/docs/stats),
[Activity](https://netlimiter.com/docs/user-gui-client/child-windows/activity).

### A12 — Reference records and public project docs have drifted (high process risk)

`docs/NETLIMITER-PARITY.md` describes master39dd41e, calls native For-a-while and
update following missing, and marks some unit-only evidence “verified equivalent”
despite its own rule requiring real acceptance. It is a historical inventory,
not the current authoritative result. `docs/RULES.md:27` and older sections of
`SEMANTICS.md` still describe smallest-ID ties and pinned revisions; README still
states no installed service and incoming-only coexistence despite newer code
and the running root daemon.

**Next:** reconcile current status, scope and precedence documentation; keep old
milestone evidence explicitly dated. Require separate reference/source/model/
receiver/UI evidence columns so a green test cannot mask an absent capability.

### A13 — Missing runtime diagnostics are not surfaced by readiness (high, live)

The live kernel AF_UNIX SOCK_DIAG query returns NLMSG_ERROR/ENOENT (-2),
`unix_diag` is not loaded, and `/lib/modules/<running kernel>` does not exist.
This was checked directly and recorded in `kernel-capabilities.json`. Wine
ownership uses that query in `internal/identity/broker.go:46`; failed broker-peer
proof prevents runtime attribution. The preceding real harness failed with
“helper did not join the selected existing broker”, not a permission prompt.
This affects live Wine census paths, not just the isolated test environment.

`doctor`/readiness checks the nft/conntrack/queue modules and ordinary socket
visibility but has no Wine Unix-peer diagnostic capability check or matching
module-tree warning (`internal/diagnostics/diagnostics.go`,
`internal/readiness/checks.go`). `doctor.json` confirms no such finding is emitted.
A daemon can consequently report active interception while required runtime
attribution is unavailable. Active enforcement is not full application coverage.

**Next:** reboot into the installed kernel before the next update/retest; add a
bounded read-only Unix-peer capability probe and a precise runtime-health error.
Distinguish missing capabilities from denied visibility, retain fail-closed
behavior, and report runtime degradation in the GUI. Do not treat a missing
module name alone as failure: a feature may be built in. The active syscall probe
is the evidence. This is an operational/diagnostics defect, not a claim about
NetLimiter's internal implementation.

### A14 — Automatic VPN classification does not mean VPN enforcement support (high gap)

The automatic zone classifier recognizes private/overlay/tunnel destinations,
but startup preflight rejects generic `wireguard`, `tun` and `xfrm` devices,
with a separately reviewed Tailscale exception
(`internal/readiness/checks.go:139`). FlowGate does not therefore have general
VPN protection parity merely because its Local/Internet labels work through
routes. NetLimiter documents working VPN integrations and a way to exclude
VPN-service traffic from duplicate accounting.

**Next:** list supported enforcement integrations separately from classification
and accounting. Add kernel receiver/coexistence cases for each generic tunnel
integration before relaxing a refusal. Do not disable an existing VPN or confuse
Ignore Traffic accounting with firewall permission.
[Reference: VPN support and accounting](https://netlimiter.com/docs/using-with-vpns).

## Coverage matrix (updated implementation rows)

“Implemented” below means the mechanism exists; it does not assert exact
NetLimiter equivalence or fresh native UI acceptance. Official specification
links are in the findings and source index.

| Area | Current FlowGate status | Important boundary / evidence |
| --- | --- | --- |
| App incoming/outgoing Allow/Deny | Implemented | Authenticated executable/UID/prefix; old native receiver suite passed under explicit localhost Ask |
| Stored Ask | Implemented, Electron | Qt cannot edit it; `TestStoredAskLifecycle` |
| Quick application setter | Implemented, Electron | Own whole-target rule; narrower rules separate; no custom weight control |
| Unmatched per-direction settings | Missing | Fixed Ask; unsafe attribution Block; A02 |
| Default Blocker weights | Partial | Machine1 / zone2 / app3; process4 extension; A05 |
| Custom Blocker weights | Missing | Legacy Priority is different |
| Plain Allow/Deny | Implemented | Once flow lease; no saved rule; not permission for another process |
| Remember field choices / durations | Implemented, Electron | Current API supports reviewed property selection; no named filter object |
| For a while | Partial | Native process lease; Wine table refused; Electron1h extension; A07 |
| Pending dismissal / timeout | Implemented, different/uncertain | Dismissal grants nothing; bounded timeout drops. Docs do not establish exact NetLimiter timeout result |
| Repeat request grouping | Implemented, Electron | One displayed group is not an application-wide grant |
| App permissions across updates | Implemented | Stable verified program key; UID/prefix/direction/scopes retained; native receiver evidence from preceding fix |
| Historical rule override handling | Implemented with presentation limits | Newest unexpired exact program scope; temporary fallback retained; Rules list has no masked-until label |
| Wine/Proton application identity | Validated capabilities, partial | Public owner tables: Wine10.0/11.x contracts; direct-owner path: two exact wineserver SHA-256 builds only; unknown builds fail closed; Unix-peer diagnostics required |
| Activity vs admission contention | Reduced, installed | `7c1fbca`: releases lock during Collect, yields to admission, verifies generation on resume; one slot retained; launch latency still needs measurement |
| Default localhost allow | Installed, same-host scope | Verified loopback device/current netns plus loopback or assigned endpoints; explicit local rules honored; guard remains fail-closed; A03/A04 |
| Explicit localhost Block/Ask | Implemented for IP scopes | Native v4/v6 TCP/UDP both-direction receiver tests passed in prior task |
| Proxy/launcher permissions | Intentionally separate | Localhost access can reach a proxy; proxy outbound remains its own policy |
| Existing TCP after rule edit | Preserved | No automatic disconnect; no manual Kill operation |
| Combined Both rule direction | Missing | Separate incoming/outgoing rules; profile `both` is not a combined rule |
| Port/IP conditions | Partial | Single remote address/CIDR; exact ports; no general ranges/lists |
| Local address/interface filters | Restricted | Validated essential presets, not a generic user editor |
| Named/composite/exclusion filters | Missing | A10 |
| Domains / wildcard hosts | Missing | Display names do not create policy DNS matching |
| Tag filters / ignore policies | Missing | Includes no VPN Ignore Traffic control |
| Automatic Local/Internet scope | Implemented, platform-specific | Kernel topology + reviewed address registry; exact VPN/IPv6 NetLimiter parity unverified |
| Custom named zones / Networks list | Missing/partial | Custom prefixes exist; only Local/Internet zone targets; no reusable network-filter inventory |
| Whole-machine quick blocker | Missing generic control | All-program zone rules exist; unrestricted machine target chiefly preset internals |
| Rates / graph | Implemented, partial source coverage | TCP payload vs optional UDP API-return bytes; shared sockets not counted twice per aggregate |
| Totals since Reset | Missing equivalent ledger | Live socket baselines and closure loss; A08 |
| Long-term usage Stats | Missing | Rules/decision SQLite are not traffic databases |
| Full Connection Log | Missing | Current Decision Log is a narrower product |
| Connection History by app/remote/time | Missing | A11 |
| Download/upload rate limits | Missing | A09 |
| Bandwidth priorities / adaptive allocation | Missing | No QoS engine; numeric rule Priority unrelated |
| Quotas / threshold actions | Missing | No durable quota accounting |
| Calendar rule scheduling | Missing | Expiry is not recurring Start/Stop/Delete |
| Generic VPN enforcement | Restricted | Preflight rejects unreviewed tunnel kinds despite automatic zone support; A14 |
| Runtime readiness | Implemented and installed | Active Unix-peer syscall probe, module-tree warning and advisory runtime checks; individual broker evidence still required; A13 |
| Forwarded/container traffic | Outside enforcement scope | Host input/output only; no FORWARD hook / forwarded Activity root |
| Remote computer management | Missing | Local Unix-socket API, not network remote management |
| Per-user permissions | Implemented, different model | Root daemon, peer credentials, selected administrator; not NetLimiter's full permission editor |
| Tray / independent backend lifetime | Implemented, different defaults | Electron opt-in tray vs NetLimiter5.3.28 close-to-tray default |
| UI customization | Partial | Fixed column presets/global units; no general per-column units, manual-only refresh or full theme/language controls |
| Application inventory / Hidden pages | Partial | Saved rules can retain inactive programs; no equivalent complete installed/history/hidden app manager |
| Service/package attribution | Platform-specific / partial | Linux executable evidence; no complete Windows svchost/Store equivalent |
| Diagnostics / installer / recovery | Implemented, different | doctor, systemd, immutable releases and rollback; no MSI/license parity needed |

## What was checked in this audit

1. Official primary documentation and release notes, including 16 page captures
   through the browsing tool in `.workspace/netlimiter-audit-20261023/sources-*.txt`.
   Direct Python HTTP downloads were denied403; their failed manifest is not
   presented as a successful source archive. Additional browsed pages are linked
   below. No secondary tutorial or forum supplied normative claims.
2. Current evaluator, rule validation and previews, process leases, runtime build
   guards, zones, API operation set, traffic lifetime accounting, decision logging,
   production nftables/boot guard, Electron and Qt entry points.
3. Standalone evaluator probe: unmatched Ask, unsafe Block, Priority override,
   equal-priority Deny, localhost exemption, explicit local Deny and assigned-IP
   non-exemption. `.workspace/netlimiter-audit-20261023/probe.go` / `probe.log`.
4. Focused policy/daemon race suites, twice, passed. Log:
   `.workspace/netlimiter-audit-20261023/focused-race.log`.
5. Overlay-only Go test with exact `guardRules`, isolated UDP receiver: passed.
   Source and overlay mapping stayed under `.workspace`; no production test/source
   file was inserted. `guard_probe_test.go`, `overlay.json`, `guard-probe.log`.
6. Read-only installed build/protection state, recorded separately from source.
7. Direct kernel Unix-diag capability request and the read-only `doctor --json`;
   capability failure is recorded separately from the broader active status.

Not performed: new NetLimiter UI/traffic experiments, fresh FlowGate on-screen
journeys, host firewall mutation, an installed upgrade, real Wine saturation
success, general throughput or VPN delivery benchmarks. Prior localhost/native
receiver and UI logs are `.workspace/localhost-{delivery,integration,outgoing}.log`
and `.workspace/localhost-ui.log`; they are earlier evidence, not reruns here.

## Original feature roadmap (new features currently deferred)

1. Correct shared explanations, client capability claims and stale parity docs
   (A01/A06/A12), with evaluator-vs-preview regression probes.
2. Agree on default actions, full same-host localhost scope and guard/failure
   behavior (A02–A04); review existing explicit local rules before migration.
3. Add custom Blocker weights with safe legacy Priority migration (A05), then
   reusable filter primitives and the missing Both/whole-machine workflows (A10).
4. Reboot into a kernel with matching modules, add runtime capability reporting
   and reviewed VPN coexistence checks (A13/A14), rerun Wine/DHCP and game-launch
   gates, then measure with Activity polling enabled. Preserve independent
   executable/UID/prefix permissions throughout.
5. Build durable accounting and connection lifecycle infrastructure (A08/A11).
6. Add genuine rate limits, bandwidth QoS, quotas and scheduling on that foundation
   (A09), with receiver/throughput evidence and real desktop journeys.

Do not fix these through per-application bypasses or inherited launcher rules.
A screenshot match or a successful API acknowledgement cannot close these rows.

## Additional official source index

- [Connections: initiation vs byte direction](https://netlimiter.com/docs/basic-concepts/connections)
- [Network detection](https://netlimiter.com/docs/basic-concepts/networks)
- [Forwarded traffic](https://netlimiter.com/docs/basic-concepts/forwarded-traffic)
- [Activity options](https://netlimiter.com/docs/options/client/activity)
- [Security permissions](https://netlimiter.com/docs/security/permissions)
- [Remote connection](https://netlimiter.com/docs/remote-connection)
- [VPN accounting and Ignore Traffic](https://netlimiter.com/docs/using-with-vpns)

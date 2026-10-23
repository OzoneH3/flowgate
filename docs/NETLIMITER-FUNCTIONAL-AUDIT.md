# FlowGate functionality audit against NetLimiter documentation

FlowGate has a substantial application firewall, a live socket monitor, and an Electron permission workflow. It does **not** implement NetLimiter's complete traffic-control or statistics product. This audit also found a reproducible permission-scope defect in the inactive-application quick editor, independently of missing features.

Baseline: **b1b658ba0b676cabef44697f71dc64eb26c0c927**, reviewed on **23 October 2026**. The baseline working tree was clean. Official NetLimiter documentation and relevant release notes were retrieved afresh. The comparison covers the Go daemon and CLI, Electron, the Qt fallback, collectors, identity adapters, persistence, installation and recovery. It assesses implemented behavior as well as documented features with no implementation. It is a feature and correctness audit, not a penetration test or a certification of every runtime/build combination.

The full repository check passed on an isolated copy of this baseline. A separate new probe reproduced the inactive-editor defect. Passing existing tests therefore does not close that finding. No installed rules, host protection, services or game prefixes were changed by this audit.

## Follow-up source status

The inventory and reproduction below are pinned to **b1b658b**. Work coordinated during the audit is tracked separately:

- **F01:** fixed in source by **fb92566**. Inactive quick edits now use the normalized draft and reject changes to unchanged authority/scope fields before saving. This audit independently compiled the changed client and ran all **7 new regression tests**, including legacy IPv4/IPv6 action/enable edits, modern scope preservation, individual preview-field tampering and stale versions/generations. The committed client/test bytes match the recorded tested-source hashes. This is client/synthetic-API verification, not installed or native-desktop acceptance.
- **F02:** **3da9427** changes the prompt to “Rule expires after” and “No expiry,” with an explanation of expiry. The source change was inspected. Backend expiry/retention behavior is unchanged, so the wording defect is fixed in source while the deletion-parity difference remains. The implementing session reports 63 focused tests passing; no new native journey or deployment is claimed.
- **F11:** current-facing README guidance was reconciled in **367b3b1**: service versus observer modes, update profiles, default tray behavior, charts, packaging, Wine observer and generic compatibility checks. The diff was reviewed against the corresponding source. The historical audit/parity documents now point to this report; dated observations remain historical evidence.
- **F04 follow-up:** **273b9d7** (backend) and **a5e48af** (UI) implement the first [observed-usage accounting slice](OBSERVED-USAGE.md), retaining sampled backend deltas after socket closure in a separate Electron tab. This partially addresses cumulative observations; live Activity semantics remain unchanged. Restart persistence, complete accounting, Reset, historical statistics and quotas remain unimplemented. Source and isolated/native verification are recorded separately from this baseline; no deployment is claimed.

No source fix in this section is evidence that the installed GUI has received it.

Later runtime-diagnostics follow-up (G11): UI2 reports that an isolated Electron
run at `fb92566` receives degraded runtime state, but the dedicated status element
is hidden and the visible control retains the detail only in its tooltip. The
short label also truncates dotted kernel versions. Evidence is peer-provided
native Electron DOM plus source inspection against an isolated real daemon, not
a captured painted-screen check; see `.workspace/ui2-verify/degraded-findings.md`.
The fix is now committed in **5507423**: runtime degradation gets a visible badge
and dotted version numbers remain intact. UI2 reports isolated native verification;
no installed-release verification is claimed. Observed recovery delay has an
unconfirmed cause and is not classified as a defect.

## Findings requiring attention

| ID | Priority and category | Finding | Status at the audited baseline |
| --- | --- | --- | --- |
| F01 | High correctness | An inactive application's legacy endpoint rule can silently become unrestricted when its action or enabled state is changed. | Reproduced in actual client functions with a synthetic Unix API; actual in-memory Go editor also accepts the submitted widened rule. |
| F02 | Medium correctness and parity | The prompt says “Delete the rule after,” but the implementation expires and retains the rule. | Source-confirmed; existing tests explicitly retain expired rules. |
| F03 | High behavioral difference | A newly created Deny does not terminate already admitted TCP connections. | Source-confirmed; official NetLimiter release notes explicitly describe termination. |
| F04 | High accounting difference | Activity totals are current socket observations, not an accumulated total since Reset. | Source-confirmed and covered by the passing traffic-lifetime test. |
| F05 | High permission-model gap | Unmatched incoming/outgoing actions are not separately configurable. | Fixed Ask for attributable non-localhost traffic; unsafe attribution Block; verified same-host exception. |
| F06 | High permission-model difference | Custom weights are absent; numeric Priority and automatic process weight 4 change ordering. | Current comparator inspected; precedence tests pass for FlowGate's contract. |
| F07 | Medium client capability gap | Qt cannot perform many implemented Electron workflows. | Ask/TCP+UDP edits explicitly read-only; no real chart or durable Decision Log UI. |
| F08 | High product gap | Rate limits, bandwidth priorities, quotas, Ignore policies and recurring rule schedules are absent. | No corresponding rule schema, enforcer, accounting or control operations. |
| F09 | High product gap | Named/composite filters and full long-term statistics/lifecycle history are absent. | Direct rule predicates and Decision Log cover narrower functions. |
| F10 | Medium operational boundary | Protection is limited by protocol, namespace, attribution and coexistence support. | TCP/UDP host input/output; no forwarding policy; WireGuard/XFRM refusal; finite queues. |
| F11 | Medium documentation correctness | Current-facing docs and historical parity labels still misdescribe implemented features. | Tray default, charts, inactive editing, service integration and removed vendor-specific commands need reconciliation. |

### F01 Inactive quick edits can widen a legacy permission

Trigger: an application is not running and its saved rule uses the supported legacy `filter.remote` endpoint representation. In its In/Out popup, change Allow/Deny/Ask or toggle enabled state.

`Rules.draft()` correctly converts an endpoint such as `198.51.100.8:443` into separate address and port fields. However, `changeStoredRule()` builds the edit from the **original** rule, substitutes `'*'` for its absent `remote_address`, and substitutes `0` for its absent `remote_port`. `Rules.preview()` then overwrites the normalized draft with those values. The preview guard checks ID, action, disabled state and direction, but not the preserved address/port scope. The save is sent.

Evidence:

- [inactive-rules.ts](../electron/src/inactive-rules.ts), `changeStoredRule`, lines 52–70: original fields and incomplete preview comparison.
- [rules.ts](../electron/src/rules.ts), `draft` lines 82–90 and `preview` lines 173–192: correct normalization followed by replacement.
- `.workspace/netlimiter-audit-01a16a05/inactive-scope-probe.cjs` and `.log`: actual compiled client functions, synthetic local Unix API; IPv4 and IPv6 endpoint cases widen, modern separate address/port control case preserves scope. Each case sends one preview and one save.
- `backend-scope-probe.go` and `.log` in the same directory: actual `Engine.EditRule` commits the widened candidates in memory at version 2. No host database or packet delivery was involved.

A narrow Allow can become a broader Allow when enabled; a narrow Deny can become a broader Deny when edited. This is a scope-preservation bug, not a request for more permissive policy. Fix the shared construction/comparison of action-only and enable-only edits using the normalized reviewed draft. Compare all unchanged permission fields before saving, including identity, UID, direction, protocol, endpoint, zone/model, process binding, priority, expiry and root-sharing state. Cover legacy IPv4/IPv6 and modern rules, and malicious/drifting preview responses. No native-screen reproduction is claimed here.

The finding and probes were handed to the coordinating backend/UI sessions. The source fix and independent regression results are recorded above; the reproduction describes the pinned baseline, not the corrected client.

### F02 Expiration is presented as deletion

The literal label is in [prompt-card.ts](../electron/src/prompt-card.ts), line 358; [decision-remember.ts](../electron/src/decision-remember.ts), lines 16–26, also offers “Do not delete.” NetLimiter's [pending-request documentation][pending] describes optional removal after a selected time.

FlowGate stops matching at `Expires` but keeps the record. [cleanup.go](../internal/store/cleanup.go) archives expired rules only during startup cleanup after a seven-day grace period, and retains bounded recovery documents. [expired_duplicate_test.go](../internal/daemon/expired_duplicate_test.go), `TestEditorCreatesScopeAlongsideExpiredRule`, explicitly expects the expired record to remain. The 256-rule creation cap counts stored rules, so expiry does not automatically free a slot in a running daemon.

Use wording that promises expiry, or implement actual scheduled removal with an explicit recovery/retention contract. Do not silently delete stored rules to make the wording true. This is distinct from the correct behavior that expired rules no longer authorize new traffic.

### F03 Blocking differs for existing TCP

The [NetLimiter 4.0.54 release notes][release454] explicitly say that creating a Block rule kills existing connections. This corrects the earlier audit's statement that no documentation promised that behavior. This is documented reference behavior; it was not freshly tested on an installed NetLimiter instance.

FlowGate's [firewall.go](../internal/hostfirewall/firewall.go), `profileRules`, accepts marked established TCP at lines 231 and 246. Admission policy changes settle waiting requests and change future decisions, but do not revoke those kernel-admitted connections. The API has no general connection-termination operation. [SEMANTICS.md](SEMANTICS.md) already describes initiation-only TCP authorization.

Keep this distinction visible wherever a user can interpret Deny as “stop this application's traffic now.” A full parity implementation requires deliberate connection revocation and tests for existing connections, both directions, shared ownership and concurrent rule changes. An Allow API acknowledgement is not evidence that the remote receiver obtained data.

### F04 Activity Total is not cumulative usage

NetLimiter's [Activity documentation][activity] defines totals since Reset. FlowGate's [traffic.go](../internal/identity/traffic.go), lines 92–130, establishes per-socket baselines and replaces its state with currently visible sockets. Closed or missing sockets lose their contribution to current aggregates; observation loss creates a new baseline. `TestTrafficLifetimes` passed and expressly verifies this behavior.

Electron's ten-minute graph memory can retain past samples, but it is not a durable accounting ledger and does not make Activity Total cumulative. TCP payload counters and optional UDP API-return counters also measure different things. The latter do not establish remote delivery. A correct ledger needs reset epochs, closed-socket finalization, gaps, ownership changes and an explicit VPN double-counting policy before it can support quotas.

### F05 and F06 Defaults and precedence differ

NetLimiter documents [separate default In/Out actions][defaults] and [custom Blocker weights above 3][blocker]. FlowGate has no persisted fallback setting. Its evaluator returns `default-ask` for supported unmatched traffic, blocks unverifiable ownership, and allows verified same-host flows by default unless explicit local scopes apply.

Current FlowGate ordering is: newest unexpired setting within each exact program scope, then target weight, numeric Priority, Deny/Allow/Ask, user rule over preset, and rule ID. Machine/zone/application weights are 1/2/3; process rules automatically receive 4. There is no user-settable weight. Priority can make an Allow beat a Deny of the same target weight. The [shared explanation](../internal/policy/precedence.go) now accurately describes this; the old contradictory-explanation defect is fixed.

The public Blocker page does not fully specify equal-weight tie handling, exact plain-Allow suppression, or unanswered-prompt timing. Earlier installed observations remain historical evidence, not new documentation-derived guarantees. Migration toward another ordering must preserve explicit scopes and must not weaken unsafe-attribution handling.

### F07 Qt is a limited fallback

The Qt editor's action list is Allow/Block and its protocol list is TCP/UDP. It deliberately refuses Ask and combined TCP+UDP rules rather than coercing them: [ruleeditor.cpp](../desktop/ruleeditor.cpp), lines 34–41 and 164–166. Its Remember controls expose the older Once/one-hour/persistent workflow, not Electron's full property selector and process lease UI. The Qt chart panel explicitly says no history is collected: [activity.cpp](../desktop/activity.cpp), lines 219–228.

Treat Electron and Qt capabilities separately. A passing Electron model test cannot demonstrate a Qt feature or an on-screen workflow. The two offscreen Qt binaries passed in this audit, including a real isolated receiver journey, but neither client received a fresh native-desktop acceptance pass here.

### F10 Runtime and operational limits

Protection acts on local host TCP/UDP input/output. Other IP protocols are not an implemented application-rule family; traffic traversing FORWARD or isolated container network namespaces is not covered by a host Activity label alone. NetLimiter separately documents [forwarded traffic][forwarded].

Current [readiness checks](../internal/readiness/checks.go), lines 155–162, refuse WireGuard/XFRM interfaces. Generic TUN is no longer blanket-refused; compatibility additionally depends on bounded mark analysis. The old vendor-specific Tailscale exception is not the current implementation. Zone classification does not prove tunnel enforcement, and there is no Ignore Traffic accounting feature comparable to the [NetLimiter VPN guidance][vpn].

Attribution requires contemporaneous executable/process/socket evidence. A short-lived UDP sender can close before resolution; shared ownership can remain ambiguous. Queue overload can also drop packets. The current suite verifies bounded/fail-closed behavior, not lossless operation or a real-game launch latency target. Historical saturation and unidentified-packet notes do not identify the owner or cause of a particular current loss. Native and Wine applications, different UIDs, and Wine prefixes must remain independent.

The startup/failure guard can block same-host traffic before normal policy evaluation. This is the documented fail-closed design boundary, not a regression in the corrected steady-state localhost classification. NetLimiter's public docs do not specify an equivalent driver-failure contract.

## Feature inventory and comparison

**Implemented** means a source mechanism exists, not that every NetLimiter detail is equivalent. **Partial** means a related mechanism exists with the stated restrictions. **Different** identifies a semantic difference. **Missing** means no implementation was found across the rule schema/API, relevant backend and UI. **Extension** identifies FlowGate-specific Linux functionality with no direct documented NetLimiter counterpart. Fresh verification is summarized separately below.

### Activity, identity and application inventory

| ID | Capability and reference | Current FlowGate behavior and evidence | Assessment |
| --- | --- | --- | --- |
| A01 | Application/process/connection tree [Activity][activity] | Live socket census, executable/process hierarchy, endpoint details, shared-socket presentation; `internal/identity/activity.go`, `electron/src/model.ts`, `desktop/activity.cpp`. | Implemented; visibility is credential/netns dependent. |
| A02 | Sort, search and details [Activity][activity] | Hierarchical sorting, search, expand/collapse, selection and copy; `renderer.ts`, `model.ts`, Qt activity implementation. | Implemented; not all NetLimiter context tools. |
| A03 | Initiation direction [Connections][connections] | Kernel/conntrack and optional TCP event evidence; explicit Unknown when unsupported; `activity_direction.go`, `initiation_events.go`, `tcpinit/collector.go`. | Partial; byte direction is correctly distinct. |
| A04 | Live transfer rates [Traffic monitoring][monitoring] | TCP_INFO transport-payload rates; optional BPF UDP collection; per-source presentation. | Partial; source semantics and gaps are visible. |
| A05 | System services and packages [Service identities][services] | Native executable identity; systemd service display names; Flatpak metadata and hosted Electron handling; `service_display.go`, `identity/electron.go`, `flatpak-names.ts`. | Platform-specific partial implementation; a service name is not independent policy authority. |
| A06 | Permissions across program updates [Service identities][services] | Verified same stable native/Wine/Electron application key can follow updates; process/preset rules remain pinned; `policy.go`, `program_scope.go`. | Implemented extension; a changed executable path/package version may remain a distinct target. |
| A07 | Application list and offline programs [Application List][applications] | Saved rules produce inactive application rows with add/edit controls; `model.ts`, `inactive-rules.ts`, basis-rule API. | Partial; no historical inventory of every app that ever produced traffic; F01 affects legacy edits. |
| A08 | All/Online/Offline/Hidden pages [Activity][activity] | Active socket filters and saved inactive rows; no persistent Hidden application manager. | Partial. |
| A09 | Icons and readable program names | Local desktop/Flatpak/PE/ICO artwork, bounded retries/caches; `icons.ts`, `icon-pe.ts`, `icon-ico.ts`, `desktop-game.ts`, `pe_version.go`. | Implemented presentation; artwork and launch labels grant no permission. |
| A10 | Wine/Proton application attribution | Verified runtime tables, broker peer, PE image, process generation and prefix; `table.go`, `wine_direct.go`, `wine_activity.go`. | Extension with validated runtime capabilities/builds; not arbitrary Wine support. |
| A11 | Runtime helper lifecycle | Discover existing brokers; validated runtime loader; retire observer on ordinary-process exit; `wine_observer.go`, `wine_loader.go`, Wine-table helper. | Implemented extension; no fresh Wine lifecycle acceptance in this audit. |
| A12 | Launcher/provenance grouping | `provenance.go`, `invocation.go`, renderer presentation can explain launch context. | Extension; parent/command line/display grouping never inherits permission. |
| A13 | Shared, vanished or inaccessible owners | Explicit unresolved/shared states, bounded retained evidence and revalidation; `socket.go`, `retained.go`, `revalidation.go`. | Implemented conservative boundary; no unsupported owner guessing. |

### Blocker, decisions and rule management

| ID | Capability and reference | Current FlowGate behavior and evidence | Assessment |
| --- | --- | --- | --- |
| B01 | Incoming/outgoing Allow/Deny [Blocker][blocker] | TCP/UDP admission decisions and durable rules; `policy.go`, `engine.go`, `queue/processor.go`. | Implemented for supported attributable local flows. |
| B02 | Stored Ask [Blocker][blocker] | Persistent Ask, source rule and prompt; Electron capability-gated support. | Implemented in backend/Electron; Qt editing gap. |
| B03 | Default action per direction [Defaults][defaults] | Fixed unmatched Ask, unsafe Block, verified localhost Allow. | Different; F05. |
| B04 | Global Blocker on/off [Service options][serviceoptions] | Independent daemon monitoring/protection lifecycle, incoming or both profiles; `protection.go`, Electron protection controls. | Implemented with a Linux-specific start/stop/guard contract. |
| B05 | Quick application rule setter [Rules][rules] | Own In/Out rule distinct from scoped rules; `activity-policy.ts`, daemon policy view/observed creation. | Partial; custom weights and other rule types absent. |
| B06 | Plain Allow/Deny [Pending requests][pending] | No durable rule; exact verified application/flow lease. TCP admission window and UDP flow lease are 30 seconds. | Implemented; not an app-wide suppression promise. |
| B07 | Remember properties [Pending requests][pending] | Application required; optional protocol/process/address/service port; backend-reviewed preview; Electron default is application only. | Partial; direct rules instead of reusable named filters; incoming selection uses local service port. |
| B08 | Remember lifetime [Pending requests][pending] | Permanent or selected duration; matching stops at expiry. | Different; F02, no automatic deletion at the chosen instant. |
| B09 | For a while [Pending requests][pending] | In-memory exact process-generation/direction lease; 15/60/300/600/1800/3600 seconds; Electron selects one hour by default. | Partial/different; docs describe a short interval; runtime-table Wine scope is refused. |
| B10 | Request grouping | Identical attempts grouped for presentation; decision targets an authoritative request; `automatic-prompts.ts`, queue reconciliation. | Implemented; grouping alone grants nothing. |
| B11 | Dismissal and timeout | Closing a card grants nothing; bounded timeout blocks held traffic; `engine.go:158`, `prompt-decision.ts`. | Implemented; exact NetLimiter timeout outcome undocumented. |
| B12 | Save rule after request/process ends | Ten-minute retained verified identity, backing-file checks, future-only rule creation; `request_rule.go`. | Extension; cannot resurrect/release the ended request. |
| B13 | Rule-change settlement | Re-evaluate covered pending requests; unrelated/ended requests retain distinct outcomes; `queue_reconcile.go`. | Implemented; reference concurrent behavior not established by docs. |
| B14 | Decision acknowledgement recovery | Reviewed receipt checks are read-only and bounded; no resending an unknown decision; `backend.ts`, `card-result.ts`. | Implemented extension; current unit tests pass, native evidence is historical. |
| B15 | Two-sided local pair decision | Exact verified local peers remain separate identities/scopes; `local_pair.go`. | Extension; does not create parent/proxy permission inheritance. |
| B16 | Rule Add/Edit/Delete [Rule List][rulelist] | Creation from pending request, live observation or saved identity; conditional version/generation edit/delete; `editor.go`, `observed_rule.go`, `delete.go`. | Partial; no arbitrary executable picker/general filter editor. |
| B17 | Enabled state [Rules][rules] | Disabled rules do not match; conditional updates persist. | Implemented; newer disabled exact-scope setting does not revive an older one. |
| B18 | Application rule revisions and overlaps | Newest unexpired exact-scope setting can mask old settings; shared precedence explanation; `program_scope.go`, `precedence.go`. | Different; Rules list lacks a full masked-until explanation. |
| B19 | Blocker weights [Blocker][blocker] | Fixed target weights 1/2/3/4; numeric Priority within a weight. | Partial/different; F06. |
| B20 | Both rule direction [Rules][rules] | Rule schema accepts incoming or outgoing only. | Missing; protection profile `both` does not create a Both-direction rule. |
| B21 | Existing connection termination [Release notes][release454] | Admitted TCP remains established; no general Kill API. | Missing/different; F03. |
| B22 | Current selected-rule explanation | Server-generated scope, overlaps, winning factor and enforcement coverage; `policy_view.go`, `editor.go`, Electron policy UI. | Implemented; old precedence sentence fixed. |

### Filters, zones and identity scopes

| ID | Capability and reference | Current FlowGate behavior and evidence | Assessment |
| --- | --- | --- | --- |
| C01 | Application, protocol and user predicates [Filters][filters] | Exact verified application/UID, TCP/UDP or both; optional exact process generation. | Partial; cannot use arbitrary display names/paths as verified identity. |
| C02 | Remote address and port conditions [Filters][filters] | One address/CIDR or any; exact local/remote ports; supported legacy endpoint form. | Partial; no general value lists, port intervals or exclusion predicates. |
| C03 | Local address and interface conditions [Filters][filters] | Reserved to validated Essential presets in schema 5. | Restricted; not a general user-editable filter facility. |
| C04 | Named/composite filter expressions [Filters][filters] | Rules embed fixed predicates; no reusable AND/OR/NOT expression objects. | Missing. |
| C05 | Multi-application selection to filter [5.3.28 release][release5328] | No named multi-application filter creation. | Missing. |
| C06 | Domain/wildcard matching [Filters][filters] | No policy DNS name/wildcard matcher or DNS metadata service. | Missing. |
| C07 | Tags and tag rules [Tags][tags] | No tag registry or tag-based rule target. | Missing. |
| C08 | Local/Internet zones [Zones][zones] | Automatic kernel topology/address-registry classification; explicit prefix configuration and unknown states; `automatic_zones.go`, `network_zones.go`. | Implemented with Linux-specific semantics; Local grants no trust. |
| C09 | Arbitrary custom zones and detected network filters [Zones][zones], [Networks][networks] | Only Local/Internet targets; custom prefixes change those classifications; no named network filter inventory. | Partial. |
| C10 | Zone/all-program blocker [Blocker][blocker] | Reviewed Local/Internet rules for self or machine; administrator check; `zone_rules.go`. | Partial; generic unrestricted whole-machine quick toggle absent. |
| C11 | Zone migration | Explicit revision-bound preview from legacy to automatic classification; `zone_migration.go`. | Extension; never silently reinterprets saved rule zones. |
| C12 | Loopback [Filters][filters], [5.3.28 release][release5328] | Verified loopback device/current netns plus loopback or assigned own addresses; explicit address rules apply. | Partial; same-host fix present, separate loopback/NOT-loopback filter functions absent. |
| C13 | Root/user and Wine-prefix scope | Independent key/UID/prefix; explicit administrative native root pairing; no launcher-wide grant; `root_scope.go`, `permission_target.go`. | Extension with authorization boundaries. |
| C14 | Forwarded traffic filtering [Forwarding][forwarded] | No FORWARD interception or forwarded Activity root. | Missing. |

### Accounting, charts and history

| ID | Capability and reference | Current FlowGate behavior and evidence | Assessment |
| --- | --- | --- | --- |
| D01 | TCP rate/bytes [Traffic monitoring][monitoring] | Payload counters since observation baseline; upload includes retransmitted payload; headers excluded. | Partial; exact byte-definition equivalence not established. |
| D02 | UDP rate/bytes [Traffic monitoring][monitoring] | Explicit optional collector; send/receive API-return bytes for socket/all peers; gaps, unavailable and partial states. | Partial; not wire or delivered bytes. |
| D03 | Shared-socket aggregation | Deduplicate socket identities within displayed aggregates; scope projections for ordinary users. | Implemented; does not solve VPN double counting. |
| D04 | Totals since Reset [Activity][activity] | Current socket baseline aggregates; no matching reset ledger. | Different; F04. |
| D05 | Global units [Activity options][activityoptions] | Persisted bit/byte and decimal SI choices; `display-units.ts`. | Implemented; no general per-column independent units. |
| D06 | Traffic chart [Chart][chart] | Electron source selection, series toggles, pan/zoom, pause and sample inspection; 60-second default, up to ten minutes retained. | Partial; Qt placeholder, no service backfill or per-second cross-app breakdown. |
| D07 | Chart style/window configuration [Chart options][chartoptions] | Window/source controls and detached chart; no full style editor or exact documented mouse gestures. | Partial. |
| D08 | Durable traffic statistics [Stats v5][stats5] | No traffic statistics database, time-range/grouped usage service or UI. | Missing. |
| D09 | Stats by application/IP/port/user/country [Stats v5][stats5] | No extended usage drill-down. | Missing. |
| D10 | Stats retention/import/move/merge [Stats manager][statsmanager] | Rules and Decision Log databases are separate products; no stats manager. | Missing. |
| D11 | Stats collection options [Stats options][statsoptions] | No zone-specific usage recording, billing-month setting or configured stats flush interval. | Missing. |
| D12 | Connection History [Connection History][connectionhistory] | No durable application/remote-IP transfer aggregation with first/last times. | Missing. |
| D13 | Connection Log [Connection Log][connectionlog] | Durable bounded Decision Log: pending/final/gap records, decision-time rule snapshots, source filters, detail and pagination. | Partial; no general Connect/Accept/Listen/Closed lifecycle stream. |
| D14 | Decision Log retention and health | 20,000 records / 30 days, bounded asynchronous writer and explicit gaps; `decisionlog/log.go`, `query.go`. | Implemented extension; not all observed or default-localhost traffic is logged. |
| D15 | Log time/text/type filters [Connection Log][connectionlog] | Preset ranges, direction/outcome/source/application filters, live/pause and older pages; `decision-log-view.ts`. | Partial; no equivalent full custom-range/type/text interface. |
| D16 | Geolocation, hostname and WHOIS [Location database][location], [WHOIS][whois] | No geographic database, reverse-DNS history enrichment or WHOIS tool. | Missing; Local/Internet classification is not geolocation. |

### Traffic-control families

| ID | Capability and reference | Current FlowGate behavior and evidence | Assessment |
| --- | --- | --- | --- |
| E01 | Per-app/filter download and upload limits [Limits][limits] | No rate rule or rate enforcer in schema/API/backend. | Missing. |
| E02 | Per-connection/process/application limit distribution [Filters][filters] | Process firewall permissions exist, bandwidth distribution does not. | Missing. |
| E03 | Critical/High/Normal/Low priorities [Priorities][priorities] | Numeric firewall Priority selects a verdict; no bandwidth scheduler. | Missing. |
| E04 | Adaptive bandwidth allocation [Priorities][priorities] | No link-capacity detection/QoS allocation engine. | Missing. |
| E05 | Quota accounting, thresholds, reset, alerts/actions [Quotas][quotas] | No quota counter, rule type or threshold action. | Missing. |
| E06 | Ignore data / Ignore limits [Rules][rules], [Tags][tags] | No ignore-policy types; Essential rules are narrowly scoped firewall permissions. | Missing. |
| E07 | Timed/recurring rule Start/Stop/Reset [Scheduler][scheduler] | Absolute expiry and a bounded evaluation deadline only. | Missing; expiry is not a calendar scheduler. |
| E08 | Background rule hotkeys [Hotkeys][hotkeys] | UI navigation shortcuts only; no per-rule global shortcut registration. | Missing. |

### Desktop integration, permissions and operation

| ID | Capability and reference | Current FlowGate behavior and evidence | Assessment |
| --- | --- | --- | --- |
| G01 | Info View and quick tools [Info View][infoview] | Selection metadata, Blocker controls, rule/decision/pending navigation. | Partial; Limit/Priority/Quota controls and several reference tools absent. |
| G02 | Dockable child windows [Child windows][windows] | Electron Info/Chart can dock, detach or hide; layout presets and retained geometry. | Partial; not a general docking system for every reference window. |
| G03 | Activity column profiles [Activity][activity] | Status/Details presets and global units; no arbitrary column/profile manager. | Partial. |
| G04 | Automatic/manual refresh [Activity options][activityoptions] | Automatic polling and explicit Refresh; no equivalent persistent manual-only mode. | Partial. |
| G05 | Tray behavior [Tray options][tray], [5.3.28 release][release5328] | Fresh Electron preferences default `keepInTray: true`; explicit opt-out preserved; tray-host failure restores a visible window. | Implemented; old opt-in-default claim is stale. |
| G06 | Pending alerts and independent service lifetime [InfoBar][infobar] | Prompt attention/tray state, bounded optional notifications; closing GUI does not stop an independent daemon. | Partial; no taskbar rate InfoBar, limiter or QoS toggles. |
| G07 | Theme, language, startup and visual preferences [Client options][clientoptions] | Fixed visual design, persisted layout/units/preferences; deployment can supply desktop launch integration. | Partial; no full theme/localization/client-options equivalents. |
| G08 | User/group Monitor and Control [Permissions][permissions] | SO_PEERCRED Unix API, per-user projection, explicitly configured administrator and separate mutation capabilities; `permissions.go`, `api.go`. | Platform-specific partial equivalent; no arbitrary user/group permission editor. |
| G09 | Local data security [Security][security] | Local rule/log files and authenticated Unix socket; renderer sandbox/CSP/network restrictions; `store.go`, Electron `main.ts`. | Implemented mechanisms; not a full security audit or network-capture proof. |
| G10 | Remote computer control [Remote Connection][remote] | Local Unix sockets only. | Missing; connecting to another local socket is not remote management. |
| G11 | Diagnostic tooling [Diagnostic Tool][diagnostic] | Read-only doctor, readiness/runtime checks, status/recovery commands, local logs and build identity. | Partial; no comparable unified diagnostic ZIP/log-level GUI. |
| G12 | Installation and service [Service options][serviceoptions] | Prepared bundles, monitoring-only install, exclusive writer, owned firewall lifecycle, explicit protection/evaluation control; deployment scripts. | Implemented Linux-specific lifecycle; no MSI/license equivalence intended. |
| G13 | Updates [Version Checker][versionchecker] | Local prepared-release updater, preflight, rollback, desktop-session relaunch supervision, visible GUI/daemon build IDs. | Partial; no automatic upstream/version/location-database checker. |
| G14 | Essential networking assistance | Reviewed DNS/DHCP scopes, current service/interface discovery, exclusions, metadata repair and DHCP scope refresh; `essential/*`, `hostfirewall/bootstrap.go`. | Extension; not a blanket Allow or bandwidth Ignore policy. |
| G15 | Coexistence and recovery | Owned table/mark checks, runtime audits, fail-closed guard, explicit cleanup/recovery; `readiness/*`, `hostfirewall/*`. | Extension; no general VPN/firewall compatibility guarantee. |
| G16 | Configuration persistence and backup | SQLite rules/versioning, startup/lab JSON rule loading, API inventory, administrative backup tooling and bounded archive; `store/*`, `cmd/flowgate`. | Implemented for FlowGate; no general NetLimiter XML/statistics import/export UI. |

## Current corrections to older audit records

- Shared precedence/scope wording, assigned-address localhost recognition and runtime Unix-peer diagnostics are present. They are not reopened as unfixed findings.
- Inactive saved-program creation/editing exists. F01 is a defect in one implemented path, not evidence that the entire feature is missing.
- New Electron profiles close to tray by default (`main.ts:114`), matching the default described in the 5.3.28 notes. Existing opt-outs remain meaningful.
- Generic TUN compatibility uses mark checks; current readiness rejects WireGuard/XFRM. Historical vendor-specific checks must not be advertised as the current integration.
- Native For-a-while leases, update-following application rules, Electron charts, installed-service tooling, receipt recovery and build headers exist. Older rows claiming these entirely absent are superseded.
- Earlier “verified equivalent” labels based solely on unit tests are not carried into this report. This audit has no fresh installed NetLimiter experiment and does not certify exact equivalence.
- At the audited baseline, README advertised `tailscale-inspect`, said no root service was installed, described the tray as opt-in, and called charts/service integration/packaging deferred. **367b3b1** corrects these current-facing claims. Historical deployment states in the dated audit remain historical; this audit did not independently query the installed daemon.

## Verification and evidence boundaries

Evidence directory: `.workspace/netlimiter-audit-01a16a05/`. Official documentation captures are `sources-*.txt`. The source snapshot is `.workspace/nla/`, exported from the pinned baseline. The first run from a longer scratch path failed because Unix socket names exceeded the platform path limit; that is recorded in `full-check.log`. The snapshot was moved and its **scratch-only** `scripts/go-env.sh` redirected temporary files to `.workspace/na/`. Product source was unchanged. The successful rerun is `full-check-short-path.log`.

| Fresh check | Result | What it establishes |
| --- | --- | --- |
| `scripts/check.sh` on the isolated snapshot | Exit 0 | The repository's standard baseline gate passed with the documented temp-path adjustment. |
| Go vet and race tests | Passed | Backend/identity/policy/store/queue/API tests, including separate ordinary-peer checks and selected namespace fixtures. |
| Deployment and script checks | Passed | Passwordless updater, update orchestration, monitoring install, rollback, release preparation, recovery/uninstall, script hardening, Essential review, fontconfig and rule-clear checks. These use fixtures/mocks where designed, not a host deployment. |
| Electron TypeScript/build and Node tests | **334 passed, 0 failed** | Current model/client/harness tests; no native-screen journey in this run. |
| Qt DesktopTest | **8 passed, 0 failed**, offscreen | Includes actual prompt-button/isolated receiver behavior; offscreen platform is not a native desktop. |
| Qt SnapshotTest | **4 passed, 0 failed**, offscreen | Snapshot reconciliation and delayed/unknown-ack behavior. |
| Isolated protection refusal | Passed | Untracked pre-existing connection refuses activation, API remains alive, owned cleanup succeeds. |
| Isolated localhost receiver matrix | Passed | Default/Block/Ask, incoming/outgoing, TCP/UDP, IPv4/IPv6, loopback and assigned own addresses; no host firewall changes. |
| Isolated incoming/outgoing receiver suites | Passed | Included Allow/Block/timeout, stale retry, listener replacement, executable update, distinct native application isolation, shared-socket ambiguity and queue-consumer absence checks. |
| New inactive-editor probe | Defect reproduced | Client sends widened legacy IPv4/IPv6 scopes; modern address/port case remains scoped. Synthetic API, no GUI/delivery claim. |
| New backend scope probe | Widened edits accepted | Actual in-memory Go editor accepts those candidate rules; no host mutation. |
| Follow-up F01 regression tests at `fb92566` | **7 passed, 0 failed** | Independently compiled client with synthetic Unix API verifies preserved scope and rejects preview drift. Recorded source hashes match the commit; not native or installed verification. |

Follow-up evidence is in `followup-scope-tests.log` and `followup-scope-source.json` in the evidence directory. The full baseline gate was not rerun on the follow-up commits; their verification must not be combined into a claim that one final revision passed every check.

Historical evidence availability: `.workspace/scope-retention.log`, referenced by `docs/HISTORY.md`, was reported accidentally deleted by another session during this audit and is unavailable. It is not an artifact supporting this audit's fresh results. The new baseline-check logs are separate evidence and do not reconstruct that historical run.

Not newly exercised: installed NetLimiter UI or network behavior; native Electron or Qt desktop journeys; real Wine/Proton runtime acceptance; the optional `--wine` suite; optional UDP BPF and TCP-initiation collector attachment; arbitrary namespaces/distributions; throughput/saturation benchmarks; real VPN combinations; live installer/update/reboot recovery. Historical or peer-provided results may guide follow-up but do not extend this fresh run's scope.

## Recommended next work

The subsequent [joint backend/UI implementation plan](NETLIMITER-IMPLEMENTATION-PLAN.md)
records the accounting-first scope, independent policy-default option and
separate established-TCP control design gate. The first accounting slice is now
implemented; its bounded observations do not close the full accounting/statistics gap.

1. Complete native inactive-program edit acceptance for the committed F01 fix, then verify the intended installed release. Keep source, native and installed acceptance distinct; no deployment was performed by this audit.
2. Verify the committed F02 wording in the native prompt. Consider an explicit indication when an older stored setting is masked by a newer exact-scope setting, using server-derived state; this is a presentation enhancement, not a newly reproduced enforcement defect.
3. Finish the finite native checks already identified for runtime degradation, ended-request Remember and For-a-while lifecycle. Retain separate assertions for save acknowledgement, receiver delivery, process exit, expiry and generation loss.
4. Treat F03–F10 as explicit product decisions or substantial work, not small bug fixes. If full parity is resumed, define permission defaults/weights/revocation and reusable filters; build accounting/lifecycle storage before quotas; then add shaping, bandwidth priorities and schedules with throughput/receiver evidence.
5. Keep short-lived UDP attribution and launch-load investigations evidence-driven. Preserve executable, UID, prefix and direction boundaries; do not close a coverage gap with inherited launcher permission or destination-specific exceptions.

## Official reference links

Links below are primary NetLimiter documentation. Version 4 wording/screenshots coexist with version 5 pages. Release-specific claims are marked in the findings rather than assumed universal. Failed guessed URLs were replaced by the actual linked pages for Chart, Application List and Stats v5.

[activity]: https://netlimiter.com/docs/user-gui-client/child-windows/activity
[applications]: https://netlimiter.com/docs/user-gui-client/child-windows/applications
[activityoptions]: https://netlimiter.com/docs/options/client/activity
[connections]: https://netlimiter.com/docs/basic-concepts/connections
[monitoring]: https://netlimiter.com/docs/basic-concepts/traffic-monitoring
[blocker]: https://netlimiter.com/docs/basic-concepts/blocker
[defaults]: https://netlimiter.com/docs/options/service/blocker
[pending]: https://netlimiter.com/docs/basic-concepts/blocker/pending-requests
[rules]: https://netlimiter.com/docs/basic-concepts/rules
[rulelist]: https://netlimiter.com/docs/user-gui-client/child-windows/rules
[filters]: https://netlimiter.com/docs/basic-concepts/filters
[services]: https://netlimiter.com/docs/basic-concepts/filters/system-services-and-windows-store-apps
[tags]: https://netlimiter.com/docs/basic-concepts/filters/tags
[zones]: https://netlimiter.com/docs/basic-concepts/zones
[networks]: https://netlimiter.com/docs/basic-concepts/networks
[limits]: https://netlimiter.com/docs/basic-concepts/limits
[priorities]: https://netlimiter.com/docs/basic-concepts/priorities
[quotas]: https://netlimiter.com/docs/basic-concepts/quota-rule
[scheduler]: https://netlimiter.com/docs/basic-concepts/rules/scheduler
[hotkeys]: https://netlimiter.com/docs/basic-concepts/rules/keyboard-shortcuts-hotkeys
[chart]: https://netlimiter.com/docs/user-gui-client/child-windows/chart
[chartoptions]: https://netlimiter.com/docs/options/client/traffic-chart
[stats5]: https://netlimiter.com/docs/stats/stats-version-5
[statsmanager]: https://netlimiter.com/docs/stats/stats-manager-version-5
[statsoptions]: https://netlimiter.com/docs/options/service/stats
[connectionhistory]: https://netlimiter.com/docs/user-gui-client/child-windows/connection-history
[connectionlog]: https://netlimiter.com/docs/user-gui-client/child-windows/connection-log
[location]: https://netlimiter.com/docs/internals/location-database
[whois]: https://netlimiter.com/docs/user-gui-client/whois
[infoview]: https://netlimiter.com/docs/user-gui-client/child-windows/info-view
[windows]: https://netlimiter.com/docs/user-gui-client/child-windows
[tray]: https://netlimiter.com/docs/options/client/tray-icon
[clientoptions]: https://netlimiter.com/docs/options/client
[infobar]: https://netlimiter.com/docs/infobar
[permissions]: https://netlimiter.com/docs/security/permissions
[security]: https://netlimiter.com/docs/security
[remote]: https://netlimiter.com/docs/remote-connection
[diagnostic]: https://netlimiter.com/docs/diagnostic-tool
[serviceoptions]: https://netlimiter.com/docs/options/service/general
[versionchecker]: https://netlimiter.com/docs/options/client/version-checker
[forwarded]: https://netlimiter.com/docs/basic-concepts/forwarded-traffic
[vpn]: https://netlimiter.com/docs/using-with-vpns
[release454]: https://netlimiter.com/releases/4-0-54-0
[release5328]: https://netlimiter.com/releases/5-3-28-0

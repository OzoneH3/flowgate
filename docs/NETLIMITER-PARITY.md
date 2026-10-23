# NetLimiter functional parity matrix

> Historical matrix: several rows describe older commits and are no longer current.
> See [the 23 October 2026 audit](NETLIMITER-AUDIT-2026-10-23.md) for the fresh
> source/documentation comparison at 0842059 and explicitly separated evidence.
> Existing verified labels below are historical claims, not a new certification.

Functional comparison with NetLimiter. Statuses: **verified equivalent**, **divergent**, **missing**, **unverified**.
No percentage scores. A row is equivalent only with behavioural evidence, never from a name,
screenshot, API success or pre-existing test alone. Observations: `.workspace/coordination/
1f879934-netlimiter-permission-observed.md` (captures `.workspace/nl-perm/shots/`).

**Reference and sources.** Target = installed NetLimiter **5.3.28.0** (WinBoat). Official docs
(netlimiter.com/docs, /features, /faqs) are extracted with feature IDs A1–M7, URLs and quotes in
`.workspace/parity/spec-docs.md` (raw text `.workspace/parity/raw/`). Installed observations:
the 1f879934 file above; UI captures in [NETLIMITER-REFERENCE.md](NETLIMITER-REFERENCE.md)
(`.workspace/netlimiter-reference/`) and `electron/ACTIVITY-PARITY-R3..R6.md`. Where docs (often
NL4 screenshots) and the installed version disagree, both are recorded and **the installed version
is the target**. Correction: NETLIMITER-REFERENCE.md §"Behaviors not established" ("No actual
Allow/Block rule was saved") is superseded; rules were saved and exercised in the 1f879934 run.

**Status legend.** *verified equivalent*: behaviour matches the installed reference **and** real
acceptance evidence exists (private kernel receivers, or a real Electron journey against a real
daemon) — cited. *divergent*: implemented but behaves differently. *missing*: not implemented.
*unverified*: implemented but without real acceptance evidence, or the reference behaviour itself was
not observed. *platform deviation (needs user agreement)*: exact NetLimiter behaviour depends on
Windows; the row states the Linux constraint and the closest implementable behaviour. Feature cells
start with the spec ID. Evidence paths are project-root `.workspace/…` unless marked
"UI ws" (= `.workspace/worktrees/electron/.workspace/…`). RE = real Electron journey, RR = real
receivers, unit = Go/cjs unit test only (not acceptance).

**How to update.** Change a row only with new evidence: cite the commit, the code `file:line` and
the RR/RE run directory. Never promote to *verified equivalent* from code reading, screenshots,
synthetic fixtures or unit tests. If the installed NetLimiter is re-observed, update the Observed
column and add the capture path. Re-rank "Dependency-ordered next increments" when a row changes.

## Blocker / application permissions (audited, master 39dd41e)

| Feature | Official source | Observed reference (5.3.28) | FlowGate behaviour | Discrepancy | Owner | Evidence | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Application quick setter (In/Out cell) | [Blocker](https://netlimiter.com/docs/basic-concepts/blocker) "Allow: All connections will be allowed" | One click sets the app's own rule; narrower filter rules untouched; Ask/Allow/Deny + enabled + Delete + Weight | One-click Ask/Allow/Deny via `application-policy-v1` sets/updates the app's own whole-target rule (TCP+UDP, any address/ports, optional zone); scoped rules separate | No Weight control | backend/UI | Go `TestApplicationSetterNeverEditsScopedRule`; receivers `--app-policy` 8/8; Electron journey 12/12 | verified equivalent (except Weight) |
| Rule Status cell meaning | — | Cell = node's own configured rule, not effective result | Cell = `application_rule`; "+N scoped" hint; process rows Not set unless own rule, inherited app rule in tooltip/Info | Hint text is a FlowGate addition | UI | Electron journey (Not set +1 scoped; Allow +2 scoped) | verified equivalent |
| Weight precedence | Blocker: machine 1, zone 2, app/filter 3, custom 4+, higher wins | Blocker tab caption confirms | Weight by target; FlowGate process-instance rules 4 | Process-instance rules are a FlowGate extension | backend | `TestNetLimiterWeightPrecedence` | verified equivalent (default weights) |
| Equal-weight ordering | — | Deny > Allow > Ask; specificity ignored (live) | Deny > Allow > Ask; explicit legacy priority kept within a weight | Legacy priority field has no NL counterpart | backend | `TestStoredAskPrecedence`; receivers scoped Deny/narrow Allow cases | verified equivalent |
| Custom weights 4+ | Blocker | Weight dropdown in quick setter/editor | Not stored or editable | Missing | backend/UI | — | missing |
| Stored Ask action | Blocker "Ask: … an interactive window will pop-up" | Ask rule persists; prompts | `stored-ask-v1`: persisted Ask for app/process/scoped/zone rules; pending names the rule; Decision Log `rule_ask` | — | backend/UI | receivers `--ask` 8/8; Electron journey Ask steps | verified equivalent |
| Allow/Deny once | [Pending requests](https://netlimiter.com/docs/basic-concepts/blocker/pending-requests) | Plain Allow creates no rule; does not cover another process's identical request | Once = tuple lease; no fan-out; next attempt prompts | Lease length (30 s) not compared | backend | `TestPolicyChangeSettlesCoveredPendingOnly`, `--ask` | verified equivalent (lease length unverified) |
| Remember scope choices | Pending requests: "select for which of the connection's properties (source application, port, ip address, etc.)" | ☑ Application (default only) ☐ protocol ☐ process ☐ remote address ☐ remote port; ANDed | Same choices, application default; compact summary before submit | NL creates named `<App>-<addr>` filter; FlowGate stores one rule | backend/UI | `TestRememberFieldsWidenOnlyChosenProperties`, `TestRememberProcessBindsRequestingInstance`; Electron journey | divergent (no named filter object) |
| Remember delete-after | Pending requests "should be deleted after some time" | Do not delete, 1/5/10/30 min, 1/6/12 h | Same 8 values (`duration_seconds`) | — | UI/backend | Electron unit tests; backend duration bounds test | verified equivalent |
| Remember on an Ask-caused request | — | Remember(app)+Allow adds a second rule that beats Ask (equal weight) | Replaces the app's Ask rule in place (exposed in preview); narrow Remember separate rule | Replace vs add (same effect) | backend | `TestStoredAskLifecycle`; `--ask`; Electron journey | divergent (equivalent effect) |
| Duplicate identical rules | — | NL allows a second identical-scope rule | FlowGate updates the existing rule | Different storage, same effect | backend | — | divergent |
| Zone in Remember | — | No zone choice in dialog | API supports zone; UI sends any | API extension only | UI | — | verified equivalent (UI) |
| For a while | Pending requests: temporary, process-scoped, "tens of seconds, minutes" | Checkbox; duration unmeasured | Not implemented | Missing; duration needs measurement | backend/UI | — | missing |
| Pending after rule change | Remember applies "to all following connections" | Window closed after Remember; later connections pass (re-evaluation of concurrent pending inconclusive) | All waiting requests re-evaluated; covered settle, ended finalized, others wait | NL concurrent behaviour unverified | backend/UI | `--app-policy`, `--ask`, Electron (no stale windows) | unverified (reference) |
| Repeated identical requests | — | One card at a time, counter | One grouped card with count (`request_group`) | — | UI | Electron journey (3 attempts → 1 row/1 window) | verified equivalent |
| Blocker default action / Blocker On-Off | Blocker: Options→Service→Blocker | Default In/Out action configurable | Unmatched supported traffic prompts; protection Start/Stop | Default action not configurable | backend/UI | — | divergent |
| Quick zone blocker | Blocker "quickly block/unblock any Zone or Whole machine" | Any/Internet/LocalNetwork Unblocked toggles | Zone rules exist; no one-click zone blocker | Missing control | backend/UI | — | missing |
| C10 Legacy Priority inside a weight | Blocker tab caption (equal weight: Deny, then Allow and Ask) | No priority field; Deny > Allow > Ask at equal weight | Editor "Priority" (-1000..1000) is compared **before** Deny/Allow/Ask (`internal/policy/policy.go:168-171`, `electron/src/workflows.ts:89`) | A non-zero Priority can make Allow beat Deny at equal weight | backend | unit `TestNetLimiterWeightPrecedence` | divergent |
| C8 Process-instance weight 4 (incl. Remember Process) | Blocker weights 1/2/3/4+ (4+ only custom) | Remember(Process) creates an auto filter rule, weight 3 (auto filters = 3) | Process rules weight 4 (`policy.go:205-215`), Remember Process binds the instance | A process Remember outranks an equal app Deny; NL would tie at 3 → Deny wins | backend | unit `TestRememberProcessBindsRequestingInstance` | divergent |
| C6/E7 Unmatched connection outcome | Blocker "default actions … applied if no other blocker rule exists" | Default In/Out = Allow (Options); no prompt when no rule | No rule → `default-ask` prompt (`policy.go:186-187`), then **block** at deadline (`internal/daemon/engine.go:112-116`) | Prompt-then-deny vs silent Allow | backend | unit `TestPendingUserTimeoutAndPolicyChangeRecords` | divergent |
| E7 Unanswered prompt | Pending requests (undocumented) | Card disappeared after ~90-105 s; held connection then completed; next two passed unprompted (single run, fw-1..12; default-Allow interpretation unverified) | Deadline 30 s (`serve --decision-timeout` 1-60 s, `cmd/flowgate/serve.go:55`), final `timeout`, held packets dropped | Shorter deadline; outcome Deny not default action | backend | unit only | divergent |
| E6 For a while (measured) | Pending requests "tens of seconds, minutes … for process from which it originated" | No duration control; text "…all subsequent connections created within a short period of time"; measured window ~10-18 s, process-scoped, no rule (single run) | Not implemented | Missing; implement as process-scoped temporary decision, no stored rule | backend/UI | NL `.workspace/nl-perm/shots/fw-*` | missing |
| B3 Quick-setter Delete | — | Popup Delete is immediate, no confirm; Rule List Delete asks "1 rule(s) will be deleted. Yes/No" [048] | Popup Delete opens a confirmation (`electron/src/activity-policy.ts:711,896` → `confirmRuleDelete`, `workflows.ts:1056`) | Extra confirm in the popup | UI | RE rule-status (UI ws `rule-status-real-T8YDJk`) | divergent |
| B3 Quick-setter Weight / Escape | — | `› Weight` expands "Weight [Default ▾] OK"; Escape does not close popup | No Weight link; Escape closes (kept for keyboard safety, R3) | See custom weights; Escape | UI | RE rule-status | divergent |
| Editor explanation text | — | — | `internal/daemon/editor.go:89` still says "within each tier highest priority then smallest ID … highest priority wins, then smallest rule ID" | Stale; contradicts weight + Deny>Allow>Ask | backend | — | divergent |
| B6 Advanced (Rule Editor) | Rules § Rule Editor: Filter, Zone, Type, Direction In/Out/Both, Value, Weight, Enabled, Scheduler | Advanced opens editor prefilled with app + direction [42] | Editor prefilled with fixed target; action/protocol/zone/address/ports/priority/expiry (`workflows.ts:281`) | No Filter chooser, Both, Weight, Scheduler, rule types | both | RE `creation-workflow.mjs` | divergent |
| C14 Direction Both | Rules "Direction … Both" | Both available in editor | `incoming`/`outgoing` only (`policy.go:105`) | No Both (two rules needed) | backend/UI | — | missing |
| B7 Rule Status icons | Activity column "Quick rule setter" | 7 family icons (Priority, DL/UL Limit, In/Out Blocker, In/Out Quota), icons on hover/selection, dots otherwise (R3) | 7-slot strip; only Blocker slots active, others `·`/n/a (`electron/src/renderer.ts:361-400`) | Limit/Priority/Quota slots inert (see G) | UI (after G backend) | RE rule-status | divergent |
| B8 Info View Rules box | Info View; screenshot Rules grid | Blocker/Limit/Priority/Quota × In/Out matrix, "Not set", Add rule | Matrix with Blocker working, other rows "unavailable"; scoped rule cards (`activity-policy.ts:443-532,606-650`) | Non-Blocker rows inert; no Edit rule/Type/Value/Notes | UI | RE permission-v1_1 | divergent |
| B9 Info View Tools | Info View screenshot | Traffic stats, Connection history, Delete rules, Open folder, Kill connections | Rule list, Decision log, Pending requests | Delete rules, Kill connections, Open folder, stats/history missing | both | — | missing |
| C2/C15 Enabled flag | Rules "Enabled: … inactive and not working" | Enabled checkbox in setter/editor | Disabled/expired rules skipped (`policy.go:126-131`); checkbox in popup/editor/Rules | — | backend/UI | RR `--ask` (disable/delete stop attribution), `.workspace/ask-1792425996` | verified equivalent |
| C5 Decision at connection creation | Rules "allowed to be created" | Blocking at connect (curl 000) | Initial packet held/decided; approved flows continue (`engine.go:144`) | — | backend | RR `--app-policy` `.workspace/app-policy-c38646f-1792425326` | verified equivalent |
| C11 Zone-restricted rule matching | AMBIGUOUS in docs | Not tested live | Rule with zone skips non-matching/unknown peers (`policy.go:135-137`) | Reference behaviour unobserved | backend | RR `--zones`, `.workspace/zones-unknown-1.log` | unverified |
| C12 Blocker tab | Blocker child window | Rules grouped Weight 1-3, For/In/Out cells, "Show pending blocker requests", caption, Blocker enabled badge [288] | Flat Rules tab (Application, Action, Direction, Protocol, Scope, Expiry, State) + Pending tab (`workflows.ts:234-241`) | Not grouped by weight; no In/Out matrix per target | UI | RE `policy-workflow.mjs` | divergent |
| E3 Ask card fields | Pending requests screenshot | Header "Outgoing connection - TCP(6)", From/To host + geo, Application link, Process Id, local/remote addr+port, Whois, Source rule/filter links [023] | Card with app, direction, protocol, endpoints, grouped count; text source line (`electron/src/automatic-prompts.ts:53-68`) | No geo, host name, Whois, links | UI (+backend DNS/geo) | RE permission-v1_1 | divergent |
| E4 Source rule / Source filter | Pending requests "click on Source filter or Source rule" | Links present | Plain text "Asked by rule …"/"No matching rule (default Ask)" | No links; no filter objects | UI | RE (prompt names Ask rule) | divergent |
| E8 Re-open pending | Blocker tab link; InfoBar | "Show pending blocker requests" link | Pending tab with count; tray count | Reference link behaviour not exercised | UI | RE (no stale windows) | unverified |
| E9 Whois in Ask window | Whois doc | Whois link in card | None | Missing | UI/backend | — | missing |

## A. Activity (audited, master dbea3d9)

Official source for A1-A18: [Activity](https://netlimiter.com/docs/user-gui-client/child-windows/activity),
[Options › Activity](https://netlimiter.com/docs/options/client/activity); others as noted. Code paths are
`electron/src/` unless prefixed.

| Feature | Official source | Observed reference (5.3.28) | FlowGate behaviour | Discrepancy | Owner | Evidence | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| A1 Activity = primary window for monitoring + creating limits/firewall rules | Activity "most important window" | Activity tab with Info View + chart | Activity tab with Rule Status strip creating Blocker rules (`renderer.ts:481`, `renderer.ts:361`) | Only Blocker rules can be created (no limits/priorities/quotas) | both | RE permission-v1_1; RE round5 (UI ws `round5-journey-yNI5mm`) | divergent |
| A2 Tree: computer → (filters/zones) → app → process → connection | Activity; screenshots | Host-name root; Filters, Tags, LocalNetwork, Internet nodes under it; apps → processes → connections | Root "All applications" → app → process → socket; pinned Internet/Local Network rows (non-policy, values unavailable); one Unidentified group (`model.ts:48-55,101-222`) | No host root, filter/tag nodes; zone rows have no values | both | unit `model.test.cjs`; RE panes (UI ws `panes-real-brlu3b`) | divergent |
| A3 Rates at every level | Traffic monitoring "speeds are displayed for any filter, application…" | Machine/zone/app/process/connection all show rates | Parents sum unique sockets once, per source (TCP or UDP, never summed); `*` partial, `—` missing (`model.ts:57-85`) | Source-separated; zone rows unavailable; missing ≠ 0 B/s | both | RE graphs (UI ws `gr-bIO32u`) | divergent |
| A4 Direction icon (red incoming, green outgoing = initiator) | [Connections](https://netlimiter.com/docs/basic-concepts/connections) | Arrow on each connection | ←/→ from initiation evidence, red/green; unknown/ambiguous neutral (`initiation.ts:4-12`) | Pre-existing/unobserved sockets show unknown; Linux socket census cannot recover who initiated a socket seen only after the fact; closest = record initiation via the TCP initiation collector/netfilter at creation, unknown otherwise | backend | RR `activity-initiation-v1` real TCP4/6 (INTEGRATION.md) | platform deviation (needs user agreement) |
| A5 Listen state | Connections "must listen" | Listen rows | TCP LISTEN / UDP bound shown "Listening · addr" (`initiation.ts:26-49`) | No Accept/Connect type labels | UI | synthetic `process-presentation.mjs` | unverified |
| A6 Sort all levels by column | Activity | First UL click descending (medium confidence); zone nodes sort with others | All levels sort, rates descending first; pinned network rows exempt (`renderer.ts:506-511`, `model.ts:249-264`) | Pinned rows do not sort; NL repeat-toggle unverified | UI | RE round5 (first click descending) | divergent |
| A7 Node context menu | Activity "context menu with several interesting functions" | Expand/Collapse, Info, Traffic stats, Connection history, Add rule, Create filter, Delete rules, Open folder, Kill connections, rename, Move to Hidden [36] | None; double-click expands / opens Info (`renderer.ts:1058-1066`) | Whole menu missing (Kill connections needs backend) | both | — | missing |
| A8 Column-header right-click | Activity (opens Options) vs FAQ (per-column units) — docs conflict | Not observed | Headers sort/resize only (`renderer.ts:497-515`) | Missing; installed behaviour must be captured first | UI | — | missing |
| A9 Rate / Total toggle | Activity § Top bar | Rate/Total; Total since Reset | Rate/Total switches columns; Total = counted since first observation of live sockets (`renderer.ts:684-696`) | Total not since reset/install; closed sockets drop out | both | RE round5 | divergent |
| A10 Layout templates | Activity § Top bar | `Status` preset dropdown; save/manage own | Fixed Status (4 cols) / Details presets (`renderer.ts:697-702`) | Cannot save own layouts | UI | synthetic panes run | divergent |
| A11 All / Online / Offline / Hidden; Move to Hidden | Activity; FAQ hide app | All/Online/Offline/Hidden pages [32-34] | All / Active / Listening socket filter (`renderer.ts:580-608`) | No Offline (needs app history), no Hidden | both | unit `model.test.cjs` | divergent |
| A12 Reset totals / Refresh / Options buttons | Activity; FAQ reset totals | ⇄ ↻ ⚙ in control row | ⊞ expand, ⊟ collapse, ↻ refresh (`renderer.ts:967`) | No Reset totals, no Options shortcut | both | — | divergent |
| A13 Auto refresh option | Options › Activity | — | Always auto-refresh (poll 1 s) (`backend.ts:99-101`) | Cannot disable | UI | — | divergent |
| A14 Configurable columns (Name, DL/UL Rate/Total/Limit, In/Out Blocker, Priority, Rule Status) | Options › Activity | 4 default columns visible | 12 fixed columns via presets; widths persisted (`renderer.ts:482-496`) | No per-column show/hide; no Limit/Priority/Blocker columns | UI | — | divergent |
| A15 Name: File name / path / description | Options › Activity | Description shown (e.g. "The curl executable") | Desktop-entry name else basename; path in Info (`renderer.ts:1087-1091`) | No selector | UI | unit `assets.test.cjs` | missing |
| A16 Units per column (static/default/auto) | Options › Activity; FAQ units | Global Units autoBit/autoByte/B…Gbit (R5) | Global Units only, persisted, decimal (`display-units.ts:2-41`) | No per-column units | UI | RE round5 | divergent |
| A17 In/Out highlighters | Options › Activity | — | Fixed colours (`style.css:907-908`) | Not configurable | UI | — | missing |
| A18 Totals since installation (persistent) | [Traffic monitoring](https://netlimiter.com/docs/netlimiter-overview/features/internet-traffic-monitoring) | — | Deltas since first observation; nothing persisted (TRAFFIC.md) | No persistent totals | backend | — | missing |
| A19 Store packages / services as entries | [Services & Store apps](https://netlimiter.com/docs/basic-concepts/filters/system-services-and-windows-store-apps) | Service metadata rows | Wine/Proton resolved to .exe; no Flatpak/Snap/systemd grouping (`internal/identity/process.go:96-160`) | No package/unit nodes; no Store/svchost on Linux; closest = group by Flatpak/Snap app ID and systemd unit (cgroup) | backend | unit identity tests | platform deviation (needs user agreement) |
| A20 App update keeps identity | Services & Store apps "each new version was … detected as a new app. It now works correctly" | — | Rules bind executable **revision** = dev:inode:size:mtime:ctime (`internal/identity/process.go:58-64`, `policy.go:132`); package update → new app, rules stop matching | Updates lose permissions and re-prompt; security trade-off; needs user agreement | backend | — | divergent |
| A21 Forwarded traffic node | [Forwarded traffic](https://netlimiter.com/docs/basic-concepts/forwarded-traffic) | — | Out of scope (NETWORK-ZONES.md) | Missing | backend | — | missing |
| A22 Tags node | Tags | Tags node under root | None | Missing | both | — | missing |
| A23 Custom filter nodes | Filters | Filters node; "The curl executable-1.1.1.1" listed [062] | No filter objects | Missing | both | — | missing |
| A24 Remote machines as roots | Remote connection | — | Local only | Missing (see J14) | both | — | missing |
| A25 Filtered view panel + search banner | Screenshots | Search filters; "The view is filtered" + Clear filter [20-25] | Search box + strip; no checkbox panel/banner (`renderer.ts:568`) | Missing panel, banner | UI | — | divergent |
| A26 Selection drives Info View / chart | [Chart](https://netlimiter.com/docs/user-gui-client/child-windows/chart) | Row click updates Info + chart [10] | `graph.update(selected)`; shared with detached panes (`renderer.ts:1179-1181`) | Equivalent for Activity selection; other lists (Applications, Filters) do not exist | UI | RE panes (UI ws `panes-real-brlu3b`) | verified equivalent |

## D. Scope

| Feature | Official source | Observed reference (5.3.28) | FlowGate behaviour | Discrepancy | Owner | Evidence | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| D1 Rules target Filters; apps are implicit filters | [Filters](https://netlimiter.com/docs/basic-concepts/filters); Rules | Rule "For" = app filter or named filter | Rule targets app key+revision+UID directly (`policy.go:11-30`) | No filter entity | backend | unit | divergent |
| D2 Editor Filter chooser | Rules § Rule Editor | Select button | Target fixed by entry point (`workflows.ts:281`) | Cannot pick filter/app | both | — | missing |
| D3 Zone field; blank = all zones | Rules § Rule Editor | Zone field in editor; zone rules not exercised live | Optional `network_zone` local/internet; blank = any (`policy.go:78,135`) | Reference matching unobserved | backend/UI | RR `--zones`; RE `activity-zone-real.mjs` | unverified |
| D4 Per-Type (Per-Connection/Process/Application) | Filters § Filter editor | Per-Type None/Per-Connection/Per-Process/Per-Application [291] | None | Missing (depends on filters + limits) | backend | — | missing |
| D5 Whole-machine filter (Any, weight 1) | Rules § Ignore; Blocker | Any row in Blocker tab and quick zone blocker | AllPrograms+AllUIDs weight 1 exists only via Essential presets (`internal/essential/model.go:239,290`) | No user whole-machine rule | both | RE `essential-real.mjs` | missing |
| D6 Connection in several filters; all rules apply | Rules § Ignore | Equal-weight cross-filter ties observed | Highest-ranked Blocker rule decides (`policy.go:120-189`) | Only Blocker; limits not applicable; Blocker only | backend | RR equal-weight cases (`--app-policy`, `--ask`) | verified equivalent |
| D7 Per-connection scope (limits) | Basic features; FAQ limit vs priority | — | Address/port scoped Blocker rules only | No connection limits (see G) | backend | RE (udp 10.79.0.2:43001 scoped) | missing |
| D8 Zones = filters; built-in Internet/Local; custom zones | [Zones](https://netlimiter.com/docs/basic-concepts/zones) | Internet, LocalNetwork zone filters; classifier unknown | `configured-prefix-v1`: admin-configured Local/Internet CIDRs; loopback/link-local Local; no match = unknown; Internet empty by default (`internal/identity/zones.go:28-96`) | No auto classification, no custom zones; classifier is a project decision; needs user agreement | backend | RR `--zones`, `--remember-zones` | divergent |
| D9 Networks auto-detected (range + gateway) | [Networks](https://netlimiter.com/docs/basic-concepts/networks) | Network List shows active interface | None | Missing (Linux routing table/NM connections allow it) | backend | — | missing |
| D10 Network List (active/inactive) | Networks child window | Present [284-287] | None | Missing | UI | — | missing |
| D11 Composite filter | Filters | Composite editor, flat base list [307] | None | Missing | backend | — | missing |
| D12 Rule on tag applies to all tagged apps | Tags | — | None | Missing | backend | — | missing |
| D13 Exclusion (Application path is not) | FAQ exclude app | — | None (Essential has interface exclusion only) | Missing | backend | — | missing |
| Process-scoped rule lifetime | Pending requests (Process checkbox) | Remember(Process) → filter with process id | Session-bound process-instance rule, inactive after restart (PROCESS-RULES.md) | Weight 4 (see C8); NL process-id rule after exit unobserved | backend | RR process-rules | divergent |

## F. Filters, zones, networks, tags

| Feature | Official source | Observed reference (5.3.28) | FlowGate behaviour | Discrepancy | Owner | Evidence | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| F1 Filter editor (name, type Zone/Composite/Filter, Per-Type, functions) | Filters § Filter editor | Blank editor, types and Per-Type observed [291] | None; one fixed filter per rule | Missing | both | — | missing |
| F2 Function editor, value lists, port ranges | Filters | Flat predicate rows [299] | Single remote address/CIDR, single local/remote port | No lists/ranges | both | unit `editor-presentation.test.cjs` | missing |
| F3 Values within a function = OR | Filters | — | Single values only | Missing | backend | — | missing |
| F4 Functions = AND | Filters | Remember app+address ANDed into one filter [076] | Fixed field set ANDed (`policy.go:132-159`) | Fixed fields, not arbitrary functions | backend | RE Remember protocol+address+port | divergent |
| F5 Function catalogue (app, path is/contains, loopback, local/remote range, ports, Network, Internet/Local, protocol, User, Tag, Forwarded, Domain; each negatable) | Filters § List of all | Catalogue observed [293] | App identity, UID/all, direction, tcp/udp/*, remote IP/CIDR, local port, remote port, zone; presets add interface/local address | No path match, ranges, loopback, Network, Tag, Forwarded, Domain, negation | backend | unit `policy_test.go` | divergent |
| F6 Internet vs Local definition | AMBIGUOUS | Not established | Configured prefixes only (see D8) | Classifier differs/unknown; see D8 | backend | RR `--zones-unknown` | divergent |
| F7 Filter List incl. zones | Filters child window | 8 entries [Filter List] | None; zone inventories in policy_view | Missing | UI | — | missing |
| F8 Filter Info View (properties, definition, rules grid) | Screenshot | — | None | Missing | UI | — | missing |
| F9 Tags (edit, chips, list column) | Tags | — | None | Missing | both | — | missing |
| F10 Tag → auto tag filter; delete removes tag | Tags | — | None | Missing | backend | — | missing |
| F11 Default tags Ignore Traffic / Ignore Limits | Tags § Default | Two Ignore rules Active in Rule List [272] | None | Missing (needs Ignore) | backend | — | missing |
| F12 Domain filters | Filters; Using with VPNs | Domain function in catalogue | None | Missing (needs DNS observation) | backend | — | missing |
| F13 Forwarded-traffic recipes | Forwarded traffic | — | Forwarded traffic out of scope | Missing | backend | — | missing |

## G. Limits, priorities, quotas, scheduler, Ignore, hotkeys

| Feature | Official source | Observed reference (5.3.28) | FlowGate behaviour | Discrepancy | Owner | Evidence | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| G1 Rule types Limit/Blocker/Quota/Priority/Ignore | Rules § Rule Editor (intro says three; editor five) | Add rule types: Limit, Priority, Blocker, Quota, Ignore; draft Limit/Internet/In/5 KB/s [276-283] | Blocker only (allow/block/ask, `policy.go:102`) | Four types missing | both | — | divergent |
| G2-G4 Limits (max DL/UL, direction = data flow, units, set flow, B5 checkbox) | [Limits](https://netlimiter.com/docs/basic-concepts/limits) | Limit units B/s…Gbit/s; DL/UL Limit slots | Display-only slots (`activity-policy.ts:160-161`) | No shaping | backend (tc/eBPF) + UI | — | missing |
| G5 Limiter On switch | Limits note 2 | Toolbar checkbox | None | Missing | both | — | missing |
| G6-G9 Priority levels and engine | [Priorities](https://netlimiter.com/docs/basic-concepts/priorities) | Low/Normal/High/Critical | None; editor "Priority" is an unrelated tie-break integer | Missing; name collision | backend | — | missing |
| G10-G11 Priorities tab / Priorities On | Priorities window | Enabled, Reaction speed Normal, adaptive, BETA method, sliders [289] | None | Missing | UI | — | missing |
| G12 Ignore rule (Ignore data / Ignore limit) | Rules § Ignore | Ignore Limits/Traffic rules, Direction Both [272-275] | None | Missing | backend | — | missing |
| G13-G15 Quota (size, direction, overflow actions) | [Quota](https://netlimiter.com/docs/basic-concepts/quota-rule) | Draft Internet/Both/1 MB/reset Never; reset Never/Every Day/Days/Once/Day of month; Actions Blocker/Limit In/Out + alert [266-271] (docs ≠ installed: installed reset choices are the target) | Display-only quota slots | Missing | both | — | missing |
| G16-G17 Quota alert / Quotas list | Quota | "There are no Quotas", Create Quota | None | Missing | UI | — | missing |
| G18 Scheduler (Start/Stop/Reset by time) | [Scheduler](https://netlimiter.com/docs/basic-concepts/rules/scheduler) | Scheduler tab in editor | Only absolute expiry/"Delete the rule after" (`policy.go:42,129`) | No time conditions | backend | — | missing |
| G19 Global hotkeys toggling rules | [HotKeys](https://netlimiter.com/docs/basic-concepts/rules/keyboard-shortcuts-hotkeys) | — | Ctrl+1..4 tab switch only | Missing; Wayland forbids global key grabs; closest = XDG GlobalShortcuts portal (KDE supports it) | UI | — | platform deviation (needs user agreement) |
| G21 Rule List Add / Edit / Delete | [Rules list](https://netlimiter.com/docs/user-gui-client/child-windows/rules) | Add rule (generic draft), Edit, Delete with "1 rule(s) will be deleted" confirm | Edit, Enable/Disable, conditional Delete with confirm; no free-form Add (`electron/src/rules.ts:243`) | No Add | both | RE `delete.mjs` | divergent |

## H. Traffic measurement, units, charts, history, statistics

| Feature | Official source | Observed reference (5.3.28) | FlowGate behaviour | Discrepancy | Owner | Evidence | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| H1 DL/UL rate | Traffic monitoring | Rates for all traffic | TCP payload via TCP_INFO (no headers, incl. retransmits); UDP only with optional collector; else `—` (TRAFFIC.md) | UDP absent by default; payload-only; unprivileged Linux has no UDP byte counters; closest = root daemon runs the UDP collector by default | backend | RR `.workspace/traffic-receiver-final.log`, `.workspace/daemon-udp-1792270674-2133903` | platform deviation (needs user agreement) |
| H2 Units selector (global default) | [Top bar](https://netlimiter.com/docs/user-gui-client/main-window/menu-bar-top) | autoBit/autoByte/B/KB/MB/GB/bit/Kbit/Mbit/Gbit; MB relabels Activity + chart (R5) | Same list, persisted; decimal K=1000 (`display-units.ts:27-35`) | NL divisor (1000/1024) not established | UI | RE round5 | unverified |
| H3 Traffic chart (DL/UL, separate axes) | Chart | Green DL / red UL, separate axes, ~10 min retained, legend totals | Same colours/axes; 60 s default (5/10 min selectable); source-specific totals (`graph.ts:396-416`) | Default window; no service-retained backfill | UI (+backend history) | RE graphs (UI ws `gr-bIO32u`) | divergent |
| H4 Chart pan/zoom/select, 1 s app detail | Chart | Click → 1 s detail with prev/next | Pan, zoom, series toggles, sample detail ‹ ›, pause (`graph.ts:41-110`) | No middle-drag select; no per-app 1 s list | both | synthetic panes | divergent |
| H5 Chart options Stream/Style/Time | Options › Traffic chart | Chart ▾ menu | Source and Window in chart menu | No Style | UI | synthetic panes | divergent |
| H6-H9 Stats service (enabled, saved zones, 180 s update, DB location/move) | [Stats](https://netlimiter.com/docs/stats); Options › Stats | Stats present | In-memory 10 min only (`history.ts:42-43`) | No stats DB | backend | — | missing |
| H10-H11 Traffic statistics window, extended Apps/IPs/Ports/Users/Countries | Stats v5 | Date ranges, Internet/Local/Loopback, groupings [80] (v4 docs H12/H14 superseded by installed v5) | None | Missing | both | — | missing |
| H13 Stats Manager (DB info, delete range, import, move) | Stats Manager v5 | — | None | Missing | both | — | missing |
| H15 Connection History (app × remote IP, first/last, totals) | [Connection history](https://netlimiter.com/docs/user-gui-client/child-windows/connection-history) | Aggregates app/remote endpoints [77] | None (Decision Log is not history) | Missing | both | — | missing |
| H16 First day of month | Options › General | — | None | Missing | UI | — | missing |
| H17 Geolocation (country/town) | [Location DB](https://netlimiter.com/docs/internals/location-database) | Geo line in Ask card, Info View | None | Missing | backend | — | missing |
| H18 Data stays local | [Security](https://netlimiter.com/docs/security) | — | Local Unix socket; no network calls found | No acceptance check | backend | — | unverified |
| H19 Ignored traffic not counted | Rules § Ignore | — | No Ignore | Missing (G12) | backend | — | missing |

## I. Connection / decision logs, attribution

| Feature | Official source | Observed reference (5.3.28) | FlowGate behaviour | Discrepancy | Owner | Evidence | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| I1 Connection Log: created/closed, Allowed/Blocked, real-time + long-term | [Connection log](https://netlimiter.com/docs/user-gui-client/child-windows/connection-log) | Event records with filters [60] | Decision Log (`decisions.db`): pending/final/gap, only in enforcing modes (`internal/decisionlog/query.go:52-58`) | No Connect/Accept/Listen/Closed events; monitor mode records nothing | backend | RR `.workspace/decision-log-1792272647`; RE `decision-log-workflow.mjs` | divergent |
| I2 Rule id + filter name on decisions | Connection log § Action | Not exercised live | Decision-time rule snapshot (id, version, action, filter), source rule/rule_ask/default_ask/user/timeout | No filter name; reference unobserved | backend | RR decision-log + `--ask` (`rule_ask`) | unverified |
| I3 Time selection (Now, ranges, hour/10-min buttons) | Connection log § Time | Time selector | Any/15 m/1 h/24 h/7 d, Live/Paused (`decision-log-view.ts:35-41`) | No custom range/hour buttons | UI | RE decision-log | divergent |
| I4 Filters Action/Type/text | Connection log | Action, Type, text box | Direction, outcome, source, application (`decision-log-view.ts:61-65`) | No Type, no IP/name text filter | both | unit `TestQueryValidation` | divergent |
| I5 Columns + Autoscroll/Clear/Start-Stop/Save | Screenshot | Present | Time, App, Decision, Source, Dir, Proto, endpoints; Jump to latest/Load older | No hostname/country, Clear, Save/export | both | RE decision-log | divergent |
| I6 Row context menu, Whois | Connection log § Context menu | — | Details aside only (`decision-log-view.ts:469-485`) | No menu/Whois | UI | — | missing |

## J. Settings, persistence, lifecycle, permissions, remote

| Feature | Official source | Observed reference (5.3.28) | FlowGate behaviour | Discrepancy | Owner | Evidence | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| J1 Options dialog (Service/Client sections) | [Options](https://netlimiter.com/docs/options) | Tools › Options [07] | Options menu items only; prefs in `electron-preferences.json` (`electron/src/main.ts:91,710`) | No dialog/sections | UI | — | missing |
| J2 Enable/disable Blocker, Limiter, Stats | Options › Service › General | Toolbar checkboxes | Root startup flags + protection Start/Stop (`cmd/flowgate/serve.go:51-58`) | No UI feature switches | both | RE `continuous-real.mjs` | divergent |
| J3 Driver / service / client; stopping service stops enforcement | [Components](https://netlimiter.com/docs/internals/3-netlimiter-components) | — | nftables+NFQUEUE, root `serve`, unprivileged Electron; guard unit keeps fail-closed (`deployment/systemd/flowgate-guard.service`) | Stop ≠ open traffic; no kernel driver; closest = nftables/NFQUEUE with explicit protection Stop releasing interception | backend | RR `continuous-isolated.py` (CONTINUOUS.md) | platform deviation (needs user agreement) |
| J4 Closing client keeps rules active | Components § Client | Close → tray, rules keep working | Daemon/rules independent of GUI | — | both | RR 310 s active without Electron (CONTINUOUS.md); RE `continuous-reopen-real.mjs` | verified equivalent |
| J5 Settings in one file; copy to migrate | [XML config](https://netlimiter.com/docs/internals/xml-configuration-file) | — | `rules.db`, `decisions.db`, `protection.json`, `/etc/flowgate/zones.json` (`internal/store/store.go:23`) | Several files; no migrate procedure | backend | unit `TestDurableRules` | divergent |
| J6 Reset service configuration | [Reset](https://netlimiter.com/docs/internals/reset-netlimiter-service-configuration) | — | None | Missing | backend | — | missing |
| J7 Per-user UI layout file | Reset UI layout | Layout restored after tray reopen | Prefs in `.workspace/electron-preferences.json` | Not per-user XDG config | UI | RE panes | divergent |
| J8 Run client at startup | Options › Client › General | — | None | Missing (XDG autostart) | UI | — | missing |
| J9 Service autostart; client offers Start | FAQ endpoint error | — | `flowgate.service` WantedBy multi-user (DAILY-DEPLOYMENT.md); no Start button | Host/reboot acceptance pending | backend | lab `test-install-monitoring.py` | unverified |
| J10 Client shows service unreachable | [Debugging](https://netlimiter.com/docs/debugging) | Not induced | Observer/control status shows unavailable | Reference not observed | UI | RE `reliability.mjs` | unverified |
| J11 Permissions Monitor/Control per user/group | [Permissions](https://netlimiter.com/docs/security/permissions) | Tools › Permissions | One root-configured admin UID; others self scope; read-only companion = Monitor (`internal/daemon/permissions.go:7-47`) | No per-user/group UI | both | RR `--ask` (read-only endpoint refuses) | divergent |
| J12 OS-account based security | Security | — | SO_PEERCRED, 0700/0600 sockets (`internal/daemon/api.go:122,161`) | — | backend | unit `permissions_test.go` | unverified |
| J13 Admin privileges | System requirements | — | Daemon root; client unprivileged | Stricter split; intentional | both | — | divergent |
| J14-J15 Remote connection; host name / File › Connect | [Remote connection](https://netlimiter.com/docs/remote-connection) | File menu connection items | Unix socket only (`api.go:125`); toolbar shows FLOWGATE | Missing | both | — | missing |
| J17 Version checker | Options › Version checker | Version Checker 5.3.28.0 [04] | `flowgate version` only | Missing | UI | — | missing |
| J18 Update keeps settings | [Updates](https://netlimiter.com/docs/installation/updates) | — | Immutable releases + atomic `current` swap (`scripts/install-monitoring.py`) | Host install not accepted | backend | lab `test-deployment-recovery.py` | unverified |
| J19 Uninstall keep / clean | Command-line options | — | Keeps data; no clean option (`deployment/uninstall.py`) | No clean | backend | lab `test-deployment-uninstall.py` | divergent |
| J20 Languages, Theme | Options › Languages/Theme | Dark Gray / Light Blue / Lime, font 100% [08] | Fixed dark theme, English | Missing | UI | — | missing |

## K. Panes, navigation, InfoBar, tray

| Feature | Official source | Observed reference (5.3.28) | FlowGate behaviour | Discrepancy | Owner | Evidence | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| K1 Dockable child windows | [Main window](https://netlimiter.com/docs/user-gui-client/main-window) | ▾ Undock/Open Window/Close; floating panes (R3, R6) | Info View + chart undock/dock/close; one window per pane (`electron/src/main.ts:489-497`) | Other windows not dockable; no edge docking | UI | RE panes (UI ws `panes-real-brlu3b`) | divergent |
| K2 Child window set | Child windows | Activity, Filter/Application/Rule/Network lists, Blocker, Priorities, Info, Chart, History, Log, Stats, Quotas | Activity, Pending, Rules, Decision Log, Info, Chart | Lists, Blocker, Priorities, History, Stats, Quotas, Whois missing | UI | — | divergent |
| K3 Tabs container | Tabs | 30 px tab strip | Activity/Pending/Rules/Log tabs, Ctrl+1-4 | Tabs not individually openable/dockable | UI | RE `workflows.mjs` | divergent |
| K4 Top bar (host name, menus, Units, On checkboxes, Search) | Top bar | Host name, File/Tools/Window/Help, Units, ☑ toggles, layout, search [R4] | FLOWGATE brand, same menus, Units, status labels, Layout, Search (app/pid/endpoint/state) | Brand vs host; labels vs checkboxes; no geo search | UI | RE round5 | divergent |
| K5 Info View content | Info View | App path/product/version/company/tags/signature; connection remote name, country | Name, executable, UID, key/revision, PID; socket endpoints/state/initiation | No metadata/signature/tags/geo/host name | both | RE panes | divergent |
| K6 Application List (+ delete missing apps) | Applications | Alphabetical list, Description/File Name/Tags [284] | None | Missing (needs app history) | both | — | missing |
| K7 Tray (Show icon, Minimize to, Close to tray) | Options › Tray | Show tray ☑, Close to Tray ☑, Minimize ☐ [116-123] | "Keep running in the tray when the window closes" (default off) (`electron/src/background.ts:24-28`) | Default off; no Minimize/Show options | UI | RE `background.mjs` | divergent |
| K8 InfoBar (rates, alerts, toggles) | [InfoBar](https://netlimiter.com/docs/infobar) | — | Tray tooltip/menu: pending count, enforcement/UDP status; notifications | No rates, no toggles; Windows 10 taskbar toolbar has no Linux equivalent; closest = StatusNotifier tray with rates + Blocker toggle | UI | unit `notifications.test.cjs` | platform deviation (needs user agreement) |
| K9 Whois tool | [Whois](https://netlimiter.com/docs/user-gui-client/whois) | Whois link in Ask card | None | Missing | both | — | missing |
| K10 VirusTotal, third-party API, customizable UI | /features | — | Local JSON API (API.md); no VirusTotal | No VirusTotal; fixed layout | both | — | divergent |
| K11 Failures to system event log | Debugging § Event Viewer | — | stderr → journald under systemd | No dedicated log; no Windows Event Log; closest = structured journald entries (`SYSLOG_IDENTIFIER=flowgate`) | backend | — | platform deviation (needs user agreement) |

## L. Diagnostics, VPN, FAQ

| Feature | Official source | Observed reference (5.3.28) | FlowGate behaviour | Discrepancy | Owner | Evidence | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| L1 Diagnostic tool (status, log levels, report zip) | [Diagnostic tool](https://netlimiter.com/docs/diagnostic-tool) | — | `flowgate doctor [--json]` read-only readiness (`cmd/flowgate/doctor.go:17`) | No log levels, no report bundle | backend | `.workspace/doctor-host.json` (real host sample) | divergent |
| L2 Crash info to copy | Debugging | — | crashDumps path only (`main.ts:59`) | Missing | UI | — | missing |
| L3 VPN double counting; Ignore Traffic remedy | [Using with VPNs](https://netlimiter.com/docs/using-with-vpns) | — | Per-socket counting (transport + inner app each counted); Tailscale coexistence profile; no Ignore | No remedy | backend | RR `tailscale-isolated.py` (COEXISTENCE.md) | divergent |
| L4-L5 Limiting VPN process; limit vs priority FAQ | VPNs; FAQ | — | No limits/priorities | Depends on G | backend | — | missing |
| L6 Control another computer | FAQ | — | None | See J14 | both | — | missing |
| L7 Per-column Auto Units FAQ | FAQ units | — | Global units only | See A16 | UI | — | divergent |

## M. Windows platform items

| Feature | Official source | Observed reference (5.3.28) | FlowGate behaviour | Discrepancy | Owner | Evidence | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| M1 MSI bootstrapper, silent options | [Installation](https://netlimiter.com/docs/installation) | — | `scripts/install-monitoring.py` hash-bound bundle | No package/silent CLI; no MSI; closest = distro package (PKGBUILD/deb) with non-interactive install | backend | lab `test-install-monitoring.py` | platform deviation (needs user agreement) |
| M2 .NET/VC++ prerequisites | Prerequisites | — | Go binaries, python3, nft, bpftool (doctor checks) | Different prerequisites; use distro dependencies | backend | `check-doctor.sh` | platform deviation (needs user agreement) |
| M3 Base Filtering Engine required | System requirements | — | nftables + NFQUEUE (`internal/hostfirewall/firewall.go`) | Linux equivalent; nftables/NFQUEUE is the closest equivalent | backend | RR receiver suites | platform deviation (needs user agreement) |
| M4 Services in shared svchost | Services & Store apps | — | Executable+revision+UID identity; no per-unit split | See A19; closest = systemd unit via cgroup | backend | — | platform deviation (needs user agreement) |
| M5 net stop/start nlsvc, nldrv | Components | — | `systemctl` flowgate.service + flowgate-guard.service (guard first) | Order reversed by design | backend | lab `test-deployment-recovery.py` | platform deviation (needs user agreement) |
| M6 Stats DB SQLite in ProgramData | Stats database | — | SQLite rules/decisions in `/var/lib/flowgate`; no stats DB | Stats DB missing (H6) | backend | — | missing |

## Dependency-ordered next increments

Ranked; each item lists the rows it closes and the owner. Items 1-6 complete NetLimiter's Blocker
behaviour; later items build on the filter and statistics foundations.

1. **Precedence cleanup** (backend): replace the legacy Priority tie-break with stored custom
   weights 4+; process-instance/Remember(Process) at weight 3; fix the `editor.go:89` text. UI:
   `› Weight` in the setter and editor. Rows: Custom weights, C10, C8, explanation text.
2. **Default Blocker action + unanswered prompt** (backend, then UI): configurable In/Out default
   (Allow/Deny/Ask, installed default Allow); prompt deadline about 90 s, then the default action.
   Rows: C6/E7, Blocker default action.
3. **Global Blocker On/Off, Blocker tab, whole-machine and quick zone blocker** (both): needs (2).
   Rows: Blocker On/Off, C12, Quick zone blocker, D5.
4. **For a while** (backend, then UI): process-scoped temporary decision, about 10-18 s, no rule.
   Row: E6.
5. **Direction Both + popup parity** (both): Both in editor; popup Delete without confirm; Escape
   behaviour. Rows: C14, B3.
6. **Stable application identity across updates** (backend, user agreement on the security
   trade-off): path-based identity with revision as evidence. Row: A20.
7. **Reusable named filters** (backend first, then UI): filter entity, function catalogue with value
   lists/ranges/negation, OR/AND, Composite, Filter List, Activity filter nodes, named Remember
   filters `<App>-<address>`, exclusion pattern, Source filter link. Rows: D1, D2, D11, D13,
   F1-F5, F7, F8, A23, Remember named filter, E4.
8. **Tags** (both, needs 7): tags, tag filters, default Ignore tags. Rows: F9-F11, D12, A22.
9. **Connection Log** (backend, then UI): open/accept/listen/close events with rule/filter
   attribution, recorded in monitor mode too; type/text filters, Clear/Save. Rows: I1-I6.
10. **Persistent traffic statistics** (backend, then UI): stats DB, totals since install with Reset,
    Online/Offline app history, Application List, Traffic statistics, Connection History, Stats
    Manager. Rows: A9, A11, A12, A18, H6-H16, K6, M6.
11. **Activity UI parity** (UI, parts need 9/10): context menu (Kill connections needs backend),
    column chooser, Name mode, per-column units, highlighters, Hidden page, filtered-view panel,
    host-name root. Rows: A2, A7, A8, A10, A13-A17, A25, K4.
12. **Traffic shaping: limits + Limiter On + Ignore** (backend tc/eBPF, then UI), then Per-Type.
    Rows: G1-G5, G12, D4, D7, B7/B8 limit slots, H19, L3-L5.
13. **Priorities, then quotas, then scheduler** (backend, then UI; need 12). Rows: G6-G18.
14. **Zones/networks** (backend; user agreement on classification): auto-detected Networks and
    Network List; decide on default Internet/Local classification. Rows: D8-D10, F6.
15. **Settings and lifecycle** (both): Options dialog, autostart, per-user prefs, reset config,
    clean uninstall, version checker, permissions UI. Rows: J1, J6-J8, J11, J17, J19, J20.
16. **Geo / Whois / host names in prompt, Info View, log** (backend data + UI). Rows: E3, E9, H17,
    I6, K5, K9.
17. **Remote connection** (both). Rows: J14-J15, A24, L6.
18. **Platform-deviation agreements** (user): A4, A19/M4, H1, J3, K8, K11, G19, M1-M5; out-of-scope
    J16/J21/M7.

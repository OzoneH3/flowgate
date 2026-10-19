# NetLimiter functional parity matrix

Functional comparison with NetLimiter. Statuses: **verified equivalent**, **divergent**, **missing**, **unverified**.
No percentage scores. A row is equivalent only with behavioural evidence, never from a name,
screenshot, API success or pre-existing test alone. Observations: `.workspace/coordination/
1f879934-netlimiter-permission-observed.md` (captures `.workspace/nl-perm/shots/`).

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

## Other feature areas

Activity hierarchy/aggregation, filters/tags/networks, limits, priorities, quotas, schedules,
Ignore, traffic measurement/units/charts/history/statistics, connection and decision logs,
settings/persistence/service lifecycle/permissions and pane behaviour: **unverified** —
audit in progress (owner 1f879934). Do not treat existing FlowGate behaviour as equivalent
until a row with evidence exists here.

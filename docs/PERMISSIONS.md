# Application permissions: NetLimiter Blocker behaviour

Reference specification: NetLimiter official documentation
([Blocker](https://netlimiter.com/docs/basic-concepts/blocker),
[Rules](https://netlimiter.com/docs/basic-concepts/rules),
[Filters](https://netlimiter.com/docs/basic-concepts/filters),
[Pending requests](https://netlimiter.com/docs/basic-concepts/blocker/pending-requests))
and the installed NetLimiter 5.3.28 observed in WinBoat
(`.workspace/coordination/1f879934-netlimiter-permission-observed.md`, captures in
`.workspace/nl-perm/shots/`). The project-wide parity matrix is `docs/NETLIMITER-PARITY.md`.

## Defect that started this increment

Activity's Application → Out → Allow, with exactly one existing rule in that
direction, edited *that* rule. For Firefox the only rule was a prompt-remembered
UDP 173.194.160.2:443 permission, so "Allow the application" never created an
application permission while its cell showed a green Allow. NetLimiter's setter
edits only the application's own rule (observed) and Allow means "All connections
will be allowed" (documented).

## Implemented behaviour (backend, master fb5b2da)

| NetLimiter behaviour | Source | FlowGate |
| --- | --- | --- |
| Application/process quick setter sets the node's own rule; narrower rules untouched | observed 5.3.28 | `application-policy-v1`: `observed_draft.application_policy=true` with the whole-target scope (TCP+UDP, any address/ports, optional zone). Creates it or updates it in place (`replaces {id,version}`, version-checked). Scoped rules are never its target |
| Weight precedence: machine 1, zone 2, application/filter 3, custom 4+; higher wins | docs Blocker + observed Blocker tab | Evaluator orders by weight by target (FlowGate process-instance rules: 4, an extension NetLimiter lacks) |
| Equal weight: Deny before Allow, then Ask; specificity ignored | observed live (narrow Allow lost to app Deny and vice versa; Blocker-tab caption) | Deny, then Allow, then Ask at equal weight (replaces previous rule-ID tie order). Explicit legacy priorities keep their stored order within a weight |
| Ask: "When a connection … is about to be created an interactive window will pop-up" | docs Blocker | `stored-ask-v1`: Ask is a persisted action for application/process/scoped/zone rules (setter, creation, editor). A winning Ask rule creates a normal pending request with `ask_rule {id,version}`; Decision Log pending source `rule_ask` with the rule snapshot (no rule = `default_ask`). Explicit Ask is distinct from no rule |
| Allow/Deny without Remember is one-time; Ask rule kept | observed (plain Allow creates no rule) | Once covers its tuple lease only; the Ask rule is unchanged and the next independent attempt prompts again |
| Remember(app)+Allow adds an Allow that beats the Ask rule at equal weight | observed (two rules; Allow > Ask) | Application-only Remember on an Ask-caused request replaces that Ask rule in place (`replaces`, version+1): same effective result without a dead duplicate. Narrow Remember creates a separate rule that wins for its scope only. A Remember that another rule would still override is refused (`policy_conflict`), never reported as success |
| Remember: choose properties (application always; protocol, process, remote address, remote port), ANDed; default application only; optional deletion time | docs pending-requests + observed 5.3.28 dialog | `decision-remember-fields-v1`: `remember {address,port,protocol,process}` (false = any), `duration_seconds` for temporary rules, compact `summary` before submit, `replaces` when the same scope exists. Process = session-bound instance binding |
| Plain Allow/Deny without Remember creates no rule; does not cover another process's identical request | observed | Once: 30 s tuple lease, never fans out |
| After a Remember/rule change, following connections use the rule | docs; observed (pending re-evaluation unverified-but-consistent) | Every policy change re-evaluates waiting requests through normal identity/policy: covered ones settle by the rule, ended attempts are finalized, others keep their own deadline |
| Rule Status cell = the node's own configured rule, not the effective result | observed | policy-view `application_rule` (own rule), `scoped_rules`, per-rule `kind` |
| "For a while": checkbox beside Remember, "Allow or deny this connection and all subsequent connections created within a short period of time"; no duration control; "active for process from which it originated"; creates no rule | docs + observed 5.3.28 (window measured ≈10–18 s; a new process prompted again) | `decision-for-a-while-v1`: `decide` with `scope:"for-a-while"`, `action` allow/block. Decides the held request exactly like Once and adds an in-memory process lease for a fixed **15 s** (`lease {id,until,seconds}` on the event; `process_leases` in `list`, admin or owning UID). Scope: the exact owning process instance (PID + start ticks + UID + boot ID + pid/mount namespace + application key/revision/executable) **and the same direction**; siblings, relaunches, other users/executables and the other direction prompt. Needs one verified owner with complete visibility, else `process_scope_unavailable`. Leases only fill prompts (default Ask or a stored Ask rule); any configured Allow/Deny rule wins. Waiting requests of the same process/direction settle by the lease. Not a rule, not persisted, lost on daemon restart. Decision Log: the user final has `scope:"for-a-while"` + `lease_id`; covered connections have source `for_a_while` + `lease_id`. Combining with Remember is a UI decision (backend treats them as separate decisions) |

## Remaining differences (explicit)

- **Electron UI** (frontend/permission-v1_1, integrated): one-click Ask | Allow | Deny application/process
  setter via `application-policy-v1` / `stored-ask-v1`; the cell shows the node's own rule only (a process
  without its own rule shows Not set; the inherited application rule is named in the tooltip and the Info
  "↳ App" row), scoped rules as "+N scoped" and a separate list; Remember checkboxes (application fixed;
  protocol, process, remote address, remote port; default application only) and the 8 deletion times;
  pending requests grouped by `request_group` (one card, count), settled requests removed; Ask source line;
  Essential `essential-interface-exclusion-v1` with a persisted per-interface exclusion (ppp0).
  Without the capabilities the UI degrades read-only (Ask never re-saved as Allow/Deny, no exclusions sent).
- **Ask on the host**: the installed release predates `stored-ask-v1`; the UI shows Ask
  read-only there until the next release is installed.
- **Custom weights 4+** (Weight control): not implemented; needs storage/schema.
- **For a while**: fixed 15 s (NetLimiter fixed, measured ≈10–18 s, not documented); FlowGate
  additionally scopes the lease to one direction and requires one verified owning process.
- **Named auto filters** (`<App>-<address>` filter nodes): FlowGate stores the same
  ANDed scope as one rule, without a reusable named filter object.
- **Duplicate scopes**: NetLimiter adds a second rule; FlowGate updates the existing
  identical-scope rule in place (same effective result, no duplicates).
- **Zone in Remember**: FlowGate's existing zone option remains available through the
  API; NetLimiter's dialog has none (UI should send `any`).
- **Process-instance rules** are a FlowGate extension (weight 4, session-bound).

## Evidence

- Ask (master fb5b2da): `TestStoredAskPrecedence`, `TestStoredAskLifecycle`,
  `TestRememberRefusedWhenAskStillWins`, `TestApplicationSetterAsk`; real receivers
  `scripts/process-rules-isolated.py --ask` → `scripts/ask_acceptance.py` (run
  `.workspace/ask-1792425996`, all PASS): application Out Ask persisted; TCP+UDP prompts
  attributed to the Ask rule (event + Decision Log `rule_ask`); Allow Once delivers, Deny
  Once does not; next independent attempt re-prompts; incoming, another executable and
  out-of-zone traffic independent; narrow Remember beats Ask for its destination only;
  application Remember replaces the Ask rule, settles waiting requests, later connections
  pass; equal-weight scoped Deny beats Ask; disable/delete stop attribution; read-only
  endpoint refuses; identical rules and enforcement after restart. Qt editor refuses to
  edit Ask/TCP+UDP rules (compiled). Expiry of Ask rules uses the shared expiry path
  (unit-covered), not a separate real-time run.

- Go: `internal/policy/weight_test.go`, `internal/daemon/application_policy_test.go`
  (setter never edits scoped rule, in-place update/stale refusal, Remember fields and
  Process binding, pending settle/ended attempts, grouping, Once no fan-out); corrected
  `process_test.go` tie expectation. Race/vet for daemon/policy/essential pass.
- Real private receivers (unprivileged user/network namespaces, `scripts/lab.sh`):
  `scripts/process-rules-isolated.py --app-policy` → `scripts/app_policy_acceptance.py`:
  application Out Allow delivers TCP/UDP IPv4/6 to 2 destinations × 2 ports with no
  prompts; scoped rule untouched; other executable still prompts; In not covered;
  waiting request settles and delivers after application Allow; equal-weight scoped
  Deny override; Local-zone-only Allow; application Deny updated in place with 0
  deliveries (incl. the scoped-Allow destination); identical rules after restart;
  owned-only nft cleanup. Run directory `.workspace/app-policy-c38646f-1792425326` (PASS on c38646f).
- Real Electron journey (`electron/test/permission-v1_1-real.mjs`, sandboxed GUI, held continuous fixture on exact
  33966e4, receivers judge delivery; PASS 12/12): Remember protocol+address+port stores udp 10.79.0.2:43001 only;
  cell Not set +1 scoped; one click Application Out Allow stores TCP+UDP any/any all zones, narrow rule unchanged;
  TCP/UDP IPv4/IPv6 to 2 destinations × 2 ports delivered with no prompts; cell stable 5 s (no blinking); other
  executable prompts, 3 identical attempts = 1 group row/1 window; incoming held (direction separate); scoped
  Deny blocks its destination while app Allow covers others; Out Ask set in place, prompt names the Ask rule,
  Allow once delivers, new attempt re-prompts, Remember(app) replaces Ask → Allow; no stale prompt windows.
- Electron journey scope note: Deny Once, Ask disable/delete, restart, read-only refusal and out-of-zone
  Ask were verified with real receivers through the API (`--ask`), not in the Electron journey.
- Not yet: host deployment of stored Ask (installed c09aae8 predates `stored-ask-v1`; the UI hides Ask there).
- For a while (`decision-for-a-while-v1`): `internal/daemon/for_a_while_test.go`; real receivers
  `scripts/process-rules-isolated.py --for-a-while` → `scripts/for_a_while_acceptance.py` (run
  `.workspace/fw1`, all PASS): Allow delivers the prompted TCP and later TCP+UDP IPv4/IPv6 connections of the
  same process without prompts; sibling instance, incoming direction and a relaunched PID prompt inside the
  window; after expiry the same process prompts; Deny blocks the current and later connections without
  prompts; Decision Log `for_a_while`; no rule at any time; no lease after daemon restart.

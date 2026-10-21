# Local API additions: conditional rule deletion

## Explicit TCP+UDP observed rules

Primary capability `observed-rule-any-protocol-v1` permits explicit
`observed_draft.protocol:"*"` on existing observed preview/save: one rule for TCP+UDP
only, unchanged exact target/draft/token/authorization/replay. `filter.protocol:"*"`
is preserved through versioned edits and history. Wildcard-to-specific edit is
rejected with `protocol_scope_changed` (fresh observed creation required), guarding
legacy clients. [Full contract and fixture](OBSERVED-RULES.md#tcpudp-observed-creation-extension).
No host rollout or automatic default broadening; old daemons retain TCP|UDP choice.


## Process-instance extension (deployed on host monitor 60d35a3)

Primary capability `process-instance-rules-v1` adds explicit process targets with
pinned native/session identity, process-tier precedence and inactive lifecycle
metadata. Application rules remain unchanged. See [PROCESS-RULES.md](PROCESS-RULES.md)
for schema3 preview/save/edit/delete, inventory, authorization and exact limitations.
Earlier application-only scope/precedence descriptions below refer to legacy rules.


## Daemon-owned incoming evaluation (new, isolated verification only)

`daemon-evaluation-v1` adds asynchronous readiness/Start/Stop to the existing root
`serve` daemon without another database/API owner. Selected administrator control
requires explicit `--allow-evaluation`; ordinary startup remains non-enforcing.
Fixed300s deadline, session/generation guards, cleanup acknowledgement, independent
watchdog; Activity, stored rules, Decision Log and UDP ownership survive Stop.
Exact contract, limitations, evidence and future deployment:
[DAEMON-EVALUATION.md](DAEMON-EVALUATION.md). **The running host daemon was not
restarted, granted this permission, or used for enforcement in this increment.**


## Decision log

Additive `decision-log-v1` (`decision-log`, `decision-log-get`); exact request,
record, health, cursor, visibility and error contract in [DECISION-LOG.md](DECISION-LOG.md).


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


## Observed-application rule creation

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


## Current: backend-authoritative Activity policy metadata

Capability `policy-explanations-v1` adds primary-only, generation-bound read-only
`policy-view` batches and separate `policy-explain` recorded-event evaluation.
Exact decimal-string versions/sequences, policy token, expiry/order guards, native
association limits and captured real API examples are in
[POLICY-EXPLANATIONS.md](POLICY-EXPLANATIONS.md). Existing mutations/numeric version
contracts are unchanged; companion metadata is not expanded.


The existing newline-delimited authenticated Unix protocol remains **v1**. No new
socket, privileges, database table or migration. Responses advertise
`capabilities: ["conditional-rule-delete-v1"]`. This means protocol support, not
permission: check `read_only`, mode and enforcement health independently.

## Conditional Delete

Use the **generation and numeric version from the rule snapshot actually shown**:

```json
{"version":1,"operation":"rule-delete","generation":"<listed-generation>","id":"<listed-rule-id>","expected_version":3}
```

Success (other existing response fields omitted here):

```json
{"version":1,"generation":"<listed-generation>","deleted_rule":{"id":"<listed-rule-id>","version":3}}
```

Stale version:

```json
{"version":1,"generation":"<current-generation>","error_code":"version_conflict","error":"stale rule version; reload before deleting"}
```

`expected_version` is mandatory, including **0** for older stored rules whose
optional version field is absent. `generation` is mandatory. Never generate a
version locally, refresh the version behind an open confirmation, or fall back to
unconditional Delete. A newer version needs a newly shown snapshot/confirmation.
`deleted_rule` acknowledges exactly the removed version. An error has no success
acknowledgement. The handler rechecks UID authorization before exposing a version
conflict; existing root-administrator and selected-user rules are unchanged.

| `error_code` | Result and client action |
|---|---|
| `version_conflict` | Rule changed; no mutation. Reload and ask again. |
| `generation_conflict` | Missing/changed backend generation; no mutation. Reload session and rules. |
| `not_found` | Already absent; no mutation. Inspect current list; not idempotent success. |
| `forbidden` | Peer/user not authorized; no mutation. |
| `read_only` | Monitor/read-only socket; no mutation. |
| `unavailable` | Non-active enforcement or no durable store; no mutation. |
| `persistence_failed` | SQLite transaction failed; stored/effective rule and caches unchanged. |
| `invalid_request` | Missing condition/ID or malformed request; no mutation. |

A connection failure/timeout is a **transport error**, not proof that deletion
failed. If the response was lost after commit, the rule is already absent. Fetch
an authoritative `list` with its generation; inspect the result and do not
replay an unconditional deletion. The API has no durable request-ID replay log.
Two concurrent conditional deletes yield one success and one `not_found`.

The condition, SQLite `Store.Replace` transaction and policy publication are all
under the same engine mutex used by Save and legacy changes. Edit first means
stale Delete conflicts; Delete first means a stale edit returns `not_found` and
cannot recreate. Only after durable commit are effective rules published and
pending/cached events conservatively invalidated; retained packets drop. Existing
approved TCP connections continue under the unchanged initiation contract.

API-created rule IDs are random 128-bit server-issued IDs, not application names,
scope hashes or client-provided IDs. Recreating the same scope gets a different ID,
even if its new version is 1. Remembered decisions derive IDs from unique pending
IDs; deletion invalidates those events. A restarted controller gets a new random
backend generation even if it loads an identical stored ID/version. Internal
`SetRules` is startup loading, not a runtime import API. Versions cannot wrap on
edit/enable/disable; an exhausted uint64 version requires delete/new creation.
The supported model is one controller owning its store, not direct SQL writers or
multiple independent engines concurrently replacing one database.

## Compatibility and caller migration

Legacy v1 `{"operation":"rule","action":"delete","id":"..."}` is retained
for existing Qt/older clients. It **does not check generation or version**. A
client-side list/precheck cannot make it safe against concurrent edits. Merely
adding condition fields to that legacy operation does not change its semantics.
There is no silent fallback from `rule-delete` to the legacy operation.

Both integrated clients now use one `rule-delete` with the displayed snapshot's
frozen generation/ID/version and require the capability. No legacy fallback is
exposed by either Delete control. Qt preserves uint64 values as decimal tokens
through parsing/serialization; Electron rejects values above 9007199254740991
explicitly rather than rounding them. Qt/Electron migration is complete. Existing
Save behavior remains versioned; stale/missing/authorization/persistence errors
also carry the corresponding structured codes above. Other editor validation
errors may still have only the existing `error` string.

CLI (with an already running authorized controller):

```sh
.workspace/flowgate rule-delete --socket /path/to/control.sock --id RULE_ID
# Lists/displays exactly that rule and asks for confirmation; deletes that version.
# Noninteractive: --yes still snapshots and prints the version before deleting.
.workspace/flowgate rule-delete --socket /path/to/control.sock --id RULE_ID --yes
# Explicit snapshot tokens for scripts; neither token can be omitted:
.workspace/flowgate rule-delete --socket /path/to/control.sock --id RULE_ID \
  --generation LISTED_GENERATION --expected-version LISTED_VERSION --yes
```

The implicit-snapshot CLI checks the advertised capability and refuses a legacy
fallback. It never automatically retries a conflict, cancellation or ambiguous
transport result. No controller is started and no privilege elevation occurs.

## Focused verification

```sh
. scripts/go-env.sh
go test -race ./internal/daemon ./internal/store ./internal/policy ./cmd/flowgate
go vet ./...
go build -o .workspace/flowgate ./cmd/flowgate
scripts/lab.sh python3 scripts/acceptance/host-lab.py \
  "$PWD/.workspace/delete-receiver-$(date +%s)" --delete-suite
```

Authenticated Unix API tests use channels/barriers around the durable transaction,
not sleeps, for both edit/delete orderings and competing deletes. Actual SQLite
abort-trigger rollback, storage reopen, wrong-UID/read-only/health errors,
recreation, generation mismatch and deliberate response loss are covered. The CLI
confirmation test edits the rule while the confirmation reader is active: it
proves Delete uses the version displayed before confirmation, not a fresh version.

`.workspace/delete-tests.log`, `delete-regression.log`, `delete-vet.log` and
`delete-receiver.log` retain local evidence. The isolated host-mode veth receiver
check admitted persistent UDP, matched another source port, conditionally deleted,
then held the next attempt until Block; no third datagram reached the receiver.
This is isolated enforcement evidence, not live-host testing. Settled frontend,
UDP accounting, ownership and broader firewall suites were reused unchanged.

## Read-only CLI diagnostics (separate from policy IPC)

`flowgate doctor --json` now emits schema-version-1 check objects with stable
`id/status/code/detail/next`, explicit namespace/credential context and completed
privileged-check IDs. No policy API operation, field or authorization changed.
Known startup errors are prefixed `[reason_code]` while preserving existing terminal
bridge behavior. No frontend automatically invokes sudo or diagnostics. See
[DIAGNOSTICS.md](DIAGNOSTICS.md) for the full bounded read-only contract and commands.

## Explicit administration (additive v1 capability)

`explicit-administrator-v1` advertises response metadata, for example:

```json
{"permissions":{"role":"administrator","observation_scope":"machine","policy_scope":"machine","can_manage_rules":true,"can_decide":false},"mode":"daemon-monitor","enforcement":{"state":"stopped"}}
```

Roles: user/administrator. Observation scopes: self/machine/user-visible (legacy
ordinary observer). Policy scopes: self/machine. Grant is root configuration only,
not request data; private selected-UID SO_PEERCRED authentication remains required.
`.monitor` sets both mutation permissions false. `daemon-monitor` permits durable
rule CRUD with the existing generation/version tokens, never packet decisions.
List can contain both Activity and rules/events. Existing modes/fields remain.
Clients must not equate `read_only=false` with active enforcement; use enforcement
health and separate can_manage_rules/can_decide. Old clients may need a permission-
aware UI adaptation; current launchers do not select this new mode automatically.
No new cross-user privilege exists on default prototype endpoints.

## Root monitor lifecycle and observation compatibility

The non-enforcing daemon companion reports `mode:host-monitor`,
`backend_mode:daemon-monitor`, `read_only:true` so existing observation clients
can attach unchanged. The primary retains daemon-monitor mode and permission
metadata. This is one Go process; no collector or controller is started implicitly.

`monitor-stop-v1` advertises lifecycle support in daemon-monitor only. Request:
`{"version":1,"operation":"monitor-stop","generation":"EXACT_LISTED_GENERATION"}`.
Only UID0 via SO_PEERCRED on the primary endpoint may stop it; the delegated
administrator cannot. Errors: read_only, forbidden, unavailable,
generation_conflict. Accepted response adds `stopping:true`; shutdown follows
the response attempt even if the client lost it. Inspect authoritative process/
endpoint state rather than replaying; never use an unconditional stop.
This operation is not an enforcement Stop/recovery operation.

## Controller observation companion / coexistence diagnostics

When the host controller supplies Activity, its read-only companion now uses
mode=host-monitor, backend_mode=host-enforcement; its primary still uses
host-enforcement with actual health/profile. ReadOnly and permission flags remain
authoritative. No frontend mutation/activation grant changes. The root monitor's
existing companion contract is unchanged; monitoring Stop does not stop controllers.

Terminal refusal codes add tailscale_unsupported, tailscale_profile_unsupported,
administrator_required and policy_database_owned. Doctor's planned profile/admin
flags only inspect; they neither grant roles nor activate policy. Existing API
Enforcement.profile remains incoming/both; this profile accepts incoming only.
See COEXISTENCE.md for the finite configuration and activation boundary.

### Decision Log integration correction

`decision-log-v1` remains additive. Health now includes `flush_interval_ms`,
`durable_after:"sqlite_transaction_commit"`, `crash_loss_bound_ms:null`.
Legacy `durability_window_ms` is a deprecated nominal interval, never a bound on
crash loss. Capacity final records have no individual `request_id`; additive
`aggregation:{observations,first_seen,last_seen,window_ms}` and the reason text
identify counted initiation observations, not unique connections. Read the full
[deduplication and durability contract](DECISION-LOG.md). A final missing from a
loaded page/filter must be labelled **Outcome not loaded**, not presumed absent.

## Terminal bridge executable selection (launcher compatibility)

`scripts/desktop-control.py` and `scripts/traffic-control.py` accept the optional
`--backend {flowgate,electron-backend}` enum. Default `flowgate` preserves Qt and
existing terminal callers. Electron supplies the fixed internal argument
`--backend electron-backend` and builds `.workspace/electron-backend`, leaving the
host-approved `.workspace/flowgate` executable untouched. No renderer-supplied path
is accepted: each enum resolves only to that fixed repository workspace filename;
absolute paths, traversal and other names reject before authentication.

This is a local terminal bridge argument, not a Unix API field or authority grant.
Authentication and existing sudo policy are unchanged; a fresh executable path may
require interactive authentication. Desktop Stop/Status/Recovery still prefer the
existing root-pinned `/run/flowgate/controller` and use the selected workspace
executable only as their existing fallback. UDP Start uses the selected executable;
daemon-owned collector/evaluation API paths do not use these legacy bridges.
No password is collected by Electron, and no privilege configuration is changed.

Focused check: `PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check-bridge-backend.py`.
Four checks cover default/selected builds, pinned preference and invalid argument
rejection. Authentication/control are explicitly mocked; no host or namespace
firewall/collector activation is performed or claimed by these tests.

## Activity initiation evidence

Capability **`activity-initiation-v1`** is advertised on primary and companion
endpoints with Activity collection. Existing `list` gains `activity.rows[].initiation`:

```json
{"state":"known","direction":"outgoing","source":"inet-diag-syn-sent","reason":"Observed TCP SYN-sent on this kernel socket cookie; retained only while this socket remains continuously visible","observed_at":"<last direct handshake sample RFC3339>"}
```

`state` is `known`, `listening`, `unconnected`, `unknown` or `ambiguous`.
Only `known` carries lowercase `direction:incoming|outgoing`. Existing display
`row.direction` is `Incoming`, `Outgoing` or `Unknown`; it is not byte direction.
Other examples: `{state:listening,source:inet-diag,reason:...}` for a TCP listener,
`unconnected` for UDP without a peer, `unknown` for connected UDP or established
TCP whose handshake was not sampled. No initiation is inferred from listener port,
process/name, endpoint convention, stored rules, connection state alone or traffic.

Incoming source `inet-diag-passive-request` requires a sampled TCP SYN-received
passive request: inode zero **and absence of full-socket diagnostic framing**.
An orphaned full socket also can have inode zero, so inode alone is insufficient.
A full socket in SYN-received is ambiguous (simultaneous open is possible).
Outgoing requires an actual SYN-sent sample. The existing bounded census is reused;
no BPF hook, conntrack lookup, faster poller or process/per-packet scan is added.

`observed_at` is the last direct handshake observation. It is retained unchanged
once established; additional sampled SYNs before establishment may advance it.
Freshness is `activity.started/collected` and the usual backend generation/sequence,
not observed_at (which can legitimately be old on an enduring connection).
Continuity is keyed by network namespace/family/protocol/kernel cookie, with exact
endpoint/inode constraints. The kernel copies a passive request cookie into its
accepted socket; only that observed zero-to-live-inode transition is retained.
Existing row IDs are not changed: a request row's inode transition may produce a
new row ID, while the kernel-cookie initiation evidence remains valid. No
endpoint-only matching or application authority is created by that association.

Cache is bounded by current census rows (at most2048), removed on disappearance,
observed disconnect/close, observer restart, incomplete census or sample gap>60s.
Conflicting handshake/identity observations become ambiguous until continuity
ends. New cookies do not inherit evidence. Handshakes and disconnect/reconnect
transitions entirely between samples cannot be reconstructed; this reports an
observed socket handshake, not a durable connection-event history. Pre-existing
or fast TCP connections can therefore remain unknown; no complete-coverage claim.

These read-only fields follow existing UID/administrator Activity projection and
never authorize a rule target, decide retained packets or assert a past verdict.
Permission flags, read-only restrictions and all mutation APIs remain unchanged.
Old daemons omit the capability/fields; render explicit unknown instead of guessing.
The running host daemon has not been restarted to expose this addition.

Focused checks: source `scripts/go-env.sh`, then `go test -race ./internal/identity
./internal/daemon` and `go vet ./internal/identity ./internal/daemon ./cmd/flowgate`.
Real isolated fixture (separate binary/database, no host collection/enforcement):

```sh
. scripts/go-env.sh
go build -o .workspace/flowgate-direction ./cmd/flowgate
scripts/lab.sh python3 scripts/acceptance/activity-direction-isolated.py \
 --binary "$PWD/.workspace/flowgate-direction" --run "$PWD/.workspace/direction-FRESH"
```

Add `--hold` for an exclusively assigned UI driver. It writes ready.json with the
actual endpoint and sampled sockets; backend cleans after explicit UI DONE by
touching only that run's `quit`. SYN-ACK holding uses private-namespace fixture nft
rules, deleted before READY. It never starts FlowGate enforcement, loads BPF or
uses a host endpoint. UI controls only this disposable daemon/database.

## Application display metadata

`application-display-metadata-v1` adds `display_name`, `display_executable` and
`executable_status` (`linked`, `deleted`, `unavailable`) to application metadata.
A verified zero-link `/proc/PID/exe` is displayed without its kernel ` (deleted)`
suffix; legacy name/executable, key and revision stay unchanged. Display paths
may select an installed desktop icon, never authorize a policy or substitute the
replacement file's identity. The old running image remains a separate revision.
Read-only host Firefox inspection found PID3053 running zero-link inode5706575;
its existing disk path points at inode5959864. No process restart or file change.
Private evidence: `.workspace/firefox-executable-status.json`. A real isolated
unlink/replace test proves metadata cleanup retains the running revision and key.

## Essential system networking v1

Capability `essential-system-networking-v1` provides administrator-only reviewed
preview/apply/status/removal. Schema5 preserves exact service identity and explicit
interface/stub constraints. See [ESSENTIAL-NETWORKING.md](ESSENTIAL-NETWORKING.md)
for payloads, authorization, errors, expiry, receipt reconciliation and compatibility.
No operation activates protection.

## Launch provenance and permission target (display only)

Additive, no capability flag (absent fields mean an older backend). Captured by
`internal/identity/provenance.go`; never consulted by policy, keys or matching.

- `owners[].provenance`, `activity.processes[id].provenance` and, for the
  principal owner (single owner or broker client), `attribution.provenance`:
  `{evidence: verified|unavailable|none, reason, role: launcher|game|runtime|helper,
  group, stop, ancestry[≤12]: {pid, start_ticks, uid, name, executable, revision,
  marker}, launch?: {kind: umu|proton|steam|wine, launcher_pid,
  launcher_start_ticks, launcher_name, game?: {name, title, executable, revision,
  status: verified-file|not-found, source}, prefix, prefix_id (dev:ino),
  prefix_source, runtime, steam_app_id, game_id, markers[]}, captured_at}`.
  `verified` = the /proc parent chain from the owner to the launcher was walked
  with start-time checks (a parent newer than its child = PID reuse, walk stops;
  PID 1 ends it; nothing is invented). `none` = complete chain, no launcher.
  `unavailable` = chain broke first. Markers come from cmdline/exe only
  (umu-run, `proton run|waitforexitandrun|runinprefix`, srt-bwrap/pv-adverb/
  pressure-vessel, wineserver, Steam `reaper SteamLaunch`, Wine loader). Only
  WINEPREFIX, STEAM_COMPAT_DATA_PATH, SteamAppId, SteamGameId, PROTONPATH, UMU_ID
  and GAMEID are read from environ (owner and ancestors, values ≤1 KiB). `game.title`
  is the PE version-resource ProductName (bounded). Results are cached per
  boot/pidns/PID/start while the process lives (≤4096 entries), so a helper keeps
  what was seen at first sight after reparenting; events keep the attribution
  captured at request time after the owner exits.
  `invocation?` records a bounded Python/Node entry mode and, for a regular
  file argument, its process-namespace path and device/inode-proven host path
  when available. `invocation.application` is display metadata only. Inline
  source text, arbitrary arguments, and environment values are not retained.
  The executable permission target remains the interpreter.
- `attribution.permission_target`: `{kind: helper|application|interpreter|unavailable,
  label, once, for_a_while, remember, shared_with_note, key_basis, prefix}`, derived
  at serialization from the attribution's current identity: Once = this request;
  For a while = this PID+start only (unavailable unless exactly one visible owner);
  Remember = the application key (UID + kind + prefix + executable path, revision
  = file stamp). A Wine/Proton helper's target names its prefix and states it is
  shared by every game using that prefix; native interpreters state that every
  script they run is covered. The UI renders these strings verbatim.

## Published request lists

`request-list-snapshot-v1` adds `snapshot_revision` (a positive decimal uint64
**string**, scoped to `generation`) and `snapshot_at` to list replies and
completed control replies. Clients must compare revisions as integers without
converting them to floating-point numbers. A daemon generation change resets the
sequence.

The API reads an immutable publication of events, request-rule metadata, previous
revision rules, zones, rules, rule states and process leases. Caller ownership
filtering still applies. A shared per-engine publisher runs every 250 ms while an
API listener exists and owns deadline expiry and pruning even without a GUI.
Readers project elapsed deadlines and lease expiry on their own copies. These
copies never authorize decisions: live mutation handlers validate authority,
identity, generation, deadlines and the selected scope.

Mutations and revalidating previews publish before their acknowledgement; pure
status, log and policy queries reuse the last publication. Clients
ignore older snapshots and lists that were already in flight when a decision
completed. An acknowledged request must not reopen from the same or an older
publication. A missing acknowledgement means an unknown outcome; reconcile via a
fresh list without automatically retrying the decision. Legacy daemons without
this capability retain the existing request-order reconciliation.

Publication still briefly holds the engine lock to capture and serialize state;
this is separation of API list reads, not a claim that policy evaluation and all
filesystem/liveness checks are lock-free. The internal synchronous `ListWithZones`
helper remains for compatibility. Activity and enforcement health have their own
sources and are not part of the request snapshot revision.

## Historical script labels and application versions

Rules may retain an optional `invocation` display object (`mode: file`, `name`,
`path`, `revision`) captured from the verified socket owner's observed invocation.
It is historical context, not evidence that a script was executed and never a
permission matcher. Rule edits preserve the backend's stored context; client
metadata cannot replace it. Interpreter rules still cover the interpreter under
their explicit rule filters, not only the recorded script. Old rules without
recorded context keep their executable label.

Activity groups revisions by backend application key and UID. Earlier saved
versions remain individually accessible beneath the program, with their original
rule targets. Names alone never merge permissions or different application keys,
users or Wine prefixes. Distinct same-name identities show their path, UID and
identity discriminator inline. A single recorded script can label a not-running
row as `script via interpreter`; mixed contexts keep the interpreter name and
list the recorded script paths in Details.

### Startup cleanup of obsolete saved rules

The exclusive daemon writer archives expired rules and confirmed replaced native
executable revisions at startup, including restarts through `update-and-start.sh`.
The complete rule JSON, reason, and timestamp are retained in `archived_rules` in
the private policy database, in the same transaction that removes the active rule.
Failure leaves the active rules unchanged and prevents startup with partial policy.

A replaced version must have the same exact native executable path and user key,
a different current file stamp, and no old executable inode in the process census.
Incomplete process visibility or an uncertain alternate root/mount view preserves
the rule. Missing files, side-by-side executable paths, Wine/Electron/runtime
identities, and absent script display metadata do not qualify for this cleanup.
This is a conservative startup snapshot, not a guarantee against later rollback;
restoring an older binary may require a new decision. Archives are recovery data,
not active permissions; there is no automatic transfer to the replacement version.
A matching already-running daemon is not restarted solely to perform cleanup.

### Shared saved native permissions for the administrator and root

Saved native application rules owned by the daemon's configured non-root
administrator also cover UID 0 for the exact executable and revision. The server
records the verified counterpart key in `root_application` on the rule and policy
references. Startup migrates eligible existing rules atomically through the rule
store and increments changed rule versions; new reviewed rules describe the same
scope. No rule is inferred from a display name, launcher, or sudo command line.

This scope applies to saved Allow, Block and Ask rules, preserving direction,
endpoint, expiry, disabled state, priorities and Block precedence. Once and
process-instance permissions stay unchanged. Other users, Wine/prefix identities,
Electron hosted identities and native identities whose original key cannot be
verified from their executable path remain separate. Existing root-only rules
remain explicit root rules and can override a shared Allow through normal policy
precedence. There is no blanket privilege-based network bypass.

Electron groups top-level entries with the same exact executable path under one
visual program when multiple accounts/identities exist. Original account rows,
rule IDs and request IDs remain children; the visual parent has no rule target.
Different executable paths are never combined merely because their names match.

### Update verification and stopped-install recovery

The monitoring installer verifies unchanged rule documents, the exact native
user/root scope migration (including its version increment), and removals backed
by a new matching cleanup archive. Unexpected mutations or unarchived removals
still fail verification. Startup can migrate data even if installation later
fails; failure handling retains the current database and never restores an older
one automatically.

After an installation failure has stopped the daemon, run
`scripts/update-and-start.sh --recover-stopped`. Recovery requires no running
daemon, no FlowGate interception tables, and persisted monitoring intent before
installation. The installer verifies monitoring first; the updater then restores
the requested profile (Both by default). `--dry-run` remains read-only.

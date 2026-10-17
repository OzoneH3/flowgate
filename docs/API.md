# Local API additions: conditional rule deletion

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
scripts/lab.sh python3 scripts/host-lab.py \
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

# Native process-instance rules

Primary capability **`process-instance-rules-v1`** extends the existing observed
preview/save/status, versioned edit and conditional Delete APIs. Electron stays
unprivileged. This increment is isolated-only: the running host build is unchanged.

## Scope, precedence and lifetime

An application rule still covers its exact application key, revision and UID across
instances. A process rule additionally binds a server-issued instance ID to daemon
generation, Linux boot ID, PID/start ticks, UID, network/mount/PID namespaces and
native executable path/revision. A pinned pidfd guards lifetime and PID reuse.
Never authorize from a PID, display association, icon, process metadata or rule
inventory alone. Preview/save freshly verify an exclusive native socket holder;
every new admission resolves ownership again and checks the pinned live identity.
Shared/unknown ownership and unresolved runtime/Wine identities cannot obtain or
use an exclusive process permission. No namespace traversal is added.

Matching **process tier precedes application tier**, regardless of their relative
priorities. Inside each tier existing descending priority, then ascending rule ID
ordering is unchanged. No matching live process rule means application fallback,
then the existing engine default. Scope still includes explicit direction, TCP or
UDP (or explicit TCP+UDP with `observed-rule-any-protocol-v1`), remote address/CIDR,
local/remote ports. See the capability contract in [OBSERVED-RULES.md](OBSERVED-RULES.md#tcpudp-observed-creation-extension). There is no new filter/action model.
Direction is connection initiation, independent of upload/download.

Normal threads belong to the live thread-group leader. A fork child is a distinct
instance; inherited shared sockets cannot receive an exclusive grant. Worker-only
ownership after leader exit is unsupported. Exit, observed credential/namespace
change or executable/revision change permanently retires a binding. **An exec of
the same executable retaining PID/start/UID/namespaces/revision is the same native
identity in this model.** Unobserved exec-away-and-back between checks cannot be
reconstructed; there is no exec-epoch tracing claim. A fresh preview may pin a
new binding, but cannot revive the old one. pidfd/inspection failure is explicit
unavailable/inactive, with no application-wide substitution.

Rules are session-lifetime: zero/year-1 expiry means until process identity ends
or this daemon session ends, **not permanent permission**. A nonzero absolute
expiry is an additional upper bound. SQLite retains the full schema3 document
across restart for inventory, versioned cleanup and history; a different daemon
generation makes it inactive forever. It never rebinds to a reused PID or surviving
process. Application documents retain their previous schemas and semantics.
An older backend rejects unsupported schema3 instead of loading it as an app rule.
Stored process-rule documents and their inactive inventory are durable data even
though enforcement is session-bound. After any are stored, keep a compatible
executable; downgrading needs a reviewed data-preserving migration/restore plan
(compatible reader or re-importable export). Never delete, widen or strip the
process binding to make an older binary start.

Existing admitted TCP connections are not terminated. New admissions and UDP
leases re-evaluate the winning tier before using a cached decision; a configured
Block also supersedes a retained Once grant. Existing reply/startup preservation
and independent collector/watchdog semantics are unchanged.

## Creation and editing

Existing primary permissions apply: **can_manage_rules**, independent of decision,
collector or enforcement activation authority. Ordinary peers retain UID scope;
explicit administrators may target supported system services. Read-only companion
creation/edit is rejected and does not advertise this capability.

```json
{"version":1,"operation":"observed-rule-preview","generation":"<list.generation>","observed_target":{"row_id":"<current stable socket ID>","process_id":"<PID:start from Activity>"},"observed_draft":{"target_scope":"process","direction":"incoming","protocol":"udp","action":"allow","remote_address":"*","local_port":0,"remote_port":0,"disabled":false,"expires":"0001-01-01T00:00:00Z"}}
```

`target_scope` is `application` (legacy default) or `process`. No caller binding is
accepted as authority. Preview returns the existing `observed_preview` object,
30-second token/expiry, complete rule and readable reviewed scope/precedence,
verified application/principal and current enforcement coverage. A process rule
has schema3 and `filter.process`:

```json
{"instance_id":"<32hex>","session":"<generation>","boot_id":"<Linux boot ID>","pid":123,"start_ticks":"987654321","uid":1000,"netns":"net:[...]","mountns":"mnt:[...]","pidns":"pid:[...]","executable":"/path/to/native","revision":"<native revision>"}
```

PID start ticks are lossless strings. Rule versions retain existing uint64 wire
semantics; policy references have exact decimal strings. Do not round either.
The server reuses a live canonical binding across previews/rules for that instance.
`observed-rule-save` sends generation, preview_token and the **identical** draft;
it rechecks live identity/authorization and publishes only after SQLite commit.
A process that exited requires a fresh live target; it cannot be saved from a
cached preview. Creation never activates enforcement or approves pending packets.
Monitoring preview/ACK clearly says stored-only, regardless of Allow/Block.

Existing `observed-rule-status` and bounded five-minute same-token receipts handle
lost ACK without duplicate creation. Do not automatically submit a fresh token;
reconcile the authoritative receipt/list. A changed/deleted receipt yields conflict.
See [OBSERVED-RULES.md](OBSERVED-RULES.md) for the unchanged principal/generation/
draft binding and transport ambiguity contract.

Edit through `rule-preview`/`rule-save` preserves the entire schema3 process binding,
application/revision/UID/direction, and uses expected_version. No conversion between
process/application or rebinding is allowed. Active permission edits revalidate
current exclusive ownership. Inactive targets cannot be enabled or edited into an
active permission; disabling an inactive record is allowed. Conditional Delete
remains available. Preserve siblings/app rules and absolute expiry on edits.

Added structured reasons: `unsupported_process`, `target_inactive`,
`immutable_target`; existing `stale_target`, `preview_expired`, `preview_mismatch`,
`generation_conflict`, `version_conflict`, `read_only`, `forbidden`,
`persistence_failed`, replay/conflict codes retain their meaning.

## Inventory, explanation and history

`list.rule_states[id]` adds `{target_scope:application|process,state:active|inactive,
reason}`. This is target lifecycle, **separate from disabled/expired and enforcement**.
`rules[]` remains the complete authorized editable record inventory.

`policy_view.applications[]` contains application rules only. Additive
`policy_view.processes[]` entries contain `ref`, `process_id`, `application_ref`,
`target` (binding), `state`, `reason`, `incoming`, `outgoing`,
`application_incoming`, `application_outgoing`, and
`precedence:"matching-process-before-application"`. Process summaries include only
that exact target; app fallback is separate, never a fabricated effective verdict.
Relevant refs include `target_scope`, `target_state`, `target_reason`, full scope
and exact string version. Exited/old-session stored targets remain in this batch.
It is bounded at256 entries, with `complete:false` on truncation. `list.rules` still
provides all authorized rules (max256).

Live supported native candidates without a preview may have empty `instance_id`
and an `observed:...` ref. This is provisional **metadata only**, never authority.
Pin the full nonempty returned preview binding; a changed instance requires fresh
review. Policy snapshot tokens cover stored rule target liveness; exit changes
the token, not stored rule version/expiry. Generation, sequence and expiry response
ordering guards remain as documented in [POLICY-EXPLANATIONS.md](POLICY-EXPLANATIONS.md).

Decision Log rule snapshots include `target_scope` and the immutable full
`filter.process` at decision time. Later target exit, edits or restart do not rewrite
history. A current explanation is not an old admission result or delivery proof.

## Focused evidence and reproduction

Build without replacing the deployed `.workspace/flowgate`:

```sh
. scripts/go-env.sh
go build -o .workspace/flowgate-process ./cmd/flowgate
go build -o .workspace/process-fixtures/native ./fixtures/process-rule
go test -race ./internal/identity ./internal/policy ./internal/daemon ./internal/decisionlog ./internal/store
go vet ./internal/identity ./internal/policy ./internal/daemon ./internal/decisionlog ./internal/store ./internal/hostfirewall ./cmd/flowgate
scripts/lab.sh python3 scripts/acceptance/process-rules-isolated.py --binary "$PWD/.workspace/flowgate-process" --native "$PWD/.workspace/process-fixtures/native" --run "$PWD/.workspace/process-check-$(date +%s)"
```

Only disposable user/network/PID namespaces and databases are used. Two instances
of the **same native executable** have distinct sockets. The receiver suite tests
incoming/outgoing TCP/UDP IPv4/6 Allow/Block versus sibling and app fallback,
process precedence, disable/enable/delete, actual exit/different-executable exec,
restart inactive persistence and Decision Log target snapshots. Thread/generation/
namespace/UID/shared/preview/SQLite failure/replay/privacy cases have focused tests;
PID-reuse checks are **simulated generation cases**, not an actual forced PID wrap.

For UI acceptance add `--hold`: it starts a monitor-only instance, writes ready.json
with private primary/companion, generation, both instances and selected targets.
UI alone owns API mutations until explicit DONE. JSON command file supports
`{"op":"exit","name":"alpha"}`, `exec`, `counts` and `quit`; results appear in
command-result.json. Backend sends quit only after UI releases ownership, then
verifies cleanup. No privileged host collector or host firewall is touched.

### Recorded private-fixture response

This excerpt is from `.workspace/pr-guard/example-preview.json`, for beta in the
disposable namespace (UID0 is namespace root, not a host rule). Full reviewed text
and application metadata remain in the local response artifact.

```json
{
  "observed_preview": {
    "token": "e7026a96e2ec6f2e85a0a363c301a9ef",
    "expires_at": "2026-10-18T14:04:15.866473911+02:00",
    "rule": {
      "version": 1,
      "executable": "/home/flowgate-user/Apps/flowgate/.workspace/process-fixtures/native",
      "created": "2026-10-18T14:03:45.866473911+02:00",
      "disabled": false,
      "schema": 3,
      "id": "user:aebcc58e3e041c10500fc2c1f867985d",
      "priority": 100,
      "filter": {
        "process": {
          "instance_id": "3aa311b43aa911fd0bcfc8132a605e66",
          "session": "11e119ca609b1fe5ea385bf3a168cc8e",
          "boot_id": "0df97295-4d92-47cb-aca5-e634069c655f",
          "pid": 28,
          "start_ticks": "19453521",
          "uid": 0,
          "netns": "net:[4026534688]",
          "mountns": "mnt:[4026534576]",
          "pidns": "pid:[4026534687]",
          "executable": "/home/flowgate-user/Apps/flowgate/.workspace/process-fixtures/native",
          "revision": "51:28037340:5054457:1792324717836441883:1792324717837530621"
        },
        "application": "6b3b6bc188734a968b2468ebd8e77e1b03209bc8c0a8549e16b07c227eabdbc7",
        "revision": "51:28037340:5054457:1792324717836441883:1792324717837530621",
        "direction": "incoming",
        "protocol": "udp",
        "remote_address": "*",
        "uid": 0
      },
      "action": "block",
      "expires": "0001-01-01T00:00:00Z"
    },
    "process_id": "28:19453521",
    "principal_uid": 0,
    "enforcement": {
      "state": "active",
      "covered": true,
      "reason": "Profile covers new attributable TCP/UDP initiations; existing admission, bootstrap exceptions and other firewalls are separate"
    }
  }
}
```

Its matching save uses the returned token and exactly the incoming/UDP/Block draft
with target_scope process, wildcard address/ports and year-1 expiry. The saved rule
retains that entire binding. Decision-time evidence is in
`.workspace/pr-guard/decision-example.json`; `target_scope:process` and full binding
are historical snapshots even after this fixture exits.

### Held native pending-prompt fixture

For a UI-owned pending-decision journey, the existing disposable process fixture
also supports `--hold --hold-enforcement --zones`. Unlike ordinary `--hold`
(monitor only), this starts the existing isolated `host-start --profile both`
engine with its independent **300-second watchdog** and 60-second pending/socket
waits. This is not the incoming-only host daemon evaluation API and does not
establish outgoing host/Tailscale support. Run only through `scripts/lab.sh`, with
a separate candidate executable, native fixture and fresh `.workspace` directory.
Start only when the UI driver is ready; do not extend/renew automatically.

`ready.json` publishes exact generation, socket endpoints, alpha/beta identities,
ports, active profile/deadline, and command path. Write one JSON command at a time;
remove/read `command-result.json` between commands:

- `{ "op":"incoming", "name":"alpha", "protocol":"udp", "v6":false }`
  sends from the disposable peer to that native receiver.
- `{ "op":"outgoing", "name":"alpha", "protocol":"tcp", "v6":false }`
  starts a native connection to the disposable peer (TCP43000, UDP43001).
- `{ "op":"counts", "name":"alpha" }` reports receiver payload counts keyed
  by tcp4/tcp6/udp4/udp6; `peer-counts` reports actual peer receive log lines.
- `quit` ends the held fixture; backend cleanup follows explicit UI DONE only.

Only one owner drives API decisions/commands while attached. Scope previews are
backend supplied. Pending Decide supports Once, one-hour application, and durable
persistent application only; it does **not** create process-only or zone-constrained
rules. Remember is exact application/revision/UID/direction/protocol/remote peer and
service port, Any zone. `event.flow.network_scope` is contextual classification,
not the scope of a remembered permission. Process/zone creation uses its separate
identity-bound preview/save workflow.

Focused fixture smoke: `.workspace/prompt-hold-smoke-results.json` records real
incoming UDP Allow receiver1 / Deny receiver0; outgoing remembered UDP receiver2
including same-executable sibling application scope; nonmatching outgoing TCP
prompt then Deny receiver0. Exact conditional cleanup restored rules0 and owner log
confirms namespace cleanup. This verifies the added fixture commands/timeouts,
not a new host acceptance or a rerun of the settled protocol matrix.

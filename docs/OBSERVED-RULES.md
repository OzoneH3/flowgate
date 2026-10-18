# Create a rule from Activity

## Process-instance extension (deployed on host monitor 60d35a3)

Primary capability `process-instance-rules-v1` adds explicit process targets with
pinned native/session identity, process-tier precedence and inactive lifecycle
metadata. Application rules remain unchanged. See [PROCESS-RULES.md](PROCESS-RULES.md)
for schema3 preview/save/edit/delete, inventory, authorization and exact limitations.
Earlier application-only scope/precedence descriptions below refer to legacy rules.


**Rollout update:** the integrated root monitor now exposes this capability after
the explicitly authorized restart. See [INTEGRATION.md](INTEGRATION.md) for current
generation/launch/Stop and host preview-only evidence. Earlier no-restart statements
below record the original implementation increment, not the current daemon state.


Primary Unix API v1 capability: **`observed-rule-create-v1`**. This is separate
from `policy-explanations-v1`: its row/application associations have no creation
authority. No new socket, storage schema or policy engine is introduced.
The existing `can_manage_rules` permission is required; `can_decide` is independent.
A non-enforcing root monitor can store rules without deciding any traffic.

## Select, review, save

Select an actual Activity socket with exactly one visible native process holder.
Send its backend `row_id` and `process_id` (`PID:start_ticks`), not an application
key, name, executable path, revision or UID. The latter fields cannot establish
identity through this operation. Direction is chosen explicitly, never inferred
from the Activity socket or upload/download byte flow. The socket supplies a
process-selection context; a rule can address another supported protocol/service.

```json
{"version":1,"operation":"observed-rule-preview","generation":"<listed-generation>","observed_target":{"row_id":"<selected-row-id>","process_id":"<selected-PID:start>"},"observed_draft":{"direction":"incoming","protocol":"tcp","action":"allow","remote_address":"192.0.2.2","local_port":8080,"remote_port":0,"disabled":false,"expires":"0001-01-01T00:00:00Z"}}
```

`observed_preview` contains:

- `token`: random, bound to authenticated UID/administrator role, generation,
  verified live process/namespace/executable, and the exact reviewed draft.
- `expires_at`: 30 seconds after verification. Saving requires timely revalidation.
- `rule`: backend-allocated ID, version1, created timestamp, schema2, priority100,
  verified executable/key/revision/UID, action, enabled state, scope and expiry.
- `application`: verified readable native executable metadata; `pid`, `process_id`
  and `principal_uid` describe the verified process, not a PID-based permission.
- `scope_preview`: authoritative sentence, including overlaps using the existing
  editor checks and the TCP initiation limitation.
- `enforcement`: freshly sampled direction coverage. Stored Block in monitoring
  mode is inactive (`state:stopped, covered:false`), not proof of network effects.

Every scope is explicit:

- `direction`: incoming or outgoing; `protocol`: tcp or udp; `action`: allow/block.
- `remote_address`: IP, CIDR, or explicit `*` for any address, using existing schema2.
- `local_port`, `remote_port`: explicit numbers; **0 deliberately means any**.
  Missing/null ports reject, rather than becoming a broad permission.
- Incoming service-oriented choice: local listening port, chosen remote address,
  remote port0. Do not copy an ephemeral incoming source port as a default.
- Outgoing destination-oriented choice: chosen remote address/service port,
  local port0. Never infer initiation direction from the observed endpoints.
- Protocol-wide rule: explicit remote `*` and both ports0. It is broad only for
  the selected protocol, application/revision/UID and direction. There is no
  all-protocol shortcut: TCP and UDP are separate rules.
- `expires` must be present as a timestamp. Explicit year1 zero means persistent;
  a timed rule uses a future absolute timestamp (including an explicitly chosen
  one-hour expiry), at most365 days. It is never renewed by saving/restarting.
- `disabled` defaults false; true creates a disabled stored rule. No Once option:
  creation does not concern one particular connection. Priority remains100; this
  API adds no priority editor or new precedence. Identical canonical scopes reject
  even if actions differ: edit the existing rule instead.

Send exactly the reviewed draft and token:

```json
{"version":1,"operation":"observed-rule-save","generation":"<same-generation>","preview_token":"<observed_preview.token>","observed_draft":{"direction":"incoming","protocol":"tcp","action":"allow","remote_address":"192.0.2.2","local_port":8080,"remote_port":0,"disabled":false,"expires":"0001-01-01T00:00:00Z"}}
```

Success returns existing `saved_rule` and `scope_preview` fields. The rule ID and
version match the preview. Backend IDs are never supplied as creation authority.
Changing even one reviewed draft field requires a new preview. Inputs are parsed
into typed values before binding (equivalent wire whitespace/key order is fine).
Saving reruns existing rule validation/duplicate/overlap checks and rejects changed
overlap descriptions with `policy_conflict`. SaveRules/SQLite transaction finishes
under the existing engine mutex before the new rule is published. A failed commit
keeps prior stored/effective policy and preview unchanged.

**Creation never calls Decide, releases retained packets, consumes Once grants,
changes pending states or activates enforcement.** New initiations use the stored
policy through the existing evaluator. Existing pending attempts still need a
decision or retry; established approved TCP continues. Existing edit/pending-create,
conditional Delete, generation and exact numeric mutation-version contracts remain.

## Identity and authorization limits

The initial Activity reference is required but insufficient. Both preview and
unsaved save run a fresh bounded `ActivityCollector` census plus `Inspect`, reusing
PID/start, executable revision, descriptor recheck and socket cookie/namespace
checks. The target must remain one visible native holder of the same kernel socket
and retain its verified executable/key/revision/UID. Net and mount namespaces must
match the daemon; there is no namespace traversal. Shared (even same-application),
unknown, display-only, detached, runtime/Wine/Proton and unsupported targets reject.
A process that exits/closes the selected socket before save must refresh/reselect;
short-lived verified identity is not pinned across process exit.

The result creates an executable permission, **not exclusive socket ownership**.
Census/inspection and the later SQLite commit are not atomic with arbitrary exec,
exit, credential changes or descriptor transfer. As with existing attribution,
ordinary native processes are supported, not proof against hostile same-user
races. Partial process visibility cannot exclude unseen descriptor holders; it is
not upgraded to a claim of exclusive ownership. Any known shared/changed/unknown
selected row rejects. The rule engine independently revalidates actual traffic
ownership; this creation token cannot authorize a socket or packet.

Ordinary peers can target only their UID. An explicitly root-configured
administrator can target supported service UIDs without rewriting the rule's UID.
An interpreter is identified as its actual executable, not a particular script;
its permission may cover other processes using that same executable/revision/UID.
Administrator permission comes only from daemon configuration/SO_PEERCRED, never
request fields. Companion/read-only endpoints reject both calls without new
metadata exposure; capability is advertised only on the primary endpoint. Basic
observation remains unprivileged; a missing/denied verifier returns uncertainty.

## Errors, retry and reconciliation

| `error_code` | Meaning / client action |
| --- | --- |
| generation_conflict | Missing/changed generation; reload, never replay into a new session. |
| read_only | No rule-management permission on this endpoint; remain non-editing. |
| forbidden | Outside authorized UID scope; no foreign identity returned. |
| unavailable | Durable storage or Activity unavailable. |
| unsupported_target | Selected row is not a supported unique native context. |
| stale_target | Process/socket/executable/namespace changed, inaccessible, or stale Activity; refresh/reselect. |
| invalid_request | Missing/invalid explicit fields or token. |
| invalid_rule | Invalid scope/expiry, or canonical duplicate; inspect existing rules. |
| preview_expired | Missing, expired, or wrong-principal token; reconcile before creating again. |
| preview_mismatch | Exact draft changed; review a fresh preview. |
| policy_conflict | Save-time duplicate/overlap/validation changed; review current policy. |
| limit_exceeded |256 rules,256 total previews/receipts or16 per peer; wait/manage existing rules. |
| persistence_failed | Transaction failed; old policy retained; no success acknowledgement. |
| replay_conflict | Prior successful token's rule has changed/disappeared; inspect, do not recreate automatically. |

A lost response is an **ambiguous outcome**. Do not generate another preview/save.
Use existing authenticated `list`, with the same generation, to find the reserved
`observed_preview.rule.id` and compare its authoritative fields/version. A known
successful token retains a receipt for5 minutes; explicit same-token/same-draft
retry returns the original acknowledgement with `replayed:true`, without new
persistence, identity collection or side effects, only if the stored rule is still
that version. Concurrent saves serialize into one commit plus one replay. Unchanged
receipt replay is an acknowledgement of an earlier creation, not fresh live identity
proof. Deletion/edit produces replay_conflict. No automatic client retry is advised.
After restart or receipt expiry use list/ID reconciliation; absence under a new
session cannot prove an earlier request failed. There is no durable replay ledger.
Preview storage is bounded, expired entries reclaimed on requests, no external
commands or new process per request. The bounded census runs outside the packet/
policy mutex and uses no continuous cache or packet accounting changes.

## Reproduce and rollout

```
scripts/check-observed-rule.sh
```

Build output **`.workspace/flowgate-creation`** exposes this capability, preserving
the running monitor's `.workspace/flowgate` executable. Focused race/vet and actual
UID1000 native UDP/Unix API/SQLite tests cover preview/save, shared inherited FD,
closure, scope/direction, changed draft/identity/generation/expiry, authorization,
read-only denial, persistence failure/restart, concurrent replay and policy-view.
Deterministic verifier seams exercise PID/revision/UID/namespace/error cases;
these are lifecycle/error tests, not claims of adversarial kernel race immunity.
Administrator service-principal unit coverage uses trusted server-side role input;
real receiver fixture below uses the namespace root peer and actual native identity.

One actual isolated host-mode NFQUEUE receiver scenario creates Allow **before any
pending event**, receives one-shot UDP from two new source ports, edits Block and
verifies no delivery, with another service returning Ask. It runs through the
existing two-endpoint disposable namespace harness. Only this representative IPv4
path was rerun; broader existing IPv4/IPv6/firewall/accounting/UI evidence is reused.
Evidence: `.workspace/observed-rule-verification.log`, `observed-tests.log`,
`observed-rule-receiver-*/observed-rule-receiver-api.json`. The following actual
unprivileged fixture captures are backend/API evidence, not live-host enforcement:
`.workspace/observed-rule-preview-example.json`, `observed-rule-save-example.json`.

The root monitor PID1973082/generation5a559274aa006090cdc4bb5cd8faed47 remains on
its old API and is not restarted here. Exposing the new API there requires a later
deliberate authorized restart. No host enforcement, BPF, networking or frontend
integration is performed by this increment.

## Actual native fixture excerpts

```json
{
  "request": {
    "observed_target": {
      "row_id": "net:[4026531833]:2:udp:7695769:4e09000000000000",
      "process_id": "2083063:13691720"
    },
    "observed_draft": {
      "direction": "incoming",
      "protocol": "udp",
      "action": "block",
      "remote_address": "127.0.0.2",
      "local_port": 0,
      "remote_port": 0,
      "disabled": false,
      "expires": "0001-01-01T00:00:00Z"
    },
    "generation": "eb1652284049e8679388d87ec39f8623",
    "version": 1,
    "operation": "observed-rule-preview"
  },
  "response": {
    "generation": "eb1652284049e8679388d87ec39f8623",
    "peer_uid": 1000,
    "observed_preview": {
      "token": "f6c88c1bade00d3947f10c31488b31ea",
      "expires_at": "2026-10-17T22:03:29.625635717+02:00",
      "rule": {
        "version": 1,
        "executable": "/home/flowgate-user/Apps/flowgate/.workspace/tmp/go-build515395904/b001/daemon.test",
        "created": "2026-10-17T22:02:59.625635717+02:00",
        "disabled": false,
        "schema": 2,
        "id": "user:47ebc61e154ad0a96827dc7a5012afac",
        "priority": 100,
        "filter": {
          "application": "ea9a9f92f7cd525771eb24f1aff9346e84a729d72cab90f387b2a85b3ab64fc7",
          "revision": "51:27793523:9201432:1792267378248361642:1792267378248361642",
          "direction": "incoming",
          "protocol": "udp",
          "remote_address": "127.0.0.2",
          "uid": 1000
        },
        "action": "block",
        "expires": "0001-01-01T00:00:00Z"
      },
      "application": {
        "key": "ea9a9f92f7cd525771eb24f1aff9346e84a729d72cab90f387b2a85b3ab64fc7",
        "name": "daemon.test",
        "kind": "native",
        "executable": "/home/flowgate-user/Apps/flowgate/.workspace/tmp/go-build515395904/b001/daemon.test",
        "revision": "51:27793523:9201432:1792267378248361642:1792267378248361642",
        "evidence": [
          "proc exe; PID plus start time"
        ]
      },
      "process_id": "2083063:13691720",
      "pid": 2083063,
      "principal_uid": 1000,
      "scope_preview": "BLOCK incoming udp for application ea9a9f92f7cd525771eb24f1aff9346e84a729d72cab90f387b2a85b3ab64fc7, revision 51:27793523:9201432:1792267378248361642:1792267378248361642, UID 1000; remote 127.0.0.2, local port any, remote port any; any local address/interface; until disabled/deleted (enabled). Priority 100; highest priority wins, then smallest rule ID. Approved TCP connections continue. Stored rule only; creation does not approve pending packets or change existing connections.",
      "enforcement": {
        "state": "stopped",
        "covered": false,
        "reason": "Observation/stored policy only; no application enforcement"
      }
    }
  }
}
```

```json
{
  "request": {
    "observed_draft": {
      "direction": "incoming",
      "protocol": "udp",
      "action": "block",
      "remote_address": "127.0.0.2",
      "local_port": 0,
      "remote_port": 0,
      "disabled": false,
      "expires": "0001-01-01T00:00:00Z"
    },
    "preview_token": "f6c88c1bade00d3947f10c31488b31ea",
    "generation": "eb1652284049e8679388d87ec39f8623",
    "version": 1,
    "operation": "observed-rule-save"
  },
  "response": {
    "generation": "eb1652284049e8679388d87ec39f8623",
    "peer_uid": 1000,
    "saved_rule": {
      "version": 1,
      "executable": "/home/flowgate-user/Apps/flowgate/.workspace/tmp/go-build515395904/b001/daemon.test",
      "created": "2026-10-17T22:02:59.625635717+02:00",
      "disabled": false,
      "schema": 2,
      "id": "user:47ebc61e154ad0a96827dc7a5012afac",
      "priority": 100,
      "filter": {
        "application": "ea9a9f92f7cd525771eb24f1aff9346e84a729d72cab90f387b2a85b3ab64fc7",
        "revision": "51:27793523:9201432:1792267378248361642:1792267378248361642",
        "direction": "incoming",
        "protocol": "udp",
        "remote_address": "127.0.0.2",
        "uid": 1000
      },
      "action": "block",
      "expires": "0001-01-01T00:00:00Z"
    },
    "scope_preview": "BLOCK incoming udp for application ea9a9f92f7cd525771eb24f1aff9346e84a729d72cab90f387b2a85b3ab64fc7, revision 51:27793523:9201432:1792267378248361642:1792267378248361642, UID 1000; remote 127.0.0.2, local port any, remote port any; any local address/interface; until disabled/deleted (enabled). Priority 100; highest priority wins, then smallest rule ID. Approved TCP connections continue. Stored rule only; creation does not approve pending packets or change existing connections."
  }
}
```


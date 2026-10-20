# Activity policy summaries and current-policy explanations

## Process-instance extension (not deployed)

Primary capability `process-instance-rules-v1` adds explicit process targets with
pinned native/session identity, process-tier precedence and inactive lifecycle
metadata. Application rules remain unchanged. See [PROCESS-RULES.md](PROCESS-RULES.md)
for schema3 preview/save/edit/delete, inventory, authorization and exact limitations.
Earlier application-only scope/precedence descriptions below refer to legacy rules.


**Rollout update:** the integrated root monitor now exposes this capability after
the explicitly authorized restart. See [INTEGRATION.md](INTEGRATION.md) for current
generation/launch/Stop and host preview-only evidence. Earlier no-restart statements
below record the original implementation increment, not the current daemon state.


Additive Unix API v1 capability: **`policy-explanations-v1`**, advertised on the
primary policy endpoint only. No new socket, rule schema, storage migration or
policy precedence. Companion/observer requests return `primary_required`; their
existing metadata exposure is unchanged. Ordinary peers see only their UID's
policy/associations; an explicitly authorized administrator sees machine scope.
Read permission is separate from can_manage_rules/can_decide.

## Requests

```json
{"version":1,"operation":"policy-view","generation":"<generation from list>"}
```

Response `policy_view` is one bounded batch, not a per-row query:

- `snapshot`: generation, opaque policy `token`, exact decimal-string `sequence`,
  `evaluated_at`, optional `valid_until` (next visible rule expiry), `meaning`.
- `activity_sequence` (decimal string), `activity_collected`, `activity_available`,
  `complete`, optional `reason`; Activity and policy have separate collection times.
- `applications[]`: `ref`, `identity:{key,revision,uid}`, `process_ids`, `incoming`
  and `outgoing` summaries. Match exact backend identity, never name/icon/PID alone.
- `rows[]`: stable `row_id`, `status` observed_native/unavailable, `reason`, optional
  `application_ref`, and **`decision_authority:false`**.

Only a supported native process with one visible holder and validated process
start time supplies an observation association. Shared sockets, unknown/inaccessible
owners, runtime identities and display-only groups remain unavailable here.
This does not weaken Resolve or turn a snapshot into exclusive ownership proof.
The method creates no application permission target or rule-creation token.
Processes sharing a logical identity can share one summary; socket rows/traffic
are not copied or counted by this API. Stale Activity (>45 seconds), collection
errors and limits produce explicit unavailable/partial results, never invented
identity. The backend reuses the existing snapshot; no proc scan is requested.

Each direction includes `configured`, optional `action`, `reason`, `rules`,
active/disabled/expired counts, `potential_overlapping_actions`,
`configured_default`, `runtime_default`, and `enforcement`:

| configured | Meaning |
| --- | --- |
| absent | No stored rule for the exact application/revision/UID/direction. |
| inactive_only | Rules exist, but all are disabled and/or expired. |
| scoped | Active rules require protocol/endpoint constraints; no whole-app action. |
| mixed | Different active configured actions; disjoint scopes need not conflict. |
| uniform | All active actions agree and unrestricted rules cover both TCP and UDP. |

`action` exists only for the conservative uniform proof. This is a configured
result, never actual admission. A single TCP-wide rule is still protocol-scoped.
IPv4-only CIDRs are not universal addresses. Disabled/expired counts can overlap.
`potential_overlapping_actions` reuses the editor's conservative overlap analysis;
it is not proof of a conflicting verdict. Summary refs are ID-sorted.

Rule refs contain `id`, **string `version`**, `action`, existing `priority`, actual
Filter as `scope`, `disabled`, `expired`, `active`, and absolute `expires`. Year1
zero expiry means persistent. Empty/zero filter fields retain existing matching
semantics, including legacy exact `remote`; the raw scope is not rewritten.
No new filters, priorities or action choices are introduced.

Defaults are read from the actual evaluator for supported rule-free contexts;
no missing inventory entry is translated into an application-wide Ask.
`configured_default:{known,action?,reason}` describes that pure engine default.
`runtime_default` stays unknown in monitoring/degraded/unavailable modes. Under
active incoming-only control, outgoing coverage is `bypassed` and its profile
permits new outgoing traffic (`allow`) irrespective of stored outgoing rules.
Under an active covered direction the fallback is the engine default.
`enforcement:{state,covered,reason}` describes sampled direction/profile health,
not universal traffic coverage or proof of delivery. Stopped monitoring can have
an active (enabled/unexpired) stored Block and **covered=false**.

Directions always mean **connection initiation**. Upload/download byte flow and
VPN transport accounting are independent; this API changes no accounting policy.

## Separate concrete-context request

```json
{"version":1,"operation":"policy-explain","generation":"<generation>","expected_policy_token":"<optional last token>","event_ids":["<authorized current-session event ID>"]}
```

Response `policy_explanations` contains `snapshot` and `contexts[]`. Each available
context has `status:evaluated`, recorded `flow`/identity, `configured_action`,
`selected_rule`, ordered `matching_rules` (with exact versions/scopes), `reason`,
coverage/runtime default and **`historical_decision:false`**.

This directly calls the existing `policy.Evaluate`: same active-rule matching,
highest numeric priority then smallest rule ID, unsafe-attribution Block and
rule-free Ask. It does not resolve ownership again, invoke Observe/RetainedState,
expire pending events, consume packets, evaluate cached Once grants, or publish
rules. It evaluates **current stored policy for recorded identity/endpoints**.
An already-approved TCP connection may continue even when this result is Block;
a Once-approved connection may have current stored-policy result Ask. Original
historical rule versions cannot be reconstructed from current policy.

Missing and unauthorized event IDs return the same unavailable result with no
flow/identity/rules. Existing socket origin is Unknown: no ports-to-direction
inference or arbitrary caller-supplied identity/context is accepted. A later log
can reuse this explanation model, but must separately record actual decision-time
outcomes/versions. No history/statistics database is implemented here.

## Snapshot and client ordering

- Generation is mandatory. Old/missing generation: `generation_conflict`.
- Policy and eligible event contexts are copied/evaluated under the existing rule
  mutex; persistent commits publish before they can appear in a summary. No
  mutation API or verdict logic was changed. Health sampling for metadata requests
  is serialized in response order without holding the rule/queue mutex during
  its external inspection; it is not a kernel-wide transactional attestation.
- Optional `expected_policy_token` rejects changed authorized policy, expiry
  state, profile or observed health with `policy_conflict`. Tokens hash only
  authorized metadata; foreign-rule edits cannot leak through ordinary tokens.
- `sequence` orders metadata reads within one generation, not policy commits.
  Parse it as BigInt/decimal, never a JS Number. Keep the newest accepted sequence;
  reject older-generation/older-sequence responses. Clear/invalidate in-flight
  requests after mutation ACK, reconnect, conflict, selection/identity change or
  expiry. A token is not a lease or substitute for conditional mutation versions.
- `valid_until` is the earliest visible future expiry, including disabled rules
  whose displayed expired flag will change. Refresh at that boundary; a following
  request classifies expiry without mutating policy. No persistent cache exists.
- Join the returned Activity association by generation, observation sequence/time,
  stable row ID and exact app/revision/UID. Invalidate reassociated/closed rows;
  never attach an older identity summary to a reused endpoint/PID.
- Rule-version strings preserve full uint64. Existing mutation `expected_version`
  remains an exact JSON integer. Electron must retain its refusal for unsafe
  numeric versions unless it implements an exact integer serializer; never round.

Limits: 2048 rows/256 apps; existing 256-rule policy bound; 256KiB authorized policy
metadata; 2MiB serialized result; 1..8 distinct event IDs of1..128 bytes per explain.
Limits produce partial associations or `limit_exceeded` as appropriate, not guessed
values. Duplicate/invalid context lists: `invalid_request`. Capability absence
requires clearly labelled fallback/unavailability, not fabricated backend results.

## Verification and rollout

`scripts/checks/check-policy-view.sh` runs focused race/vet and a real UID1000 authenticated
Unix API with native UDP Activity/SQLite rules. It writes real response captures
under `.workspace/policy-api-example.json` and `policy-explanation-api-example.json`.
The rule and recorded event are seeded test data; no intercepted decision or real
receiver verdict is claimed by that fixture. Full uint64 versions are deliberate
boundary fixtures. Other focused cases cover summary classes, both directions,
incoming-only bypass, privacy/admin visibility, unsupported/shared associations,
precedence agreement, no pending/cache mutation, concurrent edits, expiry, stale
policy/generation tokens, failed persistence and read-only companion denial.
No evaluator/verdict path was refactored; settled receiver/coexistence/accounting/
frontend evidence is reused instead of repeating those suites.

The new build is **`.workspace/flowgate-policy`**, leaving the running monitor's
executable path untouched. PID1973082 / generation5a559274aa006090cdc4bb5cd8faed47
is still running the old API. It must eventually be deliberately stopped and
restarted with the new code to expose this capability; **no restart was performed**.
No frontend files/branches were edited/integrated. First-rule creation from an
observed app now uses the separate `observed-rule-create-v1` workflow described
in [OBSERVED-RULES.md](OBSERVED-RULES.md). These read associations still confer
no rule-creation authority.

## Captured API examples (field excerpts, fixture session only)

Actual UID1000 Unix peer, native socket association and SQLite-backed scoped Block.
Other response fields are omitted here; this is not host firewall evidence.

```json
{
  "generation": "7326ef7915637722b601eed31896cbde",
  "policy_view": {
    "snapshot": {
      "generation": "7326ef7915637722b601eed31896cbde",
      "token": "8aa48ea9de9b53dc77b4ff8f2745042e00724804be912885f2241b662fcd1458",
      "sequence": "1",
      "evaluated_at": "2026-10-17T21:51:50.728776573+02:00",
      "meaning": "Current configured policy; not historical Allow/Block, continuous ownership authority or proof of delivery"
    },
    "applications": [
      {
        "ref": "a313cfce9178c4988f1ca46834bf30f50dac5c4484d6a946a1a68c725b7c227e",
        "identity": {
          "key": "9965b91b11399c5a18cd98e882c38f3a983844aad92f365305c17ff657012685",
          "revision": "51:27787660:8934648:1792266710266676896:1792266710266676896",
          "uid": 1000
        },
        "incoming": {
          "configured": "scoped",
          "rules": [
            {
              "id": "fixture-scoped",
              "version": "18446744073709551615",
              "action": "block",
              "priority": 100,
              "scope": {
                "application": "9965b91b11399c5a18cd98e882c38f3a983844aad92f365305c17ff657012685",
                "revision": "51:27787660:8934648:1792266710266676896:1792266710266676896",
                "direction": "incoming",
                "protocol": "udp",
                "remote_address": "127.0.0.2",
                "local_port": 34398,
                "uid": 1000
              },
              "disabled": false,
              "expired": false,
              "active": true,
              "expires": "0001-01-01T00:00:00Z"
            }
          ],
          "enforcement": {
            "state": "stopped",
            "covered": false,
            "reason": "Observation/stored policy only; no application enforcement"
          }
        },
        "outgoing": {
          "configured": "absent",
          "enforcement": {
            "state": "stopped",
            "covered": false,
            "reason": "Observation/stored policy only; no application enforcement"
          }
        }
      }
    ]
  }
}
```

Recorded-fixture-context explanation from that session, not a packet decision:

```json
{
  "event_id": "1442d872e96c6af4bfb839b2fd5c2071",
  "configured_action": "block",
  "selected_rule": "fixture-scoped",
  "historical_decision": false,
  "enforcement": {
    "state": "stopped",
    "covered": false,
    "reason": "Observation/stored policy only; no application enforcement"
  }
}
```

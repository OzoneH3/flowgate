# Replacement lab API map

Use the installed daemon’s authenticated primary Unix socket. Send one newline-terminated JSON v1 request per connection. Start with `list` and retain its `generation`, `permissions`, `capabilities`, and `network_zones.revision`. Use the ordinary probe account for its rules and requests. Use an authorized administrator for machine settings such as shaping. Test write refusal on the read-only companion separately.

The map follows the existing lab’s rule, desktop permission, pending/log, and traffic-limit workflows. Run real probes and receiver counters alongside the API. For an expected Block, also prove that an uncapped or otherwise unrestricted control can reach the receiver.

| Existing workflow | API setup and assertions |
| --- | --- |
| Add rule from Activity, for an application or process | `list` → `observed-rule-preview` with the Activity row/process IDs → `observed-rule-save` with the same draft and preview token. Assert `saved_rule` ID/version in a new `list`. Choose Allow, Block, or Ask with the same draft validation as the GUI. Set `application_policy:true` for the unrestricted application-policy selector. |
| Add future rule from a request or from a saved application | `request-rule-preview/save` with `id` of the event, `observed_draft` and preview token. This is a future rule and does not answer the old request. For the saved-application basis path use `rule-preview/save` with `basis_rule_id` and the draft `rule`. |
| List, edit action/scope/priority/expiry, enable and disable | `list` returns `rules` and `rule_states`. Send the full edited rule to `rule-preview` then `rule-save`, with the original `id` and `expected_version`. Include current `zone_revision` for zone edits. `rule` with `action:enable/disable` returns the updated `saved_rule`. Check the new version and scope in `list`. Probe a matching and a nonmatching connection. |
| Conditional Delete, stale edit, read-only denial | `rule-delete` returns `deleted_rule` with the removed ID/version. Use the reviewed generation/version for every edit, toggle and delete. Require refusal on stale tokens or the companion socket and verify inventory and subsequent decisions. |
| Delete all application rules | Select the displayed application/UID’s current rule versions from `list` and submit them together via `application-rule-delete`. Assert `deleted_rules`, then compare inventories. Both directions are eligible. Process rules, rules for other apps/accounts, global or shared-root policies, presets, network-endpoint rules, and shaping settings are outside this scope. |
| Stored Ask, Allow Once, Deny Once | Create Ask through the existing editor API. `list.events` exposes the held attempt and `ask_rule.id/version` for a stored Ask. Answer its exact `id` through `decide` with `scope:once` and `action:allow/block`. Check the linked final record, receiver, and a fresh attempt that asks again. |
| For a while, timed rule, scoped Allow/Deny Always | Use `decide` with `scope:for-a-while` and a duration from `for_a_while_durations` for a process lease. Read `list.process_leases`. `request-for-a-while` supports eligible ended requests and leaves the old request ended. For a Remember rule use `decision-preview` then `decide` with its token and the same fields. Use `scope:application` with `duration_seconds` for timed Remember or `scope:persistent` for Always. Check `saved_rule`, expiry, and fresh attempts after the decision, after expiration, or after restart as appropriate. |
| Activity → Pending → Decision Log, current policy | Match the live event in `list`. Read `decision-log`, `decision-log-get`, and `decision-log-outcome` for recorded decisions. `policy-view` summarizes current configured policy; `policy-explain` evaluates an authorized recorded event context against current policy. Neither substitutes for the recorded verdict. |
| Zone and endpoint rules, local pairs, established TCP | Use `zone-rule-preview/save` or `endpoint-rule-preview/save` for their respective targets. For a verified local pair use `decide-pair` with both pending event IDs. To test [established TCP control](ESTABLISHED-TCP-CONTROL.md), save or enable a winning Block and compare the original sockets and receivers with unaffected controls. |
| Application upload/download limits and priority | Read `upload-status`, then `upload-configure` with generation, shaping config version and the current desired config. Schema 4 `stored_edit` changes one UID/application/scope, with upload `bits_per_second`, `download_bits_per_second`, and `traffic_priority`. A zero-rate entry with no priority removes that saved setting. Compare `configured_caps`, worker/applied version, receiver rates, uncapped overlap, post-removal recovery, and cleanup. |
| Protection/evaluation transitions and UDP collector lifecycle | Use the existing [protection and evaluation APIs](DAEMON-EVALUATION.md) and [traffic APIs](DAEMON-UDP.md). Verify authorization, terminal states and actual delivery where applicable. Installer, distro and kernel lifecycle operations still belong to the test harness. |

## Requests and results

Example fields below use illustrative IDs. Keep numeric mutation versions exact, including explicit `0` for a legacy rule whose version is absent. Decision Log versions are decimal **strings**.

**Create.** Review the returned scope and the candidate before saving. The same save draft can be reused with the token and a new mutation ID.

```json
{"version":1,"operation":"observed-rule-preview","generation":"GEN","observed_target":{"row_id":"ROW","process_id":"324:12712"},"observed_draft":{"target_scope":"application","application_policy":true,"direction":"outgoing","protocol":"*","action":"ask","remote_address":"*","local_port":0,"remote_port":0,"expires":"0001-01-01T00:00:00Z"}}
```

From the preview read `observed_preview.token` and `observed_preview.rule`. From the save read `saved_rule.id`, `saved_rule.version`, `saved_rule.filter`, and `scope_preview`.

**Bulk delete.** Requires `application-rule-delete-v1`. Submit the complete reviewed selection, up to 256 rules. A missing, stale or invalid target aborts the complete transaction. A concurrent rule added outside the selection remains.

```json
{"version":1,"operation":"application-rule-delete","generation":"GEN","mutation_id":"8b5d944af4ad41989030b7f2e6dc9c10","application_rule_delete":{"application":"APP_KEY","uid":1000,"rules":[{"id":"IN_RULE","version":2},{"id":"OUT_RULE","version":3}]}}
```

```json
{"version":1,"generation":"GEN","deleted_rules":[{"id":"IN_RULE","version":2},{"id":"OUT_RULE","version":3}]}
```

**Remember.** Use these fields with `decision-preview`, then send them unchanged to `decide` with the returned `decision_preview.token` as `preview_token`. This example remembers only the address. With `scope:application`, specify 60–31536000 seconds for timed Remember. A process Remember rule is session-bound and requires a verified process.

```json
{"version":1,"operation":"decision-preview","generation":"GEN","id":"REQUEST","action":"allow","scope":"persistent","network_zone":"any","zone_revision":"ZONE_REV","remember":{"address":true,"port":false,"protocol":false,"process":false}}
```

**Correlate a real connection.** Bind the probe to a distinct source port, record both endpoints, direction, protocol and attempt time, and verify the owner against the probe’s UID/process/application. For an Ask, record `events[].id` as the request ID and retain the pending log record’s ID. Use `decision-log-outcome` with that record ID to find the final linked outcome. Direct rule decisions may have no pending request. The connection filters require `decision-log-connection-filter-v1`.

```json
{"version":1,"operation":"decision-log","decision_query":{"generation":"GEN","protocol":"tcp","direction":"outgoing","local":"192.0.2.10:46157","remote":"192.0.2.20:8080","request_id":"REQUEST","since":"2026-11-25T20:00:00Z","limit":20}}
```

The page exposes each record’s `id`, `sequence`, `time`, `generation`, `kind`, `request_id` when present, `flow`, `principal_uid` and available `application.key/revision`. Assert `decision.action/source/scope` and, when a rule won, `decision.rule.id/version`. Optional exact filters include `application`, `rule_id` and `rule_version` (requires `rule_id`). For follow-up paging carry `health.log_id` and the returned sequence cursor. A matching tuple alone is insufficient across retries. Use a new source port per attempt, narrow time bounds, and the request/log ID once known.

**Reconcile a lost mutation reply.** Require `mutation-receipts-v1`. Give each logical write a fresh 128-bit lowercase hexadecimal `mutation_id` and retain the exact request and daemon generation. Receipts cover rule saves/toggles/deletes, zone, endpoint and migration saves, pending decisions and shaping configuration. Preview remains read-only.

```json
{"version":1,"operation":"mutation-status","generation":"GEN","mutation_id":"8b5d944af4ad41989030b7f2e6dc9c10"}
```

```json
{"version":1,"generation":"GEN","mutation_receipt":{"id":"8b5d944af4ad41989030b7f2e6dc9c10","operation":"application-rule-delete","state":"completed","result":{"deleted_rules":[{"id":"IN_RULE","version":2},{"id":"OUT_RULE","version":3}]}}}
```

For `completed`, inspect `result.error/error_code` or assert the operation-specific success fields. Poll a `pending` receipt. On `not_found` in the same generation, retry only the identical request with the same ID. A concurrent arrival shares the reservation. Identical replays return the receipt with `replayed:true`; another body yields `mutation_conflict`. A receipt may precede refreshed inventory, so confirm the final state with another read.

## Coverage boundaries

- Receiver delivery, achieved throughput, kernel queue restoration, install/rollback and graphical behavior require the harness or GUI inventory test. The daemon exposes its decisions and controller state. It has no receiver oracle, and bypassed or unevaluated traffic may have no Decision Log row.
- Receipts are principal- and generation-bound, with a 1024-operation and 8 MiB budget for the whole daemon generation. A capacity refusal prevents execution; an `unavailable` receipt means the request cannot be replayed and its result must be checked in authoritative state. After restart the old write is refused by its generation guard. Use rules, log and controller inventory to reconcile evidence that survives. Exact attribution of an arbitrary pre-restart write would require a durable receipt committed with that write.
- Creating an app rule for a never-observed executable has no verified target through this API. The lab can start an anchor socket to obtain Activity identity before the first test connection, or use a saved basis. Shared or unverified runtime labels do not authorize a rule or an active shaping binding.

# Configured Local Network / Internet policy (`network-zone-policy-v1`)

Implemented, not deployed. This extends policy, not traffic accounting or routing.
[NetLimiter zones](https://www.netlimiter.com/docs/basic-concepts/zones) are named
filters; its [rules](https://netlimiter.com/docs/basic-concepts/rules) independently
choose a target, zone and initiation direction. The inspected installed UI has those
separate choices. Its documentation does not specify a portable Linux classifier.
FlowGate therefore states its own model instead of claiming Windows equivalence.

## Model and configuration

`configured-prefix-v1` uses immutable root startup configuration:
repeat `serve`/`host-start`/`host-session --zone-local CIDR` and
`--zone-internet CIDR`. Local includes explicit builtins127/8,::1/128,169.254/16,
fe80/10 (loopback and unicast link-local). For other unicast peers the longest
configured matching prefix wins; identical prefixes in different zones reject.
No match means unavailable/unknown. Private routed addresses, ULA, global IPv6,
VPN/Tailscale destinations and public LAN addresses get no automatic membership.
An administrator can explicitly choose Internet /0 plus narrower Local prefixes;
that is a policy partition, not proof of Internet reachability or physical LAN.
Multicast, unspecified, listeners and unconnected UDP are unavailable.
Forwarded traffic and namespace traversal are not added. Bound interface and byte
flow never infer zone or connection initiation. Reply traffic retains existing
admission semantics, not a new per-packet zone firewall.

`network_zones` on list and policy_view contains model, SHA256 revision, canonical
local_prefixes/internet_prefixes and reason. Revision binds the canonical definition;
configuration cannot hot-change. A deliberate restart changes generation/revision,
invalidates outstanding previews and process grants; durable zone rules follow the
new root-configured definitions. Configuration is not caller-controlled IPC data.
Activity row / decision event flow `network_scope` contains state known/unavailable,
optional zone local/internet, revision, source configured-prefix-v1 and reason.
Packet evaluation uses the same classifier; unknown peers skip zone-constrained
rules and reach explicit Any-zone application/process policy or the existing default.
Unknown/unsafe identity still blocks before any all-program Allow. Activity sampling
and attribution are not instantaneous/atomic with process or socket changes.

Zone accounting is deliberately absent. A connected socket's current peer class
does not allocate its historical bytes. UDP totals span peers; unconnected/multi-peer
counters cannot be divided into zones. No Internet/Local aggregate byte claims.

## Schema4, authority and precedence

Optional filter fields: `network_zone:"local"|"internet"` (omitted=Any),
`all_programs:true`, `all_uids:true`. Schema4 is required when using them.
All-program rules require a named zone and empty application/revision/executable/
process fields: the zone is not an invented application identity. AllUIDs uses
canonical uid0 but means every supported principal, not root-only. Only an existing
root-configured administrator may create/edit/delete such machine rules;
`permissions.can_manage_machine_rules` reports this separately from can_decide.
Ordinary peers may create own-UID all-program rules (`scope:self`) only.
Read-only companions reject creation/mutation. Existing selected-user privacy remains;
machine fallback rule documents contain no foreign application identity.

Matching process tier wins over application tier, which wins over all-program zone
tier. Within each tier, higher explicit priority wins. At equal priority, a matching
Local or Internet rule overrides an All networks (Any-zone) rule, for both Allow and
Block and for incoming and outgoing traffic independently. Within the same zone
scope, Deny wins over Allow, then Ask; user rules win over presets, then smaller
rule IDs win. Unknown classifications do not match named zones and retain the
All networks fallback. This zone tie-break is an explicit FlowGate behavior change;
it is not a new NetLimiter parity claim. Application/process identity,
session lifetime, exclusive ownership and inactive-after-restart inventory remain.
Existing schema0..3 and Any-zone behavior are unchanged. Old strict readers refuse
schema4 rather than ignore zone/global fields; never delete/strip documents to downgrade.
Decision Log immutable snapshots carry actual zone classification and target_scope zone.

## API and reconciliation

Example fixture configuration Local10.79.0.0/24 / Internetfd79::/64 is intentional
controlled policy labeling, not a claim that ULA is the public Internet.

```json
{"version":1,"operation":"zone-rule-preview","generation":"<daemon>","zone_revision":"<network_zones.revision>","zone_target":{"zone":"local","scope":"machine"},"observed_draft":{"direction":"incoming","protocol":"*","action":"block","remote_address":"*","local_port":0,"remote_port":0,"disabled":false,"expires":"0001-01-01T00:00:00Z"}}
```

`zone_preview` contains token, expires_at, backend-assigned schema4 rule/ID/version1,
scope_preview, enforcement coverage and network_zones. No observed process required.
Save uses operation zone-rule-save with identical target/revision/draft and
preview_token. Preview30s, per-principal16/total256 bounded zone entries; saved receipt
5min, exact same-token retry acknowledges original rule only, never duplicates.
Lost ACK: list reserved preview.rule.id and compare full document/version/generation;
no automatic replay or new creation. Changed/deleted receipt => replay_conflict.
Storage transaction precedes publication; failures preserve old policy. Creation
clears previous decision caches/held attempts without approving retained packets.

Observed application/process drafts add network_zone and zone_revision; same live
verification/preview binding as before. Existing rule-preview/save requires top-level
zone_revision for a zone rule, exact expected_version and schema4 preservation.
Zone and machine/self principal are immutable on edit (`zone_scope_changed`): use
fresh creation review for a different zone, rather than silently broadening old-client
edits. Action/disabled/expiry/supported endpoint restrictions remain editable.
Conditional Delete unchanged. `zone_conflict` rejects changed/missing definition;
other structured errors reuse observed-rule codes. `*` explicitly supports TCP+UDP.

Policy_view adds zones[{zone,incoming,outgoing}] complete all-program inventories,
network_zones and app/process zone_fallback_rule_ids referencing those rules. Existing
app/process direction.rules retain their own exact rules across all zones. No target
inventory summary is a per-socket verdict; event policy-explain shows selected and
ordered overridden matches for its actual classified context.

## Focused evidence

Race/vet: identity, policy, daemon, decisionlog and affected command packages.
`process-rules-isolated.py --zones` actual private namespace receivers cover incoming
and outgoing TCP+UDP: configured LocalIPv4 Allow vs InternetIPv6 Block; application
and process override/sibling fallback; disable/staleDelete/delete; exact explanation
ordering; Decision Log zone snapshots and token replay. Unit tests cover unknown,
private/public/ULA/VPN-prefix behavior, unconnected sockets, global authorization,
preview mismatch/expiry, stale version and failed persistence. The first receiver
run passed policy/receiver cases but exposed missing zone fields in the custom log
projection; fixed projection and full affected case passed in zones-receiver-2.
No new host interception or BPF attachment. Existing retained identity failure is
unresolved: this classifier does not weaken resolver/fingerprint checks.

Additional focused private receiver case `--zones-unknown` passed in
`.workspace/zones-unknown-1.log`: routed private10.80.0.2 is outside configured
Local10.79/24 and Internetfd79::/64, so it does not inherit global LocalAllow.
The actual incoming event is unknown/default Ask; explicit Deny keeps the native
receiver count unchanged. SQLite schema4 reload and stale generation/zone revision
are tested separately; the restart comparison uses serialized documents because
Go's in-memory monotonic timestamp component is intentionally not persisted.

An additional policy regression proves an incomplete non-nil application (missing
key or revision) cannot gain a global Allow. It is rejected as unsafe attribution;
existing resolver and retained fingerprint checks remain. Limited IPv4 broadcast is
also unclassified. These guards do not resolve the older retained-identity failure.

## Pending Remember (`decision-zone-remember-v1`)

Additive capability; legacy Decide and existing Any rules are unchanged. No
process-only Remember or stored Ask is added. Default UI choice is visibly **Any
network**, not the displayed connection zone. Once keeps its existing request/
30-second UDP tuple lease and sends no zone or preview fields.

For one-hour (`application`) or durable (`persistent`) Remember, prepare an
action-bound preview on the authenticated primary endpoint:

```json
{"version":1,"operation":"decision-preview","generation":"<daemon>","id":"<pending-event>","action":"allow","scope":"application","network_zone":"local","zone_revision":"<network_zones.revision>"}
```

`network_zone` is explicitly `any`, `local` or `internet`. Named choices must match
the held request's **current known** classification. A mismatch/unknown named
choice returns `zone_mismatch` without saving a rule or deciding the request; no
silent substitution. Any is available for unknown classification. Preview and
commit revalidate identity/fingerprint and current classification/revision; stale
request, identity, generation or definition requires fresh review. Definitions are
immutable per daemon generation; restarting with new definitions invalidates open
previews. No second classifier or frontend inference is involved.

`decision_preview` contains `token`, `expires_at`, `generation`, `event_id`, `action`,
`scope`, `network_zone`, `zone_revision`, `connection_network` (classification),
`rule` (complete reserved ID/version1/document), `scope_preview` (authoritative prose).
Rule preserves exact application/revision/UID/protocol/peer/service and chosen
expiry. Named zone uses schema4 `filter.network_zone`; Any retains schema2. No
other match restriction broadens. Absolute expiry is frozen at preview. Current
request admission and future remembered rule are separate; existing admissions are
not terminated. Precedence remains process > application > all-program zone.

Commit `operation:"decide"` with the **same** generation/id/action/scope/network_zone/
zone_revision plus `preview_token`. Response contains `decision`, `saved_rule` and
optional `replayed`. Save transaction precedes publication; failure does not decide
or publish permission. New scope fields without token return `preview_required`.
Once/process scopes cannot be smuggled through a Remember token. Older servers may
ignore unknown fields: clients MUST gate new operations on the capability.

Preview TTL is at most30seconds and the event deadline; bounded16/principal and256
total. Two action previews per visible selection are supported, not poll-driven
renewal. Successful receipt retained5minutes, bound to exact authenticated
UID/administrator role; no durability across daemon restart. `decision-status`
with generation/preview_token on the primary returns `decision_receipt`:
`{state:pending|committed,preview,decision?,saved_rule?}`. It is a query, allowed even
after enforcement stops; observer endpoints refuse it. Committed fields are
historical snapshots, not a claim the rule remains enabled/present today.

After a lost response, query status; **pending does not prove no operation is in
flight**, and must not trigger blind replay. Exact successful-token retry can only
return its original receipt (`replayed:true`), never repeat Decide, packet handling,
rule creation or Decision Log final record. Other tokens for an already-decided
request fail. After restart/expired receipt, inspect reserved rule ID/full document
and Decision Log; never replay an old admission. Errors include generation_conflict,
zone_conflict, zone_mismatch, preview_required/missing/expired/mismatch,
identity_changed, stale_decision, forbidden, capacity and persistence_failed.
Decision Log's immutable rule snapshot carries actual `filter.network_zone`; old
Any rules are never migrated.

Focused pending-Remember evidence: `.workspace/remember-zone-receivers-2/remember-zone-evidence.json`
and owner log. `process-rules-isolated.py --remember-zones` holds application,
protocol, peer address and service constant while restarting only its disposable
daemon with swapped explicit prefix definitions. Local Allow delivers twice;
same-peer Internet classification prompts instead of inheriting it. Internet Deny
prevents matching deliveries; restoring Local permits Local Allow again. Any on a
separate service continues across membership change. A distinct executable reusing
the original exact service/peer prompts and Deny keeps its receiver0. Lost ACK
reconciles by receipt, exact retry creates one rule; old generation and mismatching
named preview refuse. Rules0 and namespace cleanup confirmed. Unit/API race checks
cover concurrent tokens/replay, expiry during resolution, fingerprint/flow/revision
changes, unknown Any vs refused named scope, read-only/foreign receipt denial,
failed persistence, legacy Any and immutable logged zone snapshots. Actual PID reuse
and unrelated BPF/accounting matrices were not repeated.

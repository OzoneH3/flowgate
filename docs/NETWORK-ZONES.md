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
tier. Within each tier preserve priority descending, ID ascending. A named zone does
not silently outrank an Any-zone rule in the same tier. Application/process identity,
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

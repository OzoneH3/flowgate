# Automatic peer zones

FlowGate uses `automatic-peer-v1` in the privileged daemon. Activity, held
requests, policy matching and zone views share its immutable network revision.
Classification grants no permission: Local is a peer scope, not a trust level.
No geographic database, DNS success, VPN process identity or connectivity probe
participates in an Allow/Deny decision.

## Membership and precedence

1. Unspecified peers and unconnected/listening sockets have unavailable scope.
2. Loopback and link-local stay Local. Link/administratively scoped IPv4
   multicast, IPv6 interface/link/realm/admin/site/organization multicast and
   limited broadcast are Local; global/reserved multicast is unavailable.
3. Explicit configured Local/Internet prefixes override automatic inference by
   longest prefix. Equal conflicting prefixes are rejected. Protected loopback
   and link-local cannot be changed into Internet. The existing custom prefix
   lists remain intact; they are not an exhaustive list of Internet addresses.
4. RFC1918, RFC6598 shared/CGNAT and IPv6 ULA peers are Local even when routed:
   this includes Tailscale 100.64/10 and fd7a:115c:a1e0::/48 and private work-VPN
   destinations. Neither their interface nor their scope implies permission.
5. A globally reachable address on an active non-tunnel interface's assigned
   prefix is Local only with an agreeing connected route. Tunnel kinds and
   point-to-point interfaces cannot establish public-address LAN membership.
   A more-specific main-table VPN/gateway route instead yields Internet.
   Conflicting alternative policy tables yield unavailable scope for a public
   LAN candidate: remote-only scope cannot guess packet marks/source routing.
6. Other globally reachable IPv4/IPv6 unicast peers are Internet, including
   public destinations routed through VPNs. No destination entry is required.
   Reserved, documentation and benchmark ranges are unavailable unless an
   explicit custom definition supplies membership. IANA's most-specific
   globally-reachable exceptions take precedence over broader special blocks.

A failed or unstable network census makes topology-dependent public scope
unavailable. Address-defined private/local scopes and explicit overrides remain
usable. Unknown scope matches neither Local nor Internet rules; existing
Any-network rules and explicit per-request decisions retain their normal roles.
Namespace mismatches cannot borrow host topology. The reason is returned with
scope, including classifier and legacy-definition revisions.

## Changes and decisions

Kernel link, address, route and policy-rule notifications trigger refreshes;
a one-second census recovers from lost notifications. Two matching complete
snapshots are required. Configuration hashes exclude traffic counters. All
consumers use the shared generation, including API Activity snapshots. New
configuration reclassifies pending requests, invalidates cached policy decisions
and stale rule previews, and retains original pending IDs and deadlines.
Remember save requires the reviewed classification revision and fresh binding.
Completed receipts remain idempotent. Already admitted TCP sockets retain their
existing admission semantics; a network change is not a claim of retroactive
connection termination. No interface/display setting or daemon lifecycle is
changed by the classifier.

## Migration

Existing schema4 zone rules continue matching `configured-prefix-v1` through
scope's separate legacy fields. Ordinary edits preserve that model. New zone
rules use schema6 with `filter.zone_model = automatic-peer-v1`. Essential's
schema5 rules and the work-VPN/Tailscale-transport exclusions are unchanged.
Classification continues to see those destinations.

`zone-migration-preview` is non-mutating and returns exact CIDR coverage before,
after, added and removed for the selected zone under the current snapshot,
plus example peer reasons. It preserves rule ID, principal, executable/process
target, action, ports and absolute expiry, incrementing only version/model.
The preview explicitly discloses future automatic network/registry changes.
`zone-migration-save` requires the preview token, generation, old version,
classification revision and existing rule-management authority. It never
extends an expiry. Read-only clients cannot migrate; machine rules require
administrator authority. A repeated completed token returns the same receipt;
a changed/deleted rule causes replay conflict. An unknown acknowledgement must
be reconciled by rule ID/version before any new preview. Coverage is bounded;
an oversized review fails rather than returning a truncated change.

## Registry updates

`internal/identity/data/iana-special.json` embeds the IANA IPv4 and IPv6 Special
Purpose Address Registries, source URLs, source SHA256, registry update dates,
retrieval date and a content version. Runtime classification performs no fetch.
Run `python3 scripts/update-address-registry.py` to fetch the maintained primary
registries with size/time limits; raw downloads stay under `.workspace/`.
Review the generated diff (especially global-reachability exceptions), run the
identity/policy/daemon tests and the isolated receiver suite, then release the
reviewed binary. A changed registry changes classification revisions and
requires fresh previews. Never update the data in a running process. A future
geolocation feature must use independent data/version/update plumbing and may
not change permission when lookup fails.

## NetLimiter reference

NetLimiter 5.3.28.0 in WinBoat exposes built-in Zone filters `LocalNetwork` and
`Internet` using distinct functions “Remote host is on Local Network” and
“Remote host is on Internet”; the editor has no geographic arguments.
The installed guest has one Ethernet network, so it cannot establish behavior
for every VPN or IPv6 topology. Do not claim those unobserved cases as exact
NetLimiter compatibility.

Primary documentation:
- https://netlimiter.com/docs/basic-concepts/zones — zones are special filters.
- https://netlimiter.com/docs/basic-concepts/networks — networks are automatically
  detected from interface ranges/gateways and routing configuration.
- https://netlimiter.com/docs/basic-concepts/filters — separate Local/Internet,
  Network and Loopback predicates.
- https://netlimiter.com/docs/internals/location-database — IP2Location LITE is
  geographic information for information/statistics/history views.
- https://netlimiter.com/docs/using-with-vpns — visibility depends on VPN driver;
  observing a VPN interface alone does not establish peer classification.
- https://www.iana.org/assignments/iana-ipv4-special-registry
- https://www.iana.org/assignments/iana-ipv6-special-registry
- https://tailscale.com/docs/concepts/tailscale-ip-addresses
- https://tailscale.com/docs/concepts/ipv6

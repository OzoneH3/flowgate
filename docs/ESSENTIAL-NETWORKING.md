# Essential system networking: reviewed permissions, never automatic protection

## Delivery and current host

Backend checkpoints45d247c/200a19e add the authoritative workflow and matching
interface DHCP guard rules. Subsequent focused acceptance/refinements are in Git
history. No host installation, rules, lease, collector, routing or firewall was
changed during this work. Read-only observation on2026-10-19 finds the FlowGate
service not installed/inactive; NetworkManager, resolved, timesyncd, tailscaled
and bpftune active. Name resolution works without FlowGate interception. The old
04c5159 artifact/data are retained; no currently running FlowGate generation is
claimed. Reinstalling and activating remain separate reviewed actions.

The previous zero-essential-policy default-deny activation was unsuitable for
normal networking. This is a lifecycle/product defect, not contradicted by the
accepted dedicated receiver matrix. Exact historic blocked packet records and the
failed UI row's PID are root-private and have not been exported. We do not invent
which systemd executable the user selected.

The concrete Activity `stale_target` class was fixed in b99db85: native services
may use a private mount namespace. Fresh target mount/PID/boot binding replaces
incorrect daemon-mount equality; PID/start/UID/live executable revision/root-netns
and exclusive socket ownership remain required. Actual private-mount application
and process preview/save/persistence/replay tests passed. The UI log proves a
failed preview before Save, not a lost Save acknowledgement; exact incident target
remains unconfirmed. See [SYSTEM-NETWORKING.md](SYSTEM-NETWORKING.md).

## Permissions proposed for this host

These are a **review proposal**, not installed permissions. The root discovery
preview binds actual running executable identities and must succeed before Apply.
No name, root-owned pathname, service UID or on-disk replacement alone grants access.

| Component | Exact offered scope | Reason and boundaries |
| --- | --- | --- |
| `/usr/lib/systemd/systemd-resolved` (service UID974 observed) | Outgoing TCP+UDP53 to172.30.42.128 and172.30.42.250 on enp7s0;100.100.100.100 andfd7a:115c:a1e0::53 on tailscale0 | Configured per-link servers, including split DNS. Exact native application/revision/UID. Any network classification, exact endpoint/interface constraint. No public fallback list while active servers exist; no DoT on this host (`dnsOverTLS:no`). |
| Clients using observed resolved stubs | Outgoing TCP+UDP53 only to observed127.0.0.53 and/or127.0.0.54 on lo; live peer must be the verified resolver executable/revision/UID | All identified programs, not invented process identity or universal loopback. Corresponding incoming resolver rule restricted to exact local stub53, lo and127/8 clients. Existing reply handling stays separate. Discovery verifies listener owner; missing/unverified listeners generate no client permissions. |
| DHCP | Reviewed active auto-addressed NM interface(s), currently enp7s0; UDP client68→server67 and replies, plus DHCPv6546→547 and link-local replies/multicast discovery if selected by the profile | Persistent interface-name protocol exception shared by guard and active hooks. Handles broadcast/pre-address paths without inventing a raw-packet owner. Not a NetworkManager application exemption. The exact proposed IPv4/IPv6 choices come from active NM profile methods. |
| `/usr/lib/systemd/systemd-timesyncd` | Outgoing UDP123 to currently selected162.159.200.123 (`time.cloudflare.com`), local source port unrestricted | Exact native application/revision/UID; no incoming NTP server. Address/pool change makes this permission inactive pending fresh review, never Any destination. |
| Optional `/usr/sbin/tailscaled` | Outgoing TCP443 Any destination; UDP3478 Any destination; UDP from configured local41641 to variable peer addresses/ports | Separate unchecked installed-service option. Explicitly broader destinations because relay/peer lists vary. Native executable/UID/revision remain exact; no exemption for inner applications, interfaces, ACLs or routes. |
| Optional Tailscale direct-connectivity / HTTP | Incoming UDP to configured41641 Any peer; outgoing TCP80 Any destination | Two separate unchecked choices, require the Tailscale option. Not essential defaults. |
| mDNS, LLMNR, connectivity check, SSH, sharing, remote desktop, printing | No permission | Some resolved links advertise mDNS/LLMNR, but no approved trusted-interface policy exists. Discovery selection reports unavailable. RFC1918 is not trust. Connectivity URI needs separate review. |

The resolver's stub and upstream legs are distinct; NSS `resolve` can use local
IPC instead of the stub. Direct application DNS/DoH remains separately controlled.
MagicDNS paths are configured DNS endpoints, not presumed tailscaled-owned client
sockets. Existing Tailscale NM/resolved wiring warnings remain independent.

## API and authorization

Capability `essential-system-networking-v1`; daemon v1 JSON protocol. Machine
administrator is required for status; primary endpoint plus `can_manage_rules`
for preview/apply/removal. An administrator companion can read status only.
No renderer supplies executable identities or destination lists.

All operations include `generation`. `essential_options` explicitly contains four
booleans: `tailscale`, `tailscale_incoming`, `tailscale_http`, `discovery` (allfalse
default). Incoming/HTTP without Tailscale is invalid. No operation starts protection.

- `essential-preview` -> `essential_preview` for operation `apply`.
- `essential-remove-preview` -> same shape for `remove`, only unchanged owned rules.
- Preview shape: `{token,expires_at,revision,operation,options,components,rules,
  preserved_rule_ids,issues}`. Component: `{id,title,state,essential,details,
  service?,revision}`; state ready/unavailable/optional.
- `essential-apply` / `essential-remove` require the **exact** preview token and
  identical `essential_options`, including removal. Apply re-reads authoritative
  configuration and identity; inventory/config changes require fresh review.
- Success `essential_receipt:{token,operation,rule_ids,rules,removed_rule_ids}`.
  Remove has empty `rule_ids`/`rules`; removed IDs equal the reviewed set.
- `essential-status` -> `essential_status:{revision,components,rule_ids,issues}`.
  With `preview_token`, also returns exact committed receipt or `receipt_unknown`.
  This is the read-only lost-acknowledgement reconciliation path; never silently
  acquire a new token and replay a mutation.

Previews30sec, receipts5min, bounded16 per UID/256 total. Rule limit256. A storage
failure is atomic: no partial in-memory success. Apply/remove require actual
enforcement stopped. They invalidate held requests conservatively, never approve
packets. Errors include forbidden, unavailable, invalid_request,
generation_conflict, preview_expired, preview_mismatch, preset_stale,
policy_conflict, limit_exceeded, receipt_unknown, replay_conflict, protection_active.
UI preserves the exact error and states that a failed preview saved nothing.

Essential discovery has a15sec budget and serialized bounded refresh, API/client
20sec only for these operations; normal polling is unchanged. Background discovery
refreshes every5sec; service permissions expire after30sec without a current
snapshot. Slow/failed discovery invalidates coverage, never publishes partial
success as fresh. This is bounded polling, not instantaneous network-change events.

## Storage, updates and removal

Rules use schema5 with original application/UID/revision/direction/protocol/peer
restrictions, plus `preset:{name,component,entry_id,revision,digest}` and explicit
`interface_name`, resolved `interface_index`, `local_address`, `peer_service` where
needed. Schema5 All-program rules have no fabricated application and require
administrator authority. Older readers reject unsupported schema5; do not downgrade
by deleting records. Generic legacy editors cannot strip metadata or widen scope.
Normal rule views expose component/target state and exact conditional Delete.

Deterministic reserved IDs avoid duplicate apply. Whole inventory and component
revision are frozen in previews. Exact equivalents/user overrides are preserved;
disabled/edited owned records are disclosed and excluded from preset removal.
Removal deletes only reviewed unchanged records/versions. Restart does not apply or
rewrite anything. Receipts are in-memory; after restart inspect reserved IDs and
refresh rather than assuming an unknown token failed or blindly replaying it.

Service application permissions survive process restart with the same executable
revision/UID/config. Package replacement, changed upstream/time endpoints or missing
observer authority makes old service rules inactive. Refresh requires explicit review;
new endpoints are not silently added, broad destinations are not substituted. Old
revision inventory is retained and removable through reviewed preset removal.

DHCP is intentionally different: explicit reviewed interface/client-port permission
must work before NM/DNS/daemon readiness. It persists on that interface name until
removed, even if automatic addressing later stops. It is never described as a live
process grant or disabled merely because discovery temporarily failed. Interface
renaming/reuse requires reviewing this static boundary. Preset changes and ordinary
Delete/enable-disable of preset records require monitoring so running guard/active
scopes cannot silently diverge. Root recovery/foreign object ownership checks remain.

## Boot guard

`flowgate-guard.service` and daemon ExecStartPre read approved DHCP records from
root-owned `/var/lib/flowgate/rules.db` without opening a competing writer. Guard
and active hooks generate the same interface/protocol bootstrap scopes. No approved
interfaces means no blanket DHCP bypass. Other service permissions wait for policy
loading and authoritative live service/config discovery. Discovery runs only local
status commands, never DNS requests; unavailable cold-start services are retried
without needing DNS to authorize DNS. Services must retry until validated hooks are
ready. Cold-boot sequencing/reboot acceptance of this new preset has **not** been
observed. Intentional monitoring skips the guard. No new blanket loopback/root/VPN
exemption, foreign firewall or routing mutation is introduced.

## Focused evidence and honest limits

New evidence under repository `.workspace/`:

- `essential-dns-kernel.log`: actual private-kernel NFQUEUE outgoing-policy path;
  separate native client/upstream binaries, UDP **and TCP** DNS response through
  verified stub and exact configured upstream; unrelated direct DNS attempts block.
  This is focused policy evidence, not another host lifecycle matrix.
- `essential-dhcp-final.log`: real disposable veth peer; DHCPv4 unicast/broadcast
  and DHCPv6 link-local/multicast request/reply under guard and active rules;
  unapproved lo interface has a real receiver with zero deliveries. No host renewal.
  It tests UDP protocol bootstrap, not every raw AF_PACKET client implementation.
- `essential-api-cwd-fixed.log`: real Unix API/storage authority, atomic apply,
  receipt replay/read, idempotent duplicates, config-stale rejection, user-edited
  removal preservation, generation conflict, expiry/options/inventory conflicts.
- `essential-focused-final.log`: changed Go packages; time scopes reject inbound
  NTP/wrong peer; optional Tailscale rejects independent inner application identity
  and wrong local port; timeout and identity/config revision invalidation.
- UI exact sandboxed acceptance is recorded in its release note; simulated system
  discovery is labelled, not represented as host identity verification.

Reuse the accepted host TCP/UDP4/6 reply/receiver matrix, continuous lifecycle,
zone/process and TCP-initiation shared-bpftune evidence. The older retained-identity
failure is not relabelled resolved. No new protected host DNS/VPN or reboot success
is claimed. Other resolver/time implementations, fallback-only DNS, unresolved NTP
pools, custom resolver stubs, raw-client-specific behavior and trusted discovery
need adapters/review; no approximate blanket permission is substituted.

## Review and next activation step

Build the matched candidate, then obtain a read-only root identity/config proposal:

```sh
sudo /home/flowgate-user/Apps/flowgate/.workspace/essential-candidate/flowgate system-networking-inspect
```

This only prints discovery/rules/issues. It does not install, save or start anything.
After reviewing exact service identities and optional choices, install the matched
release **in monitoring**, open Firewall → Essential system networking, Preview the
selected options and Apply the exact proposal. Check normal rule inventory/status.
Only after that separate approval run a focused DNS/desktop/VPN/nonmatching-app
host journey and explicitly Start protection. If anything is stale/unavailable,
remain in monitoring. Existing old04c5159 must not be used to read schema5 records.

## Primary documentation

- [resolved service and local stubs](https://www.freedesktop.org/software/systemd/man/latest/systemd-resolved.service.html),
  [resolved configuration](https://www.freedesktop.org/software/systemd/man/latest/resolved.conf.html).
- [NetworkManager DHCP configuration](https://networkmanager.pages.freedesktop.org/NetworkManager/NetworkManager/NetworkManager.conf.html),
  [DHCPv4 RFC2131](https://www.rfc-editor.org/rfc/rfc2131.html),
  [DHCPv6 RFC9915](https://www.rfc-editor.org/rfc/rfc9915.html).
- [timesyncd](https://www.freedesktop.org/software/systemd/man/latest/systemd-timesyncd.service.html),
  [Tailscale transport ports and variable peers](https://tailscale.com/docs/reference/faq/firewall-ports).

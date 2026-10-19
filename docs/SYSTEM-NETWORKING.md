# Essential system networking: review required, protection stays off

## Current Essential preset implementation

The authoritative schema5 preview/apply/status/removal workflow and interface-scoped
DHCP guard are implemented. See [ESSENTIAL-NETWORKING.md](ESSENTIAL-NETWORKING.md)
for current permissions, exact API, update semantics and focused evidence. This
supersedes the historical review-only planner and blanket-DHCP descriptions below.
Host service currently absent; protection remains off. No preset permissions were
applied on the host. Exact running service identity export/review, matched install
in monitoring and focused protected-host usability acceptance remain separate.


## Incident and current recovery state (2026-10-19)

Release04c5159 was installed and its dedicated host acceptance ran, but that did
not establish usable first-run policy. The installation then left both-direction
default-deny active after removing its test rules. Essential fresh DNS/VPN/desktop
attempts had no approved rule and could be held/dropped. This is an operational
defect, not evidence that every system service should be exempt.

Journal evidence records user `flowgate-recover` at08:24:33, monitoring restored
08:24:35, then user `flowgate-uninstall` at08:24:35 and both units stopped08:24:38.
The current units/socket/daemon are absent; NetworkManager, systemd-resolved,
Tailscale and bpftune are running. `getent ahostsv4 example.org` succeeds in this
recovered state. Root-private owned firewall state has not yet been independently
read: no claim of a fresh nft inventory or running FlowGate collector is made.
Do not reactivate or reinstall continuous protection during diagnosis.

## Actual failed Activity action

`.workspace/electron-run-1un1gbv7/electron.log` records repeated `rule:preview`
errors: `stale_target: process generation, executable, principal or namespace
changed/unsupported`. This is observed Activity creation, before Save, not a
pending-request Remember or ambiguous Save acknowledgement. No duplicate Save
should be attempted. The exact selected PID/executable/UID and draft scope were
not included in that log, and the stopped daemon's preview receipts are volatile.
The private Decision Log records packet decisions, not failed Activity previews.
The root export and user context are needed to associate the exact displayed row;
we do not infer a service identity from the label “systemd”.

A concrete verifier defect was reproduced: `VerifyObservedNative` required the
service mount namespace to equal the daemon's mount namespace. Native systemd
services can have private mount sandboxes while using the same host network.
Verification now binds to the expected target mount/PID/boot namespaces, keeping
fresh exclusive socket ownership, live `/proc/PID/exe` revision, PID/start/UID,
native identity and host-netns requirements. It never opens a replacement on-disk
path as the running identity. Namespace/identity changes still reject. This fixes
the reproduced class; the exact incident target remains unconfirmed until exported.

Focused real private user/net/mount fixture checks pass namespace isolation,
negative stale namespaces/revision, actual incoming application/process Allow
preview/save, durable records and exact saved receipt replay. Existing receiver,
reply, process and kernel-direction matrices are reused. No host write/activation.

## Read-only evidence and visible preset

```sh
sudo python3 scripts/diagnose-system-networking.py
python3 scripts/review-essential-networking.py .workspace/system-networking-PRINTED_ID
```

Export reads selected service processes through the installed backend identity
resolver, current DNS/links/routes, recent Decision Log, stored inventory and owned
state; writes only a private session evidence folder. It performs no service,
collector, policy, routing or firewall mutation. Preset output is review-only:
`rules_saved:0`, exact application/UID/revision, candidate filters and reasons.
It is not an import authorization and must be revalidated through live Activity
preview/save with administrator authority after explicit review.

### This host's concrete proposed scopes

| Component | Proposal | Why / limits |
|---|---|---|
| `/usr/lib/systemd/systemd-resolved`, service user `systemd-resolve` (observed UID974) | Application scope, outgoing TCP and UDP, remote port53 to individually configured `172.30.42.128`, `172.30.42.250`, `100.100.100.100`, `fd7a:115c:a1e0::53`; local source port wildcard; exact live key/revision pending export | Current physical-link and Tailscale split-DNS servers from resolvectl. Any network with exact peer restriction, not guessed Local/Internet. No unrelated upstreams or unsolicited incoming. |
| NetworkManager `/usr/bin/NetworkManager` | No blanket rule. Existing engine DHCP bootstrap remains narrowly UDP68→67 / link-local DHCPv6 | No demonstrated need for arbitrary outbound/incoming NetworkManager permissions. Connectivity-check HTTP is separate optional traffic, not essential DNS. |
| Tailscale `/usr/sbin/tailscaled` | No wildcard. Await exact failed/observed transport peers, protocols, local/remote ports and live revision from export; propose individually, time-bound where dynamic | Outer encrypted transport/control/DERP differs from inner app traffic. A DNS preset alone does not establish VPN usability. Do not approve all UDP/TCP443 from a service name. |
| Desktop apps | Continue ordinary application prompts/rules | This host NSS uses `resolve` over local IPC before `dns`; it does not need a global all-program DNS/Internet exemption. Apps using direct DNS/DoH remain separately controlled. |

The resolver's UDP/TCP53 upstream permission is **outgoing**, not an incoming
Allow for an arbitrary systemd row. Approved conntrack reply handling is separate
and already receiver-tested; it is not an unsolicited-inbound service permission.
Loopback stub users may require explicit client/stub policy if they bypass NSS;
no all-program loopback wildcard is silently introduced. Link-local scoped DNS
cannot be represented without interface semantics and is rejected by the planner.

No preset is automatically applied at startup/update. Existing equivalent rules,
including disabled or user-edited Block, are flagged for review and preserved.
A package update changes the executable revision: old permission does not silently
bind to the replacement. Reinspect/review the new identity and retain old inventory.
Server/route/VPN changes likewise require review; these are host-specific candidates,
not universal Linux defaults. No all-root, systemd-prefix or all-Tailscale rule.

## Activation gate and validation

Future installer completion persists monitoring after the dedicated receiver
journey. It does not label a zero-rule default-deny installation daily-use ready.
No automatic continuous reactivation or boot protection until preset review.

Planner checks cover exact DNS scopes, incomplete identity rejection, no fallback
DNS guessing, user-edit preservation and executable-update IDs. Generated schema2
rules pass existing policy validation, SQLite persistence, correct DNS match, and
negative unrelated application/revision/peer/port/direction checks. These are
isolated/model checks, not host DNS under protection. Current host DNS success was
observed only with protection off. After root evidence and review, apply only the
approved exact rules through preview/save; run one focused DNS/ordinary desktop/
VPN/nonmatching app/reply journey before an explicit Start. Keep monitoring if any
step fails. No new broad/persistent service permission is approved by this document.

Current recovered-state checks also returned HTTPS HTTP200 and Tailscale
BackendState Running. Tailscale reports a separate NM/resolved wiring warning
(MagicDNS may not work). That configuration was not changed, and this DNS proposal
does not claim to repair it or prove tailnet reachability.

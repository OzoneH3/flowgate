# Explicit host-control evaluation

**Implemented and tested in disposable namespaces; not activated on the real host.**
Normal `scripts/run-desktop.sh` remains read-only. This is a manual, incoming-first
prototype, not an installed service or a claim of universal firewall/VPN compatibility.

## Review, then explicitly activate

From the repository root, as the ordinary desktop user:

```sh
scripts/evaluate-host.sh
```

This builds the programs, then uses terminal sudo to create root-owned state/API
and database directories and start the foreground daemon. It does not elevate Qt.
It deliberately changes the live host firewall **only when you execute it**.
The default evaluation lasts **five minutes**, with **30-second** prompt deadlines.
The independent, session-detached watchdog also removes this instance at that
same deadline if the daemon dies. No service, autostart or runtime helper is installed.

In another ordinary-user terminal:

```sh
.workspace/desktop/flowgate-desktop --socket /run/flowgate-api/control.sock
```

Use Pending & recent decisions for Allow/Block. Once is the default. One-hour
permissions are saved with absolute expiry; Persistent means until disabled/deleted,
subject to the executable revision guard. The Rules tab lists actual stored rules
and supports Disable/Delete. Scope previews come from the backend. The control
connection shows decisions; the existing Activity monitor remains available through
`scripts/run-desktop.sh` as a separate read-only connection.

Exact foreground command prepared by the script (after its directory setup):

```sh
sudo .workspace/flowgate host-start \
  --state /run/flowgate --database /var/lib/flowgate/rules.db \
  --socket /run/flowgate-api/control.sock --uid "$(id -u)" \
  --duration 5m --timeout 30s
```

The duration is mandatory-bounded: 10 seconds–30 minutes. There is deliberately
no unlimited production activation option in this milestone. Closing Qt does not
stop enforcement. Ctrl+C in the foreground daemon terminal deliberately stops it.

## Inspect, stop, recover

From the same repository:

```sh
sudo .workspace/flowgate host-status --state /run/flowgate
sudo .workspace/flowgate host-stop --state /run/flowgate
# After a dead daemon; never overrides an active instance lock:
sudo .workspace/flowgate host-recover --state /run/flowgate
```

Stop/recovery delete only `inet flowgate_host` with this run's random ownership
comment, clear only reserved conntrack bits `0x30000000`, and remove only recorded
API socket inodes. The root-owned record pins PID/start time, network namespace,
instance token and deadline. pidfd signalling protects against PID reuse. Recovery
is repeatable, refuses foreign table ownership/active locks, and never flushes
unrelated rules or connections. A missing ownership record is not permission to
remove an arbitrary table. Keep the state record until cleanup succeeds.

Deliberate stop restores handling to the remaining firewall configuration; FlowGate
is no longer enforcing. Unexpected queue failure leaves the owned rules fail-closed
for undecided TCP/UDP until recovery or the **disclosed deliberate evaluation deadline**.
Already approved TCP and preserved/outbound flows can continue. A full queue drops;
there is no queue-bypass or fail-open. If both daemon and watchdog are killed, use
recovery: no software watchdog can survive its own destruction.

## Profile and coexistence contract

- Local **input TCP/UDP**, IPv4 and IPv6; no forward/container/router coverage.
- New incoming SYNs and original-direction UDP are evaluated using current native
  attribution. Missing/ambiguous owners block, never generate actionable prompts.
  History/prompt limits remain 256 entries/20 new events per second; packet and
  byte retention bounds are unchanged. No-listener attempts produce bounded blocked
  history, not an endless prompt stream; no per-packet disk logging.
- Outgoing TCP/UDP is permitted by FlowGate. Output original-direction traffic gets
  a reserved conntrack bit; replies bypass incoming prompts. An input SYN does not
  inherit a port-wide application grant. Ordinary decided TCP continues under the
  initiation contract; rule changes do not disconnect it. UDP is re-evaluated.
- Confirmed TCP/UDP connections present in the startup conntrack snapshot are
  preserved. Established TCP sockets without a matching conntrack record cause
  startup refusal rather than silently breaking them. The snapshot and atomic rule
  installation are not one kernel transaction: connections first opened during
  **starting**, after that snapshot, can need a retry. This is not seamless cutover
  under an arbitrarily busy/mutating network.
- Other protocols, including ICMP/ICMPv6, remain outside application filtering and
  pass through to the remaining firewall. IPv4 DHCP server67→client68 and IPv6
  link-local server547→client546 are explicit client bootstrap exceptions. They
  are not server identity validation. Other DHCPv6 source scopes are not exempt.
  No blanket LAN exemption. Queued IP fragments/IPv6 extension-header traffic is
  still unsupported and drops; IP reassembly before input can affect what is queued.
- Exclusive NFQUEUE **101**; nft input/output priority **10**, admission-mark hook
  **11**. Approval bit `0x10000000`; preserved/local-origin bit `0x20000000`.
  Marks use masked OR/update, preserving all other bits. NFQUEUE Accept resumes at
  the next base hook; admission marking intentionally resides there.
- Preflight reads nft rules, interfaces and available queue/legacy-table diagnostics.
  It refuses an existing FlowGate table, existing nft mark/queue/notrack/zone usage,
  reserved bits already present, detectable legacy iptables tables, and detected
  WireGuard/TUN/XFRM interfaces. This is deliberately conservative; many VPN/firewall
  setups therefore cannot activate this initial profile. Permission-limited queue
  census is reported, with exclusive kernel queue binding required before mutation.
  It does not prove compatibility with every manager, route policy, BPF hook or
  concurrent privileged firewall writer. Changes by another privileged manager
  after preflight remain a coexistence limitation.
- API Active requires the live worker plus owned table and a matching normalized
  structural ruleset digest. A changed/missing table reports degraded/unavailable;
  this periodic check is not a race-free packet-delivery attestation. Disconnected
  means actual enforcement state unknown, never implicitly stopped/protected.
- FlowGate Allow is permission from FlowGate, not proof that another chain, VPN or
  remote endpoint delivered the packet.

## Authorization, storage and limitations

Root-only daemon/control records live in mode0700 directories with owned, non-writable
ancestors. The root-owned API parent grants traversal only (0711); each socket is
0600, owned by the explicitly selected GUI UID. SO_PEERCRED restricts access and
policy actions to the owning application UID; root is an explicit administrator.
The `.monitor` socket rejects all mutations. There is no network control port,
password dialog or world-writable socket. Services belonging to other UIDs will not
receive a decision from this user's GUI and can time out blocked. Review this before
use on a machine offering shared/network services.

SQLite stores at most 256 validated rule documents (schema 2), with creation time,
absolute expiry or no expiry, disabled state and an informational executable path.
Matching continues to use application/revision/UID/direction/protocol/address/ports.
One transaction commits before policy publishes a remembered verdict. Pending IDs,
packets and Once grants never persist. Unsupported/corrupt storage refuses startup;
a write error cannot publish an Allow. A disabled/deleted rule invalidates pending
and userspace cached decisions conservatively; a new connection must retry.
`/var/lib/flowgate/rules.db` survives daemon restart/reboot; `/run` control state does
not. Direct CLI calls can choose separate private paths with `--database`.

Native interpreter attribution still identifies the interpreter. Snapshots are not
hostile-same-user descriptor-transfer protection. No new Wine/game attachment,
full launcher support, continuous ownership enforcement, persistent event history,
production packaging or performance guarantee is claimed.

Dependencies reused: MIT-licensed `ti-mo/conntrack`/`netfilter` for read-only census
and netfilter encoding, MIT `mattn/go-sqlite3` with its bundled public-domain SQLite.
Go now needs CGO and a C compiler; no new system package was installed. The inspected
binary links libc and libresolv; SQLite is bundled in this build. Consult the
pinned module licenses/source, not a claim that this binary is static/portable.

## Reproduce isolated evidence

```sh
QT_QPA_PLATFORM=wayland WAYLAND_DISPLAY=wayland-0 scripts/check-host.sh
# Without a display (automated only):
QT_QPA_PLATFORM=offscreen scripts/check-host.sh
```

The new host-start implementation runs in the existing user/net/PID namespace
harness with a second network namespace and veth link. All addresses, routes and
nft mutations remain there. Tests exercise IPv4/IPv6 TCP and one-shot UDP decisions,
outgoing replies, ICMP/ICMPv6, pre-existing TCP, stored scope/expiry across restart,
disable/delete, startup conflicts, rule-health degradation, daemon death, repeatable
recovery and watchdog timeout. A stored-rule fixture shortens an absolute expiry;
the product's one-hour option is not silently shortened. Qt clicks the actual
persistent Allow, Disable, Block and Delete controls and checks receiver counts.
No Wine matrix is rerun. Separate bootstrap tests verify pre-existing IPv4/IPv6 TCP
and UDP datagrams on the DHCP client-port exceptions without prompting. Full DHCP
lease negotiation, other distributions and real-host coexistence remain unverified;
the IPv6 tests exercise ordinary NDP on the veth link.

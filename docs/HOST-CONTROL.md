# Explicit host-control evaluation

## Optional outgoing profile

Before **Start 5-minute evaluation**, select **Incoming connections** (default) or
**Incoming and outgoing connections**. Outgoing control may interrupt new
application connections while awaiting decisions. Changing the selector never
changes a running controller. Stop and start explicitly to change profile.
The same five-minute deadline, watchdog and recovery apply to both profiles.

The GUI terminal bridge carries `--profile both` for the latter choice. For a
custom explicit terminal run, `flowgate host-session --action start --uid UID
--duration 5m --timeout 30s --profile both` selects it; retain the existing
root-owned runtime/IPC paths and sudo startup procedure below. The existing
`scripts/evaluate-host.sh` shortcut remains incoming-only.

Saved outgoing rules do not control outgoing traffic in incoming-only mode.
Unknown or unobservable senders fail closed in both mode; other-UID services can
therefore be affected. Neither profile is enabled by normal desktop startup.
This increment was tested only in disposable namespaces, not the host network.


**Implemented and tested in disposable namespaces; not activated on the real host.**
Normal `scripts/run-desktop.sh` remains read-only. This is a manual, incoming-first
prototype, not an installed service or a claim of universal firewall/VPN compatibility.

## Desktop workflow (explicit opt-in)

Run `scripts/run-desktop.sh` as your desktop user. Activity is live and read-only.
Click **Start 5-minute evaluation** and accept its explanation. Konsole opens
system sudo authentication; Qt has no password field. After authentication, the
terminal bridge starts the controller and the same window verifies its generation,
mode and active health before enabling decisions. The countdown uses the backend
clock and original deadline. There is no automatic renewal or restart.

Activity and control are independent sockets. Stop, controller loss and cancelled
or failed authentication leave Activity usable. A read-only endpoint cannot stand
in for failed control. **Stop evaluation** uses terminal sudo because the selected
user's policy API permission does not include machine-wide Stop. **Status / recovery…**
uses the same explicit privileged path. Confirmed Stop leaves saved rules on disk;
the window labels the retained Rules snapshot as last received and disables edits
until the controller is available. Disconnected without cleanup confirmation means
actual enforcement state unknown. A status check can confirm cleanup later.

The evaluation lasts **five minutes**, with **30-second** pending deadlines.
Closing Qt does not stop it. Its independent detached watchdog remains responsible
for the original deadline. Authentication cancellation is bounded to 60 seconds;
startup has a 30-second bound after authentication. Cancel startup requests a
cancel/foreground Stop, but the UI requires cleanup acknowledgement before saying
stopped. If the terminal disappears without a result, the UI reports unknown and
provides status/recovery. No failed operation is automatically replayed.

The launcher needs Konsole, Python 3 and an existing sudo policy permitting these
commands. Nothing installs an authorization framework, sudoers rule or service.
Restricted sudo policies can refuse a command; the concrete error is shown.
Konsole remains the authentication owner. Direct live sudo/host activation was
not exercised in development; simulated authentication is distinguished below.

Terminal alternative:

```sh
scripts/evaluate-host.sh
# Optional separately launched GUI; normal run-desktop.sh already combines both:
.workspace/desktop/flowgate-desktop \
  --monitor-socket /absolute/private/observer.sock \
  --control-socket /run/flowgate-api/control.sock
```

The evaluator now calls `sudo .workspace/flowgate host-session --action start
--uid "$(id -u)" --duration 5m --timeout 30s`. It creates/validates root-owned runtime,
API and database directories without following symlinks or taking ownership of an
unsafe existing directory. It snapshots `/proc/self/exe` into mode0700
`/run/flowgate/controller`, then executes that snapshot. The watchdog and later
controls use it, so rebuilding a writable workspace binary cannot replace an
active controller's executable. This is a per-run executable, not an installed
service. Root never writes results into a GUI-provided job directory: the
unprivileged terminal bridge writes bounded private files under `.workspace`.
All executable arguments are structured; observed metadata supplies no commands.

The lower-level `host-start` remains available for controlled custom deployments
and namespace tests. Duration is bounded to 10 seconds–30 minutes; the desktop
always requests five minutes. Qt remains unprivileged throughout.

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
a write error cannot publish an Allow. Enable preserves the exact scope, creation time and absolute expiry; it does not
revive an expired lease. Once decisions never appear as stored rules. Rule columns
show application, action, direction, protocol, endpoints, absolute expiry and state.
A changed rule invalidates pending
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

## Unified desktop evidence

`QT_QPA_PLATFORM=wayland WAYLAND_DISPLAY=wayland-0 scripts/check-unified.sh`
exercises the real controller, private root-in-namespace snapshot, receiver and
read-only observer together. The C++ test replaces only terminal authentication
with a private test launcher. `check-control-bridge.py` separately runs the real
terminal bridge with a simulated sudo executable inside a disposable namespace.
These checks do not authenticate or activate on the real host.

Qt tests verify a minimized pending request invokes the installed native tray
facility, throttles repeated attempts, and opens the current request without an
Allow action. Clicking an expired notification grants nothing. Native notifications
can be suppressed by desktop settings; the pending count/list remain authoritative.
Dialog prompts are shown automatically only while the main window is active, not
over inactive/fullscreen applications. The tray contains no Allow action.
Notification callbacks are tested through Qt; no claim is made that desktop Do Not
Disturb settings or every shell delivers a visible popup. No pixel-identical
NetLimiter claim or new game support is made.

# Milestone semantics and safety boundaries

## Optional UDP accounting adapter (isolated kernel/Wayland verification passed)

See UDP.md. The optional BPF path counts successful send return bytes and non-peek,
non-error-queue receive return bytes, keyed by registered UDP socket cookie in the
selected namespace/UID. Truncation follows the return value, not wire length.
UDP API-byte and TCP transport-byte aggregates are never silently summed.
UDPSnapshot v1 has generation, monotonic sample_ns, namespace, collection time and
missed-operation count. A repeated sample has no new rate, not a synthetic zero;
restart/registration reset has a new observed interval. The collection-only socket
accepts authenticated list/Stop, never policy changes. Normal monitoring starts
neither BPF nor enforcement. UDP4/6 BPF counts, shared FD/reuseport/rebind/restart and actual Wayland-rate
checks passed in the user-authenticated isolated namespace; see UDP.md. UDP Activity keys
omit endpoints so a connect does not replace a still-live socket row.


## Activity byte counters

Read-only Activity now uses length-checked Linux INET_DIAG_INFO TCP payload counters
for IPv4/IPv6. Upload includes retransmitted payload; download is accepted TCP
payload. Rates use monotonic differences, totals are observed since baseline.
UDP/listener/unsupported measurements remain unavailable. Unidentified/shared
sockets retain their own counters under one presentation-only group. Partial
aggregates do not treat missing values as zero. See TRAFFIC.md for complete
lifetime, ownership, loopback, restart and coverage semantics. No enforcement
logic changes accompany these measurements.


## Optional incoming + outgoing profile

The default host profile remains `incoming`. `--profile both` is an explicit
startup-only choice; the desktop carries that choice through the authenticated
terminal bridge. New original-direction local TCP SYNs and UDP datagrams queue
in the output hook (priority 10). Hook 1/3 on the single NFQUEUE 101 selects
incoming/outgoing attribution; invalid or missing hooks drop. Output admission
priority 11 sets the same approved conntrack bit used by input. Queue occupancy
and retained-packet/byte bounds are shared, not multiplied by direction.

Both directions preserve the startup snapshot bit and accept reply-direction
traffic only with an approved or preserved mark. New SYNs precede mark fast paths.
An approved TCP connection continues without continuous accepted-socket ownership
checks; edits do not terminate it. UDP keeps current ownership/lease checks.
Both profile does not exempt generic DNS, interpreters, Wine or common ports.
TCP/UDP DHCP exceptions remain IPv4 client68→server67 and IPv6 client546→server547
only to fe80::/10 or ff02::1:2. ICMP/ICMPv6 and non-TCP/UDP remain outside this
application policy. No forwarding coverage is claimed.

Unknown/ambiguous ownership, timeout and overload drop. A one-shot UDP datagram
can be held and released without retry, but its socket must remain observable:
if a sender closes before delayed revalidation it fails closed. Local loopback
between different applications may require sender and receiver decisions; there
is no blanket local exemption. Other-UID application traffic can be blocked
without becoming actionable for the selected user's policy client.

Remembered outgoing defaults: application/revision/UID, outgoing, protocol,
remote destination address and service port; local source port zero (any).
Incoming defaults remain remote client address, local service port, remote
source port zero. Existing incoming rules never migrate to both directions.
Incoming-only output exemption intentionally takes precedence over any stored
outgoing rules. A FlowGate Allow does not imply delivery through other firewalls.

Editor semantics, atomicity and conflict rules are specified in RULES.md.


## Identity and evidence

Socket discovery uses NETLINK_SOCK_DIAG TCP/UDP IPv4/IPv6 dumps, including inode, cookie, state and endpoints. `/proc/*/fd` finds **all visible owners**, including processes whose current network namespace differs from their retained socket. Socket snapshots are checked again after the scan. Processes carry PID plus start ticks, UID, current network/mount namespaces, actual executable, parent and cgroup. PID reuse or listener/cookie changes invalidate delayed answers.

Native logical keys hash UID, kind and executable path. Wine keys add canonical prefix and resolved Windows executable; the runtime executable and Steam display metadata are excluded. A revision guard uses device/inode/size/mtime/ctime, not a cryptographic content attestation. Wine mappings must match the mapped inode as well as argv[0]. A changed/replaced executable requires a new permission. Moved installations and reused paths do not inherit permissions automatically. Runtime updates do not change a Wine key. Interpreted native programs currently identify their interpreter, not each script.

Wine identification requires a Wine runtime indication, explicit WINEPREFIX or STEAM_COMPAT_DATA_PATH/pfx, and argv[0] corroborated by a mapped .exe. Only WINEPREFIX, STEAM_COMPAT_DATA_PATH and SteamAppId environment values are retained. Reads are bounded; raw environments, command lines and maps are never serialized. Reading the bounded proc environment still accesses other values transiently because proc exposes one file. Diagnostic metadata/path strings are JSON escaped, not shell commands. Prefix and metadata are evidence supplied by a process, not trusted security assertions.

The prototype does not infer a child's identity from its parent, a prefix, basename or SteamAppId. Runtime version, launcher installation databases and tracked multi-process launch sessions are not yet implemented. Missing explicit prefix, a launcher changing argv, inaccessible mappings or multiple mapped image candidates may prevent attribution.

One matching socket and one visible owner are required by default. The explicit Wine broker mode additionally accepts one mapped Windows client plus a configured broker with reciprocal Unix peer evidence, same UID/namespaces/prefix. Both holders are preserved; the client is the authorization principal. Its evidence, roles and non-sharing assumptions are serialized under `association`. See WINE.md for the demonstrated dormant-handle boundary. Two visible Windows clients, SO_REUSEPORT candidates, socket activation with shared owners and relays remain ambiguous. A v6 wildcard remains a candidate for IPv4 when v6-only state is unknown; observed INET_DIAG_SKV6ONLY excludes known v6-only sockets. Runtime-table permission for IPv4 on an IPv6 socket requires observed dual-stack mode. Specific and wildcard listeners are not ranked by guessed kernel selection. Hidden processes or inaccessible FDs reduce capability. `/proc` scanning is not atomic: FD transfers, bind/close and image mutation can race even a second snapshot. This baseline is a lab prototype, not protection against a hostile local process. Passing data through a shared proxy cannot be reliably attributed back to an original game by this method.

## Policy

Filters are separate from actions. A startup rule is:

```json
[{"schema":2,"id":"example","priority":100,"action":"allow","filter":{
  "application":"KEY_FROM_ATTRIBUTION","revision":"REVISION_FROM_ATTRIBUTION",
  "uid":0,"direction":"incoming","protocol":"tcp","local_port":8080,"remote_address":"127.0.0.1"
},"expires":"2030-01-01T00:00:00Z"}]
```

Highest numerical priority wins; ties use lexicographically smallest unique rule ID. All matching rule IDs are returned in precedence order. Schema 2: `remote_address` is an IP, CIDR, or explicit `*`; omitted/empty means any address. `local_port` and `remote_port` are exact ports; omitted/zero means any port. CLI remembered incoming defaults to observed remote address + local service port, with unrestricted source port. Outgoing defaults to observed remote address + destination port, with unrestricted local port. A CIDR or advanced remote-port restriction can be selected in a startup rule. The `remembered_filter` output previews the scope. Identity/revision/UID/direction/protocol remain mandatory. Legacy schema omitted/0/1 keeps `remote` as an exact IP:port or empty for any endpoint; it cannot use the new fields. Mixing legacy `remote` with new address/remote-port fields is rejected. Unknown schema versions and startup JSON fields are rejected. The API remains v1 with additive output fields. No implicit Allow/Block priority or hidden specificity weights. No matching rule means Ask; unsafe attribution means Block even if a rule would otherwise match. Unknown users have no application permission. API authorization is independent of policy matching.

Rules are bounded to 256. The lab retains memory-only rules; explicit host-control mode commits remembered rules to SQLite before publishing decisions. See HOST-CONTROL.md for durable expiry and Disable/Delete semantics. The bounded saved-rule editor is described in RULES.md. Loading/replacing rules clears userspace decisions. Expired rules are re-evaluated on subsequent queued packets. New application-scope answers invalidate decided userspace events whose effective policy changes, while retaining unaffected decisions and unrelated pending requests. This prevents an unrelated answer from discarding a just-approved one-shot packet before its verdict is sent. Replacing the complete rule set invalidates pending IDs too; their held packets drop. TCP connections already admitted keep their kernel decision until conntrack expires/closes; rule changes do **not** revoke these connections. UDP original-direction datagrams recheck ownership and rule/decision lifetime. New SYNs are always attributed even on marked tuples, and their sequence separates successive attempts using a tuple. This prevents a standing port-wide permission.

## Lifecycle, resources and failure

Observed/awaiting-attribution are synchronous transient stages. Stored events are awaiting-decision, allowed, blocked or expired. Initial undecided packets remain in the kernel NFQUEUE within explicit bounds. The callback records only packet ID, length, event identity and deadline, then returns. A separate 20 ms verdict loop processes CLI decisions and timeouts. No packet is manually reinjected. A timely Allow rechecks current application/listener/broker relationship and rule validity immediately before issuing a normal verdict; otherwise it drops. The kernel still owns payload storage; no payload is logged or retained in Go. Answers re-resolve ownership and reject changes, stale IDs, unauthorized users and expired requests. CLI disconnect leaves the daemon and pending state running.

Pending timeout defaults to 15 seconds (configurable 1–60). Once decisions last 30 seconds in userspace; an admitted TCP connection then uses conntrack for its lifetime. UDP once is a fixed 30-second lease, not an idle sliding window. Expired event history is removed after five seconds on the next access. Max 256 events, 20 new events per second, 128 kernel queue packets, 16 simultaneous API clients, 16384-byte API requests and three-second server request deadlines. Retained packets are additionally limited to 64 globally, 1 MiB of IP packet bytes globally, 64 KiB per full flow, and four UDP datagrams or one TCP SYN per flow. TCP retransmitted SYNs are dropped while the initial one waits. UDP packets retain arrival order up to the cap; duplicate UDP datagrams are not inferred from payload equality. Excess packets drop without an Allow. Byte accounting describes packet lengths, not allocator/skb overhead. Queue processing can add scheduling latency to timeout handling; no Allow is issued after the original retention deadline even if the decision lease was renewed. Scanning on every queued packet is intentionally simple and can be CPU-expensive; no throughput or zero-overhead claim. No custom replay buffer. CLI disconnect leaves held packets pending; Block, timeout, invalidation, shutdown or queue errors drain/drop them. If verdict delivery fails, the queue closes, dropping remaining kernel packets. Bounded retention cannot prevent application-side timeouts or buffer unlimited UDP.

NFQUEUE has neither queue-bypass nor fail-open. A missing consumer or full queue drops new traffic; a SIGKILL test verifies no receiver delivery. Already admitted TCP connections can continue using their conntrack mark after consumer failure. Graceful lab shutdown removes only `inet flowgate_lab`, ending enforcement deliberately. An unexpected queue error terminates the daemon and retains the table, so new traffic remains blocked. Graceful SIGINT/SIGTERM is an explicit lab teardown. No production service supervisor or host installer is provided.

The table is created exclusively and cleanup only runs after successful creation. A pre-existing table causes startup failure. Recovery inside the lab is `nft delete table inet flowgate_lab`, or exit the namespace. There is no generic flush command. Conntrack mark 0x4647 is reserved only in the isolated lab. The separate host-control mode uses its own allocation, preflight and recovery described in HOST-CONTROL.md; these lab marks are never used for host activation. Allowed means FlowGate's verdict, not proof of delivery through other firewall chains.

## Network scope

The harness creates fresh user, network, mount and PID namespaces and private procfs; it enables loopback only. Incoming TCP SYN attribution examines listeners before accept. Outgoing SYN attribution examines the sender socket. UDP checks connected and unconnected sockets. Return traffic uses the explicit decision mark; bare established state is not permission. IPv4 and simple IPv6 packets are supported. Fragmented packets and IPv6 extension-header packets queued to userspace are rejected; ICMP and other protocols are outside this prototype's TCP/UDP policy. No forwarding/container protection, DNS/domain policy, bandwidth limiting is claimed; the optional host `both` profile is described above.

## Optional runtime census experiment

`serve-lab` can explicitly select the Wine table adapter documented in WINE.md.
Its authorization principal contains a UID, not an invented Linux PID. Raw FD
holders and Windows handle holders are separate output. One current Windows
holder plus corroborating broker/kernel/image evidence permits an application
key; multiple holders deny single-app permission. Two snapshots and a kernel
bookend are repeated at delayed release. Observer loss is sticky fail-closed for
that runtime until daemon restart. New TCP attempts and UDP are rechecked;
already allowed established TCP keeps the existing fast path and does not promise
continuous detection of subsequent socket transfer. Defaults and rule schema
remain unchanged.

## Connection-initiation product contract

This milestone authorizes **new TCP connections**. Once approved, a connection
may continue on its kernel fast path, including after an accepted-socket transfer
to another process. This is intentional initiation control, not continuous
ownership enforcement. The actual WSADuplicateSocket fixture demonstrates that
beta can receive on alpha's already-approved connection after alpha closes its
reference. A new SYN still needs current policy and attribution. Remembered rules
remain application/revision/user/endpoint filters, never runtime or port grants.

Rule replacement, deletion through replacement, expiry, or a new Block decision
invalidates relevant userspace decisions as previously documented; none currently
disconnects an already-admitted TCP connection or clears its conntrack mark.
There is no separate disconnect operation yet. UDP retains the existing per-flow
lease and per-datagram ownership/rule checks. Continuous ownership tracking and
explicit disconnect are separate future capabilities, not prerequisites for
native prompts under this contract.


Runtime attachment is explicit for already-running workspace test prefixes.
Discovery is read-only. Broker PID/start/revision/namespaces and observer generation
are pinned; replacement or helper/protocol failure requires explicit reattachment.
A prefix is a runtime-session boundary, not a game-session assertion. IPv6 table
rows preserve scope IDs; link-local permission remains unsupported without a
validated interface mapping. See WINE.md for commands and tested family cases.

## Native desktop client and additive API metadata

The v1 response now includes an opaque random backend `generation`, `read_only`,
`mode` (`isolated-lab` only when explicitly set by serve-lab), `server_time` and
peer UID as seen by the backend namespace. Generation is independent of request
IDs. Event `scope_previews` contains backend-generated descriptions keyed by the
supported `once` and `application` scopes; UI controls require an available preview.
Authorization and the existing decision validation are unchanged. UI and CLI
answers both report an explicit client decision.

The Qt client polls every 500 ms with at most one list request in flight. Decisions
use separate asynchronous sockets, at most eight outstanding. Requests time out
at 3.5 seconds, replies cap at 4 MiB and lists at 256 events. Displayed remaining
time uses the backend clock offset, but only the daemon decides expiry. A failed
or missing acknowledgement is not success; the client refreshes and never replays
an answer. Changing socket invalidates outstanding callbacks and clears state.
Read-only endpoints expose pending requests without prompts or mutation controls.
All supplied metadata is plain text; nothing is evaluated as HTML or a command.

Recent history contains at most 256 events/8 MiB observed by this client during
the current backend session. It is not persistent or complete: backend events
expire and disconnected clients can miss them. Reconnecting to the same generation
refreshes authoritative pending state; a different generation clears old history.
There is one non-modal prompt and bounded notification-ID deduplication. Dismissal
leaves requests pending. Closing the frontend does not stop the backend or grant
traffic. The demo supervisor separately owns lab teardown, triggered by q/Ctrl+C
in its launching terminal; closing its GUI alone keeps the lab enforcing.

The demo's 60-second pending timeout is explicit and lab-only; the daemon default
remains 15 seconds. Kernel retention/queue limits, policy matching, runtime adapters
and established TCP fast paths are unchanged. The GUI outside the single-user
namespace retains host UID1000; SO_PEERCRED inside maps that same owner to UID0,
which is the namespace administrator under the existing API contract. Socket
permissions remain 0600 with a 0700 parent; no host-root GUI or policy bypass.

## Host observation mode

`flowgate observe --socket PATH --interval 2s` uses no nftables commands, NFQUEUE,
packet interception, namespace manipulation or Wine helper. A single collector
reads inet_diag TCP/UDP in its current network namespace and `/proc/PID/fd`.
Sockets remain visible when holders cannot be inspected. UID is not proof of a
current owner; kernel-owned/time-wait sockets and races also leave no visible holder.
Shared sockets carry visible PID/start IDs and appear once, not once per FD.
The additive `display_application` can describe the common native application of
all validated visible owners; it never changes enforcement authority. Worker
fallback uses TID/start IDs and adds `thread_group_pid`. FD links are rechecked
after inspection. Expected inode-zero rows alone are not incomplete coverage.
Visible descriptor ownership is not exclusive recipient identity or a firewall
decision. Observation creates no policy events.

The v1 `list` response adds `activity` in host mode: monotonic snapshot sequence
within a backend generation, start/completion timestamps, elapsed milliseconds,
completeness, issues/error, socket rows and an indexed process table. Socket IDs
include namespace/family/protocol/inode/cookie/endpoints; process IDs use PID/start.
Initiation is Unknown. Linux TCP states describe sockets; connected UDP means a
non-unspecified peer/port, not a TCP-style established connection. Counts are
unique socket rows in the selected filter, not traffic totals.

Serial collection sleeps for the configured delay after completion (500 ms–30 s,
default 1 s). GUI polls asynchronously every second with one list in flight and
never initiates collection. Only the latest snapshot is retained. Errors replace
successful data; an overdue snapshot (interval + five seconds since completion)
returns an error without old rows. Initial collection reports unavailable until
complete. Reconnect fetches current data; a new generation clears Activity state.

Bounds: 2048 socket rows, 2048 process rows/cache entries, 32 visible holders per
socket, 8192 process directories and 131072 descriptor entries per census. Descriptor
iteration checks a two-second budget; scheduling/proc reads are not hard real-time.
Host netlink dumping uses a 64 KiB buffer, finite receive/time budgets and bounded
multipart accumulator (remaining row count and 3 MiB). Truncated/interrupted/error
dumps cannot claim completeness. API snapshots cap at 3 MiB serialized; oversized
results return an error. Metadata fields over 4096 bytes are unidentified instead
of truncated into an identity. Cached strings are detached from raw proc buffers.
Raw environments, command lines and payloads are not exposed or executed.

Descriptors are scanned once per process per snapshot, not once per socket.
Existing process inspection is cached at most five seconds, with PID/start,
executable link, revision, proc UID and network/mount namespace links checked each cycle. Exit removes a process; reuse,
exec and revision changes force inspection. Wine mapped-image metadata can lag by
that TTL while its runtime executable is unchanged; this observation cache is never
used for enforcement. No new Wine detection or helper attachment is performed.

Complete means within bounded observation scope: current-namespace TCP/UDP and
process-leader FD directories plus bounded live-worker fallback after leader exit
(see ATTRIBUTION.md). Other namespaces, private FD tables of workers with a live
leader, hidden
proc mounts and transient sockets can be missed. Partial visibility is shown even
when some holders are identified. Non-atomic snapshots are not attestations.

The host API is forced read-only even if its setup caller requests otherwise.
Only the observer UID reads host snapshots; private 0700 parent, 0600 socket and
peer credentials remain. No root shortcut to another user's host snapshot.
`decide` always rejects. No pretend rules or Protected status. Normal launcher
creates independent instances and stops only its observer when its GUI exits or
supervisor receives Ctrl+C/SIGTERM. This differs from explicit lab teardown and
from connecting a GUI to a separately managed observer.

## Explicit host-control profile

HOST-CONTROL.md defines the implemented optional host profile, privileged socket
ownership, conntrack snapshot cutover, mark reservation, bootstrap exceptions,
SQLite rule lifecycle and scoped watchdog/recovery. Lab and read-only observation
semantics above are preserved. Host responses add `enforcement` (state, detail,
absolute stops_at) and bounded `rules`. States are starting/active/degraded/stopped;
missing interception is unavailable, and disconnected means unknown. Non-active
host responses reject mutation. `rule` accepts disable/delete, with existing peer
ownership checks. `persistent` is available only when durable storage is configured;
`application` is one saved hour in that mode, one memory-only hour in the lab.
Rule schema 2 gains display-only executable, created and disabled fields; older
rules default enabled. Unknown/corrupt stored documents fail startup. Pending IDs
and Once permissions remain ephemeral; a restart never replays a GUI answer.

## Unified desktop control

The normal frontend holds independent observation/control connections. Observation
never changes control health or policy authority. Each has bounded serial polling;
control retains existing generation/epoch and stale-decision guards. Root activation
and Stop remain explicit terminal-sudo commands, outside the selected-user policy API.
Readiness requires matching generation and active health, not a successful preflight
or live monitor. No failed or reconnected command is automatically replayed.
Stored-rule `enable` uses existing ownership checks and preserves all scope/expiry
fields. Offline rules are labelled last received. Minimized notifications are
bounded and open current pending state; they contain no approval action. Dismissal
or a stale callback never grants permission.

## Conditional saved-rule deletion

The additive v1 `rule-delete` operation requires current backend generation and
`expected_version`, checked under the same lock as edits and SQLite commit. Failed
conditions/transactions preserve policy and caches. Successful deletion preserves
legacy conservative pending/cache invalidation; already approved TCP connections
continue. API-created replacements use fresh server-issued random IDs, and backend
restart changes generation. Versions cannot wrap on updates. See API.md for exact
structured error outcomes and lost-response handling. Legacy `rule` Delete remains
unconditional and is explicitly not concurrency-safe. Integrated Qt/Electron Delete
controls now require the conditional capability, freeze confirmation tokens and
never replay an ambiguous mutation. Qt preserves uint64 tokens; Electron refuses
versions outside its safe-integer range rather than rounding.

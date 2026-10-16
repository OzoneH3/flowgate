# Milestone semantics and safety boundaries

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

Rules are bounded to 256 and held in memory. Startup loading and CLI answers are implemented; no durable rule store or live arbitrary rule editor. Loading/replacing rules clears userspace decisions. Expired rules are re-evaluated on subsequent queued packets. New application-scope answers invalidate decided userspace events whose effective policy changes, while retaining unaffected decisions and unrelated pending requests. This prevents an unrelated answer from discarding a just-approved one-shot packet before its verdict is sent. Replacing the complete rule set invalidates pending IDs too; their held packets drop. TCP connections already admitted keep their kernel decision until conntrack expires/closes; rule changes do **not** revoke these connections. UDP original-direction datagrams recheck ownership and rule/decision lifetime. New SYNs are always attributed even on marked tuples, and their sequence separates successive attempts using a tuple. This prevents a standing port-wide permission.

## Lifecycle, resources and failure

Observed/awaiting-attribution are synchronous transient stages. Stored events are awaiting-decision, allowed, blocked or expired. Initial undecided packets remain in the kernel NFQUEUE within explicit bounds. The callback records only packet ID, length, event identity and deadline, then returns. A separate 20 ms verdict loop processes CLI decisions and timeouts. No packet is manually reinjected. A timely Allow rechecks current application/listener/broker relationship and rule validity immediately before issuing a normal verdict; otherwise it drops. The kernel still owns payload storage; no payload is logged or retained in Go. Answers re-resolve ownership and reject changes, stale IDs, unauthorized users and expired requests. CLI disconnect leaves the daemon and pending state running.

Pending timeout defaults to 15 seconds (configurable 1–60). Once decisions last 30 seconds in userspace; an admitted TCP connection then uses conntrack for its lifetime. UDP once is a fixed 30-second lease, not an idle sliding window. Expired event history is removed after five seconds on the next access. Max 256 events, 20 new events per second, 128 kernel queue packets, 16 simultaneous API clients, 4096-byte API requests and three-second server request deadlines. Retained packets are additionally limited to 64 globally, 1 MiB of IP packet bytes globally, 64 KiB per full flow, and four UDP datagrams or one TCP SYN per flow. TCP retransmitted SYNs are dropped while the initial one waits. UDP packets retain arrival order up to the cap; duplicate UDP datagrams are not inferred from payload equality. Excess packets drop without an Allow. Byte accounting describes packet lengths, not allocator/skb overhead. Queue processing can add scheduling latency to timeout handling; no Allow is issued after the original retention deadline even if the decision lease was renewed. Scanning on every queued packet is intentionally simple and can be CPU-expensive; no throughput or zero-overhead claim. No custom replay buffer. CLI disconnect leaves held packets pending; Block, timeout, invalidation, shutdown or queue errors drain/drop them. If verdict delivery fails, the queue closes, dropping remaining kernel packets. Bounded retention cannot prevent application-side timeouts or buffer unlimited UDP.

NFQUEUE has neither queue-bypass nor fail-open. A missing consumer or full queue drops new traffic; a SIGKILL test verifies no receiver delivery. Already admitted TCP connections can continue using their conntrack mark after consumer failure. Graceful lab shutdown removes only `inet flowgate_lab`, ending enforcement deliberately. An unexpected queue error terminates the daemon and retains the table, so new traffic remains blocked. Graceful SIGINT/SIGTERM is an explicit lab teardown. No production service supervisor or host installer is provided.

The table is created exclusively and cleanup only runs after successful creation. A pre-existing table causes startup failure. Recovery inside the lab is `nft delete table inet flowgate_lab`, or exit the namespace. There is no generic flush command. Conntrack mark 0x4647 is reserved only in the isolated lab. Host coexistence/mark allocation is unimplemented. Allowed means FlowGate's verdict, not proof of delivery through other firewall chains.

## Network scope

The harness creates fresh user, network, mount and PID namespaces and private procfs; it enables loopback only. Incoming TCP SYN attribution examines listeners before accept. Outgoing SYN attribution examines the sender socket. UDP checks connected and unconnected sockets. Return traffic uses the explicit decision mark; bare established state is not permission. IPv4 and simple IPv6 packets are supported. Fragmented packets and IPv6 extension-header packets queued to userspace are rejected; ICMP and other protocols are outside this prototype's TCP/UDP policy. No forwarding/container protection, DNS/domain policy, bandwidth limiting or simultaneous incoming+outgoing ruleset is claimed.

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

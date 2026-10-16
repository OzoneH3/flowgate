# Milestone semantics and safety boundaries

## Identity and evidence

Socket discovery uses NETLINK_SOCK_DIAG TCP/UDP IPv4/IPv6 dumps, including inode, cookie, state and endpoints. `/proc/*/fd` finds **all visible owners**, including processes whose current network namespace differs from their retained socket. Socket snapshots are checked again after the scan. Processes carry PID plus start ticks, UID, current network/mount namespaces, actual executable, parent and cgroup. PID reuse or listener/cookie changes invalidate delayed answers.

Native logical keys hash UID, kind and executable path. Wine keys add canonical prefix and resolved Windows executable; the runtime executable and Steam display metadata are excluded. A revision guard uses device/inode/size/mtime/ctime, not a cryptographic content attestation. Wine mappings must match the mapped inode as well as argv[0]. A changed/replaced executable requires a new permission. Moved installations and reused paths do not inherit permissions automatically. Runtime updates do not change a Wine key. Interpreted native programs currently identify their interpreter, not each script.

Wine identification requires a Wine runtime indication, explicit WINEPREFIX or STEAM_COMPAT_DATA_PATH/pfx, and argv[0] corroborated by a mapped .exe. Only WINEPREFIX, STEAM_COMPAT_DATA_PATH and SteamAppId environment values are retained. Reads are bounded; raw environments, command lines and maps are never serialized. Reading the bounded proc environment still accesses other values transiently because proc exposes one file. Diagnostic metadata/path strings are JSON escaped, not shell commands. Prefix and metadata are evidence supplied by a process, not trusted security assertions.

The prototype does not infer a child's identity from its parent, a prefix, basename or SteamAppId. Runtime version, launcher installation databases and tracked multi-process launch sessions are not yet implemented. Missing explicit prefix, a launcher changing argv, inaccessible mappings or multiple mapped image candidates may prevent attribution.

One matching socket and one visible owner are required for an application-specific decision. Shared descriptors (including wineserver), SO_REUSEPORT candidates, socket activation with shared owners and relays remain ambiguous. A v6 wildcard is conservatively a candidate for IPv4 because v6-only state is not queried. Specific and wildcard listeners are not ranked by guessed kernel selection. Hidden processes or inaccessible FDs reduce capability. `/proc` scanning is not atomic: FD transfers, bind/close and image mutation can race even a second snapshot. This baseline is a lab prototype, not protection against a hostile local process. Passing data through a shared proxy cannot be reliably attributed back to an original game by this method.

## Policy

Filters are separate from actions. A startup rule is:

```json
[{"id":"example","priority":100,"action":"allow","filter":{
  "application":"KEY_FROM_ATTRIBUTION","revision":"REVISION_FROM_ATTRIBUTION",
  "uid":0,"direction":"incoming","protocol":"tcp","remote":"127.0.0.1:50000"
},"expires":"2030-01-01T00:00:00Z"}]
```

Highest numerical priority wins; ties use lexicographically smallest unique rule ID. All matching rule IDs are returned in precedence order. Empty remote matches any endpoint; other fields are mandatory. No implicit Allow/Block priority or hidden specificity weights. No matching rule means Ask; unsafe attribution means Block even if a rule would otherwise match. Unknown users have no application permission. API authorization is independent of policy matching.

Rules are bounded to 256 and held in memory. Startup loading and CLI answers are implemented; no durable rule store or live arbitrary rule editor. Loading/replacing rules clears userspace decisions. Expired rules are re-evaluated on subsequent queued packets. New application-scope answers invalidate other cached userspace decisions. TCP connections already admitted keep their kernel decision until conntrack expires/closes; rule changes do **not** revoke these connections. UDP original-direction datagrams recheck ownership and rule/decision lifetime. New SYNs are always attributed even on marked tuples, and their sequence separates successive attempts using a tuple. This prevents a standing port-wide permission.

## Lifecycle, resources and failure

Observed/awaiting-attribution are synchronous transient stages. Stored events are awaiting-decision, allowed, blocked or expired. No packet waits for a person: undecided traffic is dropped, and the prompt says retry is required. TCP generally retransmits; UDP applications may not. Answers re-resolve ownership and reject changes, stale IDs, unauthorized users and expired requests. CLI disconnect leaves the daemon and pending state running.

Pending timeout defaults to 15 seconds (configurable 1–60). Once decisions last 30 seconds in userspace; an admitted TCP connection then uses conntrack for its lifetime. UDP once is a fixed 30-second lease, not an idle sliding window. Expired event history is removed after five seconds on the next access. Max 256 events, 20 new events per second, 128 kernel queue packets, 16 simultaneous API clients, 4096-byte API requests and three-second server request deadlines. Excess requests drop. Scanning on every queued packet is intentionally simple and can be CPU-expensive; no throughput or zero-overhead claim. No generic framework or packet-retention buffer.

NFQUEUE has neither queue-bypass nor fail-open. A missing consumer or full queue drops new traffic; a SIGKILL test verifies no receiver delivery. Already admitted TCP connections can continue using their conntrack mark after consumer failure. Graceful lab shutdown removes only `inet flowgate_lab`, ending enforcement deliberately. An unexpected queue error terminates the daemon and retains the table, so new traffic remains blocked. Graceful SIGINT/SIGTERM is an explicit lab teardown. No production service supervisor or host installer is provided.

The table is created exclusively and cleanup only runs after successful creation. A pre-existing table causes startup failure. Recovery inside the lab is `nft delete table inet flowgate_lab`, or exit the namespace. There is no generic flush command. Conntrack mark 0x4647 is reserved only in the isolated lab. Host coexistence/mark allocation is unimplemented. Allowed means FlowGate's verdict, not proof of delivery through other firewall chains.

## Network scope

The harness creates fresh user, network, mount and PID namespaces and private procfs; it enables loopback only. Incoming TCP SYN attribution examines listeners before accept. Outgoing SYN attribution examines the sender socket. UDP checks connected and unconnected sockets. Return traffic uses the explicit decision mark; bare established state is not permission. IPv4 and simple IPv6 packets are supported. Fragmented packets and IPv6 extension-header packets queued to userspace are rejected; ICMP and other protocols are outside this prototype's TCP/UDP policy. No forwarding/container protection, DNS/domain policy, bandwidth limiting or simultaneous incoming+outgoing ruleset is claimed.

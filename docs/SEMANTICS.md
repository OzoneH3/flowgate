# Milestone semantics and safety boundaries


## Saved application permissions follow program updates

Ordinary saved application rules, including existing rules, follow a newly
verified revision of the same program. The stable application key still binds
user, runtime kind, Wine prefix and executable key path. Every admission needs
current executable/socket ownership evidence; names, ancestry and launchers do
not grant permission. Replacing a user-installed program at this same identity
also retains its saved permissions. A different path, user or prefix does not.
Actions, directions, protocol/address/port/zone restrictions, disabled state,
expiry and explicit root-sharing consent remain unchanged. Process rules,
Once/For-a-while grants and essential presets keep their exact revision and
lifetime checks. A missing or inconsistent identity never inherits permission.

The captured rule revision remains evidence, rather than a request to reapprove
each upgrade. Read-only `follows_updates` metadata states this behavior; a client
cannot write it into permission authority. Native stored paths must hash to the
stored target key; non-native runtime scopes additionally need a current
validated identity witness. Native zero-link images retain their stable program
key using kernel inode evidence, with their original file revision unchanged.
A linked filename literally ending in ` (deleted)` is a different program.

Startup cleanup retains update-following rules instead of archiving them merely
because an executable revision changed. Within one exact program/user/direction/endpoint/zone scope, the newest created saved setting wins; a disabled newest setting does not revive an older choice. Equal creation timestamps keep normal priority/deny precedence. Temporary settings only supersede while unexpired, so they cannot erase a persistent fallback. Startup atomically archives an older copy only when the newer setting covers its remaining lifetime, logging the rule ID and retaining its exact document in the bounded private recovery archive. An older setting retained beneath a temporary override takes effect again when the newer override expires or is deleted. Full-editor edits of the older identical scope are rejected as duplicates while that override is live; enable/disable/delete actions remain available. Different scopes keep normal priority/deny precedence. This does
not infer authority for a newly versioned installation path or a different
prefix, and does not restore rules already archived by an earlier release.


## Process-instance extension (not deployed)

Primary capability `process-instance-rules-v1` adds explicit process targets with
pinned native/session identity, process-tier precedence and inactive lifecycle
metadata. Application rules remain unchanged. See [PROCESS-RULES.md](PROCESS-RULES.md)
for schema3 preview/save/edit/delete, inventory, authorization and exact limitations.
Earlier application-only scope/precedence descriptions below refer to legacy rules.


## Daemon-owned incoming evaluation (new, isolated verification only)

`daemon-evaluation-v1` adds asynchronous readiness/Start/Stop to the existing root
`serve` daemon without another database/API owner. Selected administrator control
requires explicit `--allow-evaluation`; ordinary startup remains non-enforcing.
Fixed300s deadline, session/generation guards, cleanup acknowledgement, independent
watchdog; Activity, stored rules, Decision Log and UDP ownership survive Stop.
Exact contract, limitations, evidence and future deployment:
[DAEMON-EVALUATION.md](DAEMON-EVALUATION.md). **The running host daemon was not
restarted, granted this permission, or used for enforcement in this increment.**


## Activity rule creation does not approve a socket

Primary capability `observed-rule-create-v1` adds generation/principal/draft-bound
30-second preview and save from a freshly verified single-holder native Activity
context. Explicit protocol/direction/address/ports/absolute expiry; identity comes
only from backend inspection. Stored-only monitoring, existing authorization,
SQLite atomic publication and precedence remain. Creation never approves pending
packets; repeated same-token saves are bounded acknowledgements, not duplicate
rules. See [OBSERVED-RULES.md](OBSERVED-RULES.md) for schema, examples, errors,
reconciliation and native/namespace limitations. New `.workspace/flowgate-creation`
build leaves the root monitor/executable untouched; eventual restart unexecuted.
Focused race/vet/API/shared-FD/SQLite checks and isolated receiver Allow->Block
passed. No frontend integration or broader matrix rerun.


## Current-policy metadata is not admission history

Primary-only policy-view/explain report supported native configured rules and
sampled direction coverage with coherent generation/token/order metadata. Concrete
explanations evaluate recorded event identity/endpoints against current stored
rules via the same policy.Evaluate. They neither expire/decide pending traffic nor
resolve ownership/consume Once grants. Established TCP admission can differ from
current policy. Shared/display-only associations remain unavailable, not permission
targets. Direction is connection initiation, independent of upload/download.
See POLICY-EXPLANATIONS.md for exact defaults, proof limits and authorization.


## Product-independent compatibility checks

The former Tailscale-specific coexistence adapter and inspection command are
removed. Interface names grant no exception. TUN traffic remains subject to
ordinary application rules; wireguard and xfrm devices remain unsupported.
Explicit packet/conntrack mark masks and routing selectors must be proven
disjoint from FlowGate's reserved bits. Opaque iptables-nft operations require
matching, stable kernel/export snapshots; unknown operations, native mark
writers, queues, notrack and zones are refused. Runtime checks detect later
conflicts. The updater checks candidate compatibility before stopping the
installed release; activation still rechecks because configuration can change.
No foreign firewall or VPN configuration is modified by this change.
Vendor transport presets are no longer discovered or generated; retired API
options explicitly refuse enabled values. Existing ordinary application rules
remain independent. Old transport presets are retained as records but cannot
be validated by the removed adapter, so they are inactive. A tunnel daemon's
transport now needs ordinary application permissions and may prompt.

Removing the vendor IPv6-prefix override also changes zone matching: tailnet
IPv6 addresses in fd7a:115c:a1e0::/48 now classify as Local under the generic
ULA rule, while 100.64.0.0/10 IPv4 peers remain Internet under CGNAT handling.
Existing Local-scoped rules consequently match those IPv6 peers too. An explicit
custom prefix can override classification; zone classification alone grants no
permission.

## Actor permissions and root monitoring

An explicit root-configured administrator may manage supported application
principals of other UIDs; ordinary privileged-endpoint peers remain self-scoped.
The actor never replaces the rule application UID/revision or resolves ambiguous
ownership. Non-enforcing `daemon-monitor` can edit durable rules but cannot decide
packets; root execution alone never enables enforcement. See AUTHORIZATION.md.
Existing TCP initiation, rule precedence, expiry and conditional versions are unchanged.


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
UDP DHCP bootstrap is automatically scoped to current NetworkManager active
auto-addressed interfaces when protection starts (IPv6 also accepts method dhcp).
The pre-NetworkManager boot guard permits these DHCP pairs on current non-loopback
interfaces; active protection replaces that boot-only set with profile scopes.
Saved DHCP scopes remain supported. Active discovery is bounded to three seconds; on
failure only saved scopes remain. No permission records are written. IPv4 is
client68→server67; IPv6 client546→server547 only to fe80::/10 or ff02::1:2.
Guard and active hooks share one activation snapshot; profile/interface changes
are picked up on the next activation. ICMP/ICMPv6 and non-TCP/UDP remain outside this
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

Process inspection reads a fresh process-mapping snapshot on every call. A read error or a snapshot exceeding 2 MiB makes inspection unavailable; a truncated or unreadable mapping list cannot establish a native identity. Native runtime hints scan the fresh bytes directly. Wine image checks receive a private string copy of that same snapshot. Up to four scratch byte buffers are retained (at most 8 MiB plus four overflow-detection bytes); their old contents are never evidence for another inspection. Buffer reuse changes allocation cost; runtime-classification frequency is described below.

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

Pending timeout defaults to 30 seconds for `serve`/`host-start`, and 15 seconds for `serve-lab` (configurable 1–60). Once decisions last 30 seconds in userspace; an admitted TCP connection then uses conntrack for its lifetime. UDP once is a fixed 30-second lease, not an idle sliding window. Expired event history is removed after five seconds on the next access unless it retains future-rule evidence. Display history still shares the 256-event client bound with live requests: under pressure the oldest ended rows beyond that five-second grace are removed from the list, without deleting their separately bounded retained evidence or receipts. Live prompts and admission leases are never evicted for optional history. Max 256 live event slots, 20 new prompts per second (immediate rule verdicts do not consume prompt rate; replaceable policy history is evicted or omitted without changing the verdict), 128 kernel queue packets, 16 simultaneous API clients, 16384-byte API requests and three-second server request deadlines. Retained packets are additionally limited to 64 globally, 1 MiB of IP packet bytes globally, 64 KiB per full flow, and four UDP datagrams or one TCP SYN per flow. TCP retransmitted SYNs are dropped while the initial one waits. UDP packets retain arrival order up to the cap; duplicate UDP datagrams are not inferred from payload equality. Excess packets drop without an Allow. Byte accounting describes packet lengths, not allocator/skb overhead. Queue processing can add scheduling latency to timeout handling; no Allow is issued after the original retention deadline even if the decision lease was renewed. Scanning on every queued packet is intentionally simple and can be CPU-expensive; no throughput or zero-overhead claim. No custom replay buffer. CLI disconnect leaves held packets pending; Block, timeout, invalidation, shutdown or queue errors drain/drop them. If verdict delivery fails, the queue closes, dropping remaining kernel packets. Bounded retention cannot prevent application-side timeouts or buffer unlimited UDP.

A UDP sender that closes its socket before attribution may be refused even with
a saved application Allow: the queued packet contains no verified executable or
process-generation identity. The accounting collector's cookie/byte counters
are not packet-bound ownership evidence. Reusing a previous tuple owner would
transfer authority on socket replacement, so no such fallback is used. Supporting
this lifetime case requires a separate send-time identity mechanism that binds
each queued packet to the socket and executable generation and handles shared
FDs, exec, namespaces and event loss explicitly. The current implementation does
not provide that mechanism.

The NFQUEUE callback parses and submits work without running process attribution. Eight general workers and two dedicated runtime-census workers share a bounded scheduler: at most 48 attribution packets and 1 MiB of packet lengths, including active jobs, with at most sixteen waiting jobs per network namespace/direction/protocol/local endpoint in addition to its frozen active batch, all within the same global bounds. This key provides scheduling only; every job requires fresh ownership evidence and current policy. A worker may freeze up to sixteen contiguous UDP jobs with the identical complete flow (including interface and namespace) and token before starting one fresh ownership check. That observation covers only those already-queued datagrams; later arrivals and subsequent batches require another check. Each packet still has its own policy evaluation, deadline, retention limit and verdict. The entire active batch stays charged to the queue bounds and cannot be displaced; a busy census defers it without a partial decision. TCP and differing UDP flows/tokens do not share this evidence. Different remotes sharing a local endpoint are serialized conservatively. A nonblocking observer result that requires a busy runtime census transfers the entire endpoint queue to the census lane, keeping its original order and admission deadlines. The lane is capped at 32 packets and 512 KiB within the global attribution budget, not in addition to it; new packets for that endpoint stay in the lane until it empties. Overflow drops rather than waiting on a general worker. Runtime observer slots limit concurrent census/setup work to two; an available slot may run on a general worker, while busy slots or sessions defer to the dedicated lane. The split depends on a resolver implementing TryResolve; custom resolvers without it retain the blocking fallback. The legacy lab-only `--attach-prefixes` and `FLOWGATE_WINE_TABLE_RUNNER` paths use that fallback; the production WineObservers path supplies TryResolve. No payload is copied into the scheduler. Unused global packet slots may be borrowed by a waiting second batch. At global count/byte capacity, a general endpoint within its base sixteen-packet allowance first reclaims one queued tail beyond another endpoint's base allowance, even if that endpoint has a recent-progress hint. Active batches are never borrowed victims. Borrowers cannot displace base work to extend their own queue, and the conservative shared byte reserve remains fixed. Otherwise general-lane traffic may displace one queued packet from another endpoint. Waiting census work is preferred, then the most backlogged general queue and its oldest queued tail; active heads and retained packets are never displaced. A single queued victim must free enough space or the new arrival is refused without speculative drops. Census followers cannot displace another endpoint. General followers may use waiting census capacity; against another general queue they must reduce a backlog imbalance rather than taking its sole waiting head, unless recent progress gives the incoming endpoint priority over that cold queue. Surviving per-endpoint order and original deadlines remain intact. At most one displaced drop occupies the incoming callback transient slot, and shutdown waits for that verdict before closing the queue socket. A bounded history of at most 48 general-lane completions provides one-second scheduling hints: recent endpoints are preferred over cold waiting work and their base allowance cannot be displaced by a cold endpoint; borrowed tails remain reclaimable. At most two consecutive general-lane selections may overtake the oldest queued endpoint; the next selection takes that FIFO head. This bounds hot-endpoint preference without enlarging any queue. A busy-census result immediately revokes the hint. Socket replacement can inherit priority but no cached attribution or permission: every job still runs current ownership and policy checks. This is a bounded progress preference, not an unlimited-throughput guarantee. If global count/byte capacity still prevents admission, the single receive callback waits up to 250 ms for a worker to free space, bounded also by the original packet deadline. Later arrivals remain in the finite kernel/netlink queues during that wait; no userspace backlog or worker is added. A general endpoint with an active check or a completion in the last second may also wait up to 2 ms at its sixteen-packet limit. These endpoint waits share a cumulative 10 ms budget per 100 ms window across the single callback, accounting actual blocked time; scheduler delays may overshoot the requested wait. Endpoints without an active check or recent completion and census-lane pressure still drop immediately. This scheduling hint grants no permission and every admitted datagram requires fresh ownership evidence and its own policy check. Queue bounds are unchanged; the cumulative budget limits interference with other endpoints. Cancellation and scheduler stop interrupt the wait. Sustained overload can still drop packets. Expired jobs drop before resolution or after resolution finishes, with a fixed five-second attribution admission deadline. This deadline does not interrupt a resolver already running. Attribution and prompt retention have separate bounds; together they admit at most 112 outstanding packet IDs before callback transients. Attribution-capacity, census-lane-capacity, admission-fairness-displacement and attribution-expiry/shutdown drops are aggregated in the daemon log once per second; they do not invent application identity for a decision-log entry. Workers drain before the queue socket closes, and cancellation prevents an in-flight result from admitting traffic. Retention revalidation runs outside the Add mutex so new pending packets can be retained while an earlier identity is checked. A slow resolver can occupy a worker; no unlimited-throughput or hard real-time guarantee is made.

Packet evaluation discards direction/protocol/port-incompatible rule candidates before validating their process/preset targets or interface names. This does not change program-scope replacement precedence: those fields are part of the canonical scope, and the final evaluator still checks the full rule. Each packet makes a fresh kernel link observation outside the global policy mutex, then evaluates current policy, expiry and zones under that mutex. A known non-loopback device also makes the same packet's local-peer lookup unnecessary; unknown or loopback observations keep the ordinary peer resolver. Where a relevant named-interface rule needs a fresh link dump, that namespace-pinned snapshot supplies its loopback flag too. No link observation or policy result is cached across packets by these paths, and the native UDP inspection refresh/window remain unchanged.

Admission rejection logs include bounded last-observed limit-mask counts: endpoint=1, global=2, census=4, stopped=8, follower-headroom=16 (combined with endpoint when its waiting batch is not itself full; global count or conservative byte headroom binds). Zero is unclassified. Conditions can overlap; reporting windows can race in-progress callbacks. These are diagnostic observations at failed admission, not attribution, permission, receiver loss or a count of packets lost from netlink overflow notifications.

NFQUEUE has neither queue-bypass nor fail-open. A missing consumer or full queue drops new traffic; a SIGKILL test verifies no receiver delivery. Already admitted TCP connections can continue using their conntrack mark after consumer failure. Graceful lab shutdown removes only `inet flowgate_lab`, ending enforcement deliberately. Netlink ENOBUFS notifications are counted and reported while reception continues; they indicate message loss, never permission to accept an unseen packet. Other unexpected queue errors terminate the daemon and retain the table, so new traffic remains blocked. Graceful SIGINT/SIGTERM is an explicit lab teardown. The production service, independent guard and installer lifecycle are specified in [CONTINUOUS.md](CONTINUOUS.md) and [DAILY-DEPLOYMENT.md](DAILY-DEPLOYMENT.md).

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
lease and fresh ownership/per-datagram rule checks. A frozen UDP batch may share
one fresh ownership observation as described above. Reuse is limited to a complete,
directly associated attribution of one exact native executable in its thread-group
leader, without a holder witness or hosted runtime. A fresh UDP census must show
exactly that socket (netns, inode, cookie) for the same direction and local endpoint.
Every reuse reads the owner's raw generation, executable revision, credentials and
namespaces twice and requires both reads to match the stored identity. Changed or
unreadable identity withdraws reuse and forces full attribution immediately. Runtime
classification from mappings is established by that full attribution, rather than
rescanned for each native reuse hit. Full refresh is scheduled after at least 10 seconds
and is required at the next packet after 30 seconds; verification cannot extend that
window. A native process that loads Wine components in-process without changing its
executable can therefore retain its native classification until full re-resolution.
This is the chosen practical checking policy for trusted ordinary applications. The
API does not currently expose a separate runtime-classification age. Wine/runtime,
hosted and worker-held identities continue to take the full resolver for every batch.
Partial or failed attribution, TCP and link-local endpoints are never reused. The
remote never contributes identity evidence and policy is evaluated for each packet.
These checks re-verify the recorded owner, not the complete current holder set:
new descriptor inheritance or transfer since the last full census remains outside
this bounded snapshot model. Continuous ownership tracking and explicit disconnect
remain separate capabilities. No unlimited UDP throughput is claimed.


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
is 30 seconds for production `serve`/`host-start`, and 15 seconds for `serve-lab`. Kernel retention/queue limits, policy matching, runtime adapters
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

### Localhost policy default

TCP/UDP between loopback or currently assigned host addresses is allowed by default when the packet's
interface is a kernel loopback device in the daemon's network namespace.
This covers IPv4 127.0.0.0/8 and IPv6 ::1, including mapped IPv4 addresses,
and exact addresses assigned in this network namespace. Both endpoints must
qualify; unspecified, multicast and scoped addresses do not. LAN peers and
forwarded traffic are not exempt. Interface names and application/launcher names are not evidence.

This also allows an Internet-blocked application to contact a local proxy or
relay. The proxy's own outbound connections remain subject to its own policy;
localhost access does not inherit the proxy's permissions.

Broad application, process, machine and Local Network zone rules do not block
or prompt for localhost. To filter localhost explicitly, scope a rule's remote
address to a loopback IP/subnet (IPv4 /8 or narrower, IPv6 ::1/128), or use a
legacy exact loopback remote endpoint. For assigned host addresses, an exact
remote IP, /32 or /128 host prefix, or exact endpoint participates too; a LAN
subnet does not become an explicit localhost scope. Those rules keep ordinary executable,
UID, prefix, process, direction, protocol, port, expiry and precedence checks.
A port-only scope or a subnet that includes non-loopback addresses is not an
explicit localhost target. Existing rules with an explicit loopback address
continue to apply; they are not silently removed or broadened.
Only loopback-scoped rules participate for localhost: a broad application Allow
does not override an all-program localhost Ask/Block; use an application Allow
with an explicit loopback address scope for that exception.

With no possible explicit target, admission skips runtime attribution and does
not create a prompt or saved application permission. If an explicit target
might apply, ownership is resolved normally; missing/ambiguous evidence still
fails closed. A rule for another verified application cannot grant or deny this
one. Localhost Allow reports `default-localhost-allow`; other firewall chains
and queue/packet bounds can still prevent delivery. As elsewhere, edits control
new TCP admissions and future UDP checks, not already admitted TCP payloads.

### TCP loopback self-connections

An incoming TCP SYN with identical local and remote loopback address and port,
on a verified loopback interface, follows the localhost default above unless an
explicit localhost rule applies.
Only after an Allow, FlowGate may set the two per-connection TCP BE_LIBERAL window
flags. This avoids conntrack rejecting later self-connection payloads as INVALID.
No global TCP setting, admission mark, timeout, TCP state, or firewall rule is
changed. Outgoing permission remains separate. Missing conntrack evidence skips
this compatibility adjustment and preserves ordinary policy/prompt logging.

The update uses the packet's confirmed original/reply tuple and zone. The kernel
ignores CTA_ID on UPDATE, so FlowGate checks the connection ID before and after
with GET and refuses the queued SYN on failure. This is not atomic CAS. The queued
packet holds its original conntrack reference; a replacement must still pass its
own SYN admission, and window flags grant no permission. Calls share a one-second
deadline and run in the verdict path, not the receive callback. Failures are counted
and reported at the queue log interval. Kernel regression tests cover IPv4/IPv6
multi-payload delivery, incoming/outgoing denial, and mismatched connection IDs.

Wine TCP activity association uses per-broker batches, not a fixed first-eight
socket selection. Each batch brackets a fresh complete kernel descriptor census
with runtime owner tables, rechecks kernel cookies, and verifies the broker,
Windows image, UID and prefix for each row. Image evidence is shared only within
that batch; no previous refresh donates an association. Unix descriptor holders
remain visible. Busy or incomplete observations stay unidentified, and admission
continues to use its independent per-request census. Broker groups rotate when
one refresh's scheduling budget cannot cover them all.

Wine Activity annotation also covers connected and unconnected UDP sockets. Each protocol/address-family table is independently bookended around the fresh kernel ownership census; an unconnected socket identifies no remote peer or direction. Ambiguous Windows holders remain unidentified. These display associations do not grant permissions: observed-rule creation still performs a fresh admission resolution. Closed TCP sockets without userspace owners remain unidentified.

Wine owner-table attribution can corroborate a launcher handoff whose command line still names the earlier executable: only an otherwise unresolved Wine process may use the runtime-reported image, with readable PE-header and nonzero-offset section mappings of that exact file and current revision (device/inode, or `map_files` file identity when the filesystem reports different devices), plus the existing same-prefix broker peer and process-generation rechecks. This does not turn command-line names into permission identities or transfer launcher permissions.

Direct Linux sockets opened by an otherwise unresolved Wine client (including native-library DNS) can use the schema-3 process-image census. Two complete runtime Windows PID/Linux PID/creation-time/image snapshots bookend fresh kernel socket/FD-owner verification. The runtime Linux PID must equal the actual socket owner in the same PID namespace, and the private read-only runtime list must agree with public process enumeration. The sole Linux owner must map the exact selected PE header and section file, and have a verified Unix peer of the pinned same-user, same-prefix Wine server. Missing, changing or multiple matching process images refuse attribution. Earlier helpers lack this capability and remain explicit; command lines and launcher names do not donate permissions.

For a full IPv6 socket with a nonzero inode, concrete IPv4-mapped local and remote endpoints in kernel inet_diag also prove dual-stack delivery when SKV6ONLY is omitted. Wildcard endpoints and partial/request socket rows do not provide that proof. Explicit v6-only diagnostics continue to reject IPv4 candidates.

### Optional runtime capability health

`doctor` probes Unix socket diagnostics, the facility used to verify Wine broker
peers, and checks for the running kernel's module tree. A missing tree is not
proof that a built-in capability is absent: the syscall result is reported
separately. With Wine enabled the daemon publishes `runtime_checks`, refreshed
every 30 seconds, and logs initial unavailable checks. Failure leaves the control
API and native protection available; Wine attribution still requires its normal
proof and fails closed. After a kernel upgrade that removed the running kernel's
modules, reboot into the installed kernel and repeat the probe.

Activity annotations skip new batches while Wine admission censuses are waiting
or running. An in-flight batch releases the broker lock during its full process/FD scan,
resumes only with a non-waiting lock attempt, and yields at helper/image
boundaries when admission arrives. Helper request/reply pairs remain serialized;
helper generation and session are rechecked before using either bookend. A
currently executing helper request is not interrupted. This reduces contention
but is not a latency guarantee.

The crash/startup guard deliberately remains fail-closed for new localhost
traffic: it cannot evaluate executable-specific local Ask/Block rules without
attribution. A blanket loopback guard exemption would bypass those explicit
rules. Default localhost delivery is a property of the active daemon path.

Essential preset executable-revision format migration is repaired at daemon
startup after fresh discovery and before protection restoration. Only unedited
records with a stale target hash and an identical currently derived permission
qualify. The record ID and filter stay unchanged; derived entry metadata and
version are updated atomically through the rule store, then logged per ID.
Changed executable identity, endpoint, peer service or scope requires normal
review. A failed save retains the old inactive records and emits a warning.

A protection activation/runtime refusal leaves the control daemon available in
failed/degraded state, with its fail-closed resources retained. Systemd readiness
means the control API is available, not that protection activated successfully.
The status and journal retain the refusal reason; an explicit Stop performs owned
cleanup and returns to monitoring. The daemon does not restart repeatedly merely
because activation was refused. Startup samples established sockets before the
conntrack dump to avoid comparing newly established sockets with an older dump;
a genuinely untracked established socket still refuses activation, naming its
endpoints and inode for diagnosis.


## Bounded Wine UDP dispatch hints

Wine UDP admissions may reuse a routing hint for at most 250 ms from its initial
native discovery, with 128 entries and at most 16 holders per entry. The key is
the full flow, direction and network namespace; link-local, native and hosted
cases are excluded. Only a complete positive Wine result seeds a hint, and hits
do not renew its age. A hint is not application evidence or permission: it clears
its application/association/table target and cannot bypass a fresh full kernel
socket/holder census, identical inode/cookie, broker generation, two equal runtime
owner tables, both holder-set checks and mapped image validation. Fresh holders
are published only after validation. A mismatch invalidates the hint and permits
one fresh initial lookup; incomplete results remain refused. Policy is evaluated
for every packet, including changed Allow/Deny/Ask rules. Queue, deadline and
snapshot-race limits remain unchanged. See [UDP attribution capacity](UDP-ATTRIBUTION-CAPACITY.md)
for measured receiver scope and remaining latency/overload limitations.


### Interim Wine census speedups (32-packet partition)

The runtime census lane admits at most 32 packets and 512 KiB within the
unchanged global 48-packet/1 MiB attribution budget. This leaves 16 packet
slots outside the census subset under Wine load; it does not promise lossless
overload. Per-endpoint waiting limits, deadlines and per-packet policy remain
unchanged. The experimental shared-observation implementation is not included.

Fresh holder enumeration may use an explicitly enabled, digest-pinned task_file
iterator helper. Startup probes compare its self-TID result with /proc. Each
table iteration remains fresh, unpinned and unattached to packet hooks. All
membership/generation/kcmp brackets, matched-FD rechecks and budgets remain;
unavailable capabilities or incomplete iterator results fall back to /proc.
API holder_enumeration reports the mechanism and fallback counts.

Wine helper/image scans skip only candidates excluded by existing necessary
conditions: complete generation-bracketed missing-prefix evidence, then exact
UID/namespace scope, then canonical prefix mismatch. Unknown reads take the
full inspection path. These are non-atomic observations, not ownership reuse.
Prefix canonicalization is performed only after scope checks. Existing mutable
environment/symlink races remain. Pre-existing missing-prefix normalization to
"." and potentially blocking prefix filesystem resolution remain separate
limitations; this release does not claim to repair them.


## Socket-bound authorization candidate (not release-approved)

The isolated candidate adds an explicit, default-off `serve
--socket-authorization` option. It requires `--allow-protection` and the
`socketprototype` build. It activates only within a continuous protection
session with the `both` profile. This documents candidate behavior; existing
installed launchers and host protection are unchanged.

Only verified, explicit application-rule Allows can authorize IPv4 UDP output.
A grant binds socket cookie, full local/remote tuple, direction, network
namespace and the output interface observed by NFQUEUE. A cookie is not owner
identity. Application/user/Wine-prefix proof and current policy remain mandatory.
The actual output interface is checked by a numeric nft `meta oif` match;
interface identity alone never supplies zone authority. A changed route misses
the old entry and returns to the queue. ECMP may therefore cause queue fallback.

The production connection path verifies identity and current policy initially,
then retains the exact authorized socket/destination/direction. It has **no
250 ms ownership-renewal deadline**. A temporary allowing rule still supplies a
hard BOOTTIME deadline in the kernel. Packet hits never extend that deadline.
Policy and zone publication revoke prior generations; new decisions use current
policy. A policy edit currently re-queues affected and other tracked tuples once.
An optional asynchronous check every five seconds per connection can revoke on
positive complete evidence of a different executable, user, prefix, revision or
socket cookie. Failed, slow or inconclusive checks do not remove authorizations
and established packets do not wait for them. There is no guaranteed ownership-
transfer detection bound: a recipient of an already-authorized socket can use
that exact destination until a confirmed change, socket close, policy/zone/link
revocation or temporary-rule expiry. This is deliberately different from the
previous 250 ms trial contract. Unknown or unverified new connections still queue.
A complete kernel UDP snapshot cleans closed cookies; an idle but live socket
is not expired. A new socket has a different cookie and cannot inherit a grant.

Deny, Ask, ambiguous ownership, unsupported traffic and exhausted capacity use
ordinary enforcement. TCP, IPv6 and incoming traffic remain on their existing
paths. At most 64 entries/eight per application and 32 fixed interface instances
are retained. Active IPv4 interfaces, preferring default routes, are selected at
session start; skipped or newly created links remain queued. Link identity
change or watcher uncertainty disables acceleration for the session; normal
carrier/MTU changes do not. Status advises a deliberate protection restart to
retry. Accelerator failure is optional degradation, not permission to stop the
firewall or accept unverified traffic.

The session installs fixed rules before recording its audited table digest.
The record selects the digest format; legacy records retain legacy semantics.
For the candidate format, only tagged socket-output numeric interface matches
are normalized against stable before/after interface snapshots. Ambiguous
snapshots are inconclusive, never silently accepted. Acceleration is disabled
on uncertainty; repeated uncertainty fails the audit. All other rule content
remains audited. Stop revokes before stopping the queue; resource release
follows confirmed owned-table deletion.

Known limitation: background checks compare application identity, not a handoff
to another instance of the same executable. That handoff can retain the prior
connection authorization, including its original process context, until socket
closure or an applicable policy/application-identity revocation. Process-instance
handoff detection is deferred; no bounded transfer-detection guarantee is made.

Rule edits re-evaluate each existing connection against the complete new policy
using its detached, initially verified identity and exact flow. Still-allowed
connections keep their grants; denied, unsupported or now-unmatched grants are
removed before the edit is acknowledged. A shorter temporary horizon is applied
in the kernel; an edit never extends the existing horizon. In-flight first
observations are invalidated separately from the kernel epoch. Zone/interface
changes and wholesale policy replacement retain conservative global revocation.

Normal protection activation also preserves already-confirmed connections via
the existing conntrack cutover mechanism, independently of socket grants. A
protection restart alone therefore does not prove those connections were
re-attributed or denied.

A daemon crash does not time-expire existing connection grants: already
authorized live tuples can continue until cleanup, socket close or a kernel
permission deadline. New tuples still queue without a listener and cannot inherit
permission. Recorded continuous recovery removes old kernel references before
a new session authorizes traffic.

The fast path skips attribution queueing only. Later admission, limits and
priority hooks must remain effective. Traffic accounting stays with the existing
collector/ledger; authorization counters are diagnostic totals, not additional
usage. The regular API publishes a compact, detached status snapshot without
waiting for the policy lock; detailed renewal/observer histories are excluded
from that periodic snapshot. Status is presentation, never authorization evidence.

Earlier finite 250 ms renewal trials are retained as historical evidence, not
acceptance for this connection-lifetime candidate. Receiver delivery, startup,
steady-state maximum added delay, loss and policy changes are rechecked on the
exact new candidate. Shaping/accounting and unchanged route/destination scopes
reuse unaffected evidence.

An isolated VM verified upload caps, a live cap edit, supported native TCP
download limits and TCP priority competition while UDP acceleration was active.
UDP download shaping is not supported by the existing shaper; UDP-versus-UDP
priority and Wine shaping were not established by that fixture. These finite
results do not establish an unconditional latency guarantee or final release
acceptance. CPU work and startup packet loss remain open. Startup delay is
accepted separately; startup packet loss has not been waived. Deployment requires
a separate exact candidate review and deployment approval. Connection-lifetime
ownership-transfer and crash behavior must be presented explicitly.

# Current status

Worktree `/home/flowgate-user/Apps/flowgate`, branch `milestone/backend`. This increment started at `1fd763921a25e5ba48c636c1abc2271d01653201`; use `git rev-parse HEAD` for the current snapshot. PLAN.md is the authoritative plan; HANDOFF.md contains the tracked continuation.

## Implemented in this increment

- Explicit opt-in Wine broker/client roles, preserving every descriptor holder. Configured executable identity, reciprocal Unix-socket peers, UID/namespaces/prefix and mapped client image corroborate the relationship. The client is the policy/API principal; the broker is not granted application permission.
- Direction-aware remembered filters (schema 2). Incoming: application revision/user/protocol, local service port, observed remote address, any source port. Outgoing retains destination address/service port. Legacy exact endpoint rules remain exact. API output previews `remembered_filter`.
- Bounded initial NFQUEUE retention without manual reinjection: 64 packets/1 MiB globally, 64 KiB per flow, four UDP datagrams or one SYN per flow; finite original deadline and fresh identity/rule revalidation before Allow. Unknown/expired/stale/error/overload cases never automatically Allow.
- Real PE inheritance and polling/plain TCP fixtures; focused unit, receiver and boundary tests.

## Directly verified

Local environment remains CachyOS x86-64, Wine 11.19. Matching wine-11.19 source was inspected; see WINE.md for the source/behavior distinction.

- `.workspace/wine-increment.log`: concurrent alpha.exe/beta.exe in one runtime/prefix; independent Allow/Block, reversed decisions, receiver verification. UDP single-send delivery passed. TCP passed **only for the explicitly labelled FIONREAD variant with visible client FD**. Structured evidence: `.workspace/run/wine-increment-evidence.json`.
- `.workspace/wine-boundary.log` and `.workspace/run/wine-boundary.json`: plain TCP broker-only listener denied; two materialized inherited clients remain ambiguous; no shared traffic delivery; materializing a second client invalidates a pending answer; parent exit while child is dormant leaves broker-only attribution denied. Dormant inheritance is a proven limit of FD snapshots.
- `.workspace/scope-retention.log`: sender transmits UDP exactly once and closes; timely Allow delivers, Block/timeout deliver nothing, listener replacement rejects the stale answer, per-flow retention delivers four of eight UDP datagrams, and shutdown drops a retained datagram. A genuinely new incoming TCP connection with a changed client port matches a remembered permission; different service port or remote address remains controlled.
- `.workspace/native-increment.log`: original receiver matrix rerun after the queue/identity changes (not before investigation): TCP/UDP IPv4/IPv6, timeout/stale/retry, different executable reusing a service port, shared ports, bounded repeated attempts and absent queue consumer.
- `.workspace/outgoing-increment.log`: original outgoing TCP/UDP receiver checks passed.
- `.workspace/increment-unit.log` and `.workspace/increment-unit-final.log`: race-enabled unit/API tests, retention packet/byte bounds, retransmission handling, error/shutdown drains, expiry, stale relationship, rule invalidation, direction-aware scopes and legacy exact endpoint behavior. `go vet ./...` passed.

Reproduce the increment sequentially with `scripts/check-increment.sh`. The original conservative Wine baseline still runs through `scripts/check.sh --wine`; it does not enable the opt-in broker model. Keep generated evidence under `.workspace`; do not run scripts sharing the default API socket concurrently.

## Remaining observation boundary

**Universal transparent Wine attribution is not complete.** `FLOWGATE_WINE_BROKER` is disabled by default because a dormant inherited Windows handle can be absent from `/proc` while the original client and broker remain visible. Opt-in mode assumes ordinary non-sharing handles, visible client FDs and an unmodified selected Wine runtime; its evidence is not a complete Windows handle census. Plain server-only TCP listeners remain unidentified. The bounded improvement is independent control of the tested visible-client path, not every Wine program or game.

No real Proton/game, Heroic/Lutris/Bottles, Flatpak, VPN, arm64 or other-distribution claim. Direct WSADuplicateSocket execution, adversarial FD transfers and production throughput remain unverified. No Qt, durable SQLite, bandwidth shaping, host service installation or broad packaging was added. The baseline default binary's libc/libresolv dependency remains; no new native dependencies were introduced.

## Host state and next step

No host firewall rules, network configuration, services, launcher settings or existing prefixes were changed. Tests used disposable namespaces and `.workspace/wine-prefix`; namespace feature use can autoload kernel modules. No additional privileges were requested.

Next smallest step: optionally isolate a fresh launch/server/network namespace to support broker-only listeners, or observe the missing Wine server handle-reference lifecycle explicitly. See WINE.md for exact limits. Do not turn a broker name exception into a supposed solution to dormant sharing.

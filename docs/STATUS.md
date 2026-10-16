# Current status

Worktree `/home/flowgate-user/Apps/flowgate`, branch `milestone/backend`. The current experiment started at `8783ff6add4fa73691e4bb2367d6aa2a523e5f8e`; use `git rev-parse HEAD` for the current snapshot. PLAN.md is the authoritative plan; HANDOFF.md contains the tracked continuation.

## Current increment: runtime attachment and IPv6

Implemented read-only `runtime-discover` and explicit `serve-lab --attach-prefixes`
for up to four already-running workspace runtime sessions. Runtime bin directories
are caller-selected; supported broker builds are hash-pinned. Attachment requires
the caller's UID/namespaces, an initialized workspace prefix/TMPDIR, live broker
generation and reciprocal helper peer evidence. It disables server creation,
executes no metadata commands, and performs no automatic retry/recovery. Each
prefix has a separate observer; prefix identity is not a game-session identity.

On both Wine 11.19 and direct dwproton-11.0-4 / Wine 11.0:

- Actual WSADuplicateSocket: one original holder; two at preparation **before**
  recipient WSASocket; two after construction; one after original close; zero
  after final close. Recipient receives after original close.
- Preparation invalidates retained UDP approval. Constructed shared receivers get
  no data. Actual numeric handle reuse was observed (52 Wine / 60 Proton in the
  recorded focused runs); a new kernel socket generation rejects the old packet.
- Approved TCP continues after accepted-socket transfer, as required by the new
  explicit connection-initiation contract. Rule changes do not disconnect existing
  approved TCP; no revocation behavior was changed.
- Late attachment to two concurrent prefixes; same executable and reused service
  port in the second prefix do not inherit the first prefix's permission.
- Wineserver death/restart invalidates pending/session evidence; explicit daemon
  restart/reattachment creates new observer generations and rejects old IDs.
- Ordinary IPv6 TCP and one-shot UDP independent Allow/Block and reversal;
  dual-stack wildcard over both wire families; IPv4-mapped IPv6 binds; separate
  IPv6-only/IPv4 applications sharing a service port.

Final reproducible runner: `scripts/check-runtime.sh`, once without Proton env and
once with the two runtime-selection variables shown in WINE.md. Latest evidence:

- `.workspace/runtime-final-{wine,proton}.log`: sequential builds, race tests, vet,
  duplication, attachment/restart and IPv6 receiver checks.
- `.workspace/run/{wine,proton}-{duplication,attachment,ipv6}.json`: structured
  evidence, including generations, ownership stages and distinct application keys.
- `.workspace/attachment-{wine,proton}.log`: final attachment-path helper-exit
  extension, explicit recovery, cross-prefix port reuse and server restart.
- `.workspace/runtime-native-regression.log`: native incoming regression after
  changes to shared socket-family matching; unchanged scope/retention/outgoing
  evidence below remains reusable.
- `.workspace/runtime-unit.log`: malformed/schema/family/build responses, sticky
  failure, scoped-address rejection, v6-only candidates and workspace boundaries.
  Actual attached-helper exit and server-loss/recovery are both exercised.

Limits: link-local Wine policy needs an explicit interface-index mapping and stays
unsupported. These are loopback namespace tests, not full UMU/Steam/container or
real-game validation. Discovery does not attach or initialize anything; attachment
is explicit and restricted to workspace test sessions. There is no production host
enforcement, general cross-user helper launcher, GUI or continuous TCP ownership
reauthorization. See HANDOFF.md for the next prompt-client step.

## Previous snapshot: optional runtime census

Implemented a lab-only public Wine owner-table helper/adapter. Ordinary TCP and
one-shot UDP independently Allow/Block alpha/beta, reversed, on installed Wine
11.19 and dwproton-11.0-4 (Wine 11.0). Windows handle holders remain distinct from
raw Unix FD holders. Shared dormant handles deny single-application permission.
No target/runtime modifications, tracing privileges or default launch isolation.
See WINE.md for precise startup, build, snapshot and established-TCP limits.

Evidence (generated, not committed):

- `.workspace/table-enforcement-final.log`, `.workspace/table-proton-enforcement.log`:
  receiver-based ordinary TCP and UDP, both decision directions. Structured output
  `.workspace/run/{wine,proton}-table-enforcement.json`.
- `.workspace/table-{wine,proton}-lifecycle.log` and corresponding
  `.workspace/run/{wine,proton}-table-lifecycle.json`: late startup, dormant TCP/UDP
  handle census, parent exit, child receiver delivery, shared dormant listener
  denial, stale listener approval, observer disconnect with retained UDP.
- `.workspace/table-unit.log`: race-enabled internal tests and vet; row filtering,
  multiple-holder preservation, missing generations and stopped/unsupported observer.
- `.workspace/table-native-regression.log`: native incoming IPv4/IPv6 TCP/UDP,
  permission isolation, replacement, timeout, shared ports, bounds and daemon loss.
  Rerun because the authorization principal representation changed. Existing
  direction-aware scope/retention/outgoing evidence below is reusable.

Reproduce with WINE.md commands. The adapter remains explicitly optional, selected
for one server/prefix in a lab daemon. Numeric Windows handle reuse,
WSADuplicateSocket and server-restart recovery remain unverified. No real games.

## Prior increment (preserved)

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

## Earlier FD-only observation boundary (still applies without table adapter)

**Universal transparent Wine attribution is not complete.** `FLOWGATE_WINE_BROKER` is disabled by default because a dormant inherited Windows handle can be absent from `/proc` while the original client and broker remain visible. Opt-in mode assumes ordinary non-sharing handles, visible client FDs and an unmodified selected Wine runtime; its evidence is not a complete Windows handle census. Plain server-only TCP listeners remain unidentified. The bounded improvement is independent control of the tested visible-client path, not every Wine program or game.

No real-game, Heroic/Lutris/Bottles, Flatpak, VPN, arm64 or other-distribution claim. The installed dwproton fixture coverage is described above. Direct WSADuplicateSocket execution, adversarial FD transfers and production throughput remain unverified. No Qt, durable SQLite, bandwidth shaping, host service installation or broad packaging was added. The baseline default binary's libc/libresolv dependency remains; no new native dependencies were introduced.

## Host state and next step

No host firewall rules, network configuration, services, launcher settings or existing prefixes were changed. Tests used disposable namespaces and `.workspace/wine-prefix` / `.workspace/proton-prefix`; namespace feature use can autoload kernel modules. No additional privileges were requested.

Next smallest step: implement a minimal unprivileged native prompt client over the
existing authenticated pending/decide API, first against these isolated sessions.
Keep daemon-owned pending state, scope previews, stale rejection and separate
monitor/policy permissions. Production host enforcement remains a separate task.

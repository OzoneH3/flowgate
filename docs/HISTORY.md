# Historical backend evidence

Archived pre-desktop status. Sections below describe their recorded snapshots,
including limitations subsequently resolved. Current capabilities and limits are
in [STATUS.md](STATUS.md). Logs remain under `.workspace`; they are not committed.

# Pre-desktop snapshot

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


# Accepted desktop prompt milestone (4e1303e)

User confirmed the demo works. The following pre-host status is historical;
current capabilities are in STATUS.md. Its evidence remains reusable.

## Desktop capabilities

- Async authenticated Unix API polling; explicit connected/disconnected/reconnecting,
  read-only and isolated-lab status. Backend generation resets session history.
- Persistent pending table, selectable plain-text details, resizable columns,
  full executable/IPv6 endpoints, attribution/reason, countdown and backend scope.
- One non-modal prompt, deduplicated notifications, default Once, Allow/Block and
  accurate one-hour memory-only remembered permission. Backend acknowledgement
  precedes success. Errors also appear in the prompt.
- Stable request-ID selection, disabled duplicate/disconnected/read-only actions,
  authoritative refresh and no automatic answer replay. Closing the client does
  not affect enforcement.
- Recent client-observed events bounded to 256/8 MiB; responses capped at 4 MiB,
  eight concurrent decisions, one poll in flight, finite I/O deadlines. No durable
  history, notification service, tray, full application tree or installed service.
- One-command demo uses native one-shot UDP, private mode-0700 run directory and
  mode-0600 sockets, a 60-second lab timeout, and scoped cleanup on terminal exit.
  The ordinary host user is correctly mapped to the same user inside the lab's
  user namespace; no authorization exception or display-access relaxation.

## Direct verification this increment

Qt 6.12.0/CachyOS x86-64, **actual Wayland platform**, ordinary UID 1000 client:

- Real pending datagram reaches no receiver before approval; prompt Allow delivers
  it without retry; main-window Block (keyboard activation) delivers nothing.
- Remembered Allow admits a subsequent one-shot datagram with a different source
  port. Separate local service ports still prompt.
- Prompt dismissal/expiry delivers nothing; stale API answer rejected. Read-only
  monitor disables mutation. Client closure retains pending traffic; reconnect
  refreshes state; backend loss disables main and prompt buttons with no delivery.
- Synthetic metadata/error tests: long selectable paths, literal untrusted markup,
  full IPv6 endpoints, keyboard traversal, notification deduplication, unauthorized
  response and reconnect/new generation without decision replay.
- Rendered main window and prompt inspected via QWidget captures from the real
  Wayland run. These are application captures, not compositor screenshots. The
  long-path/IPv6 presentation check uses synthetic metadata; final window size
  is also subject to the compositor. Inspected Wayland captures are 1040×740.
- Focused daemon/policy race tests and `go vet ./...`; unchanged native matrix and
  Wine/runtime evidence reused. No new Wine/game compatibility claims.

Evidence: `.workspace/desktop-final.log`, `.workspace/desktop-wayland.log`, `.workspace/desktop-go.log`,
`.workspace/desktop-build.log`, `.workspace/desktop-demo-smoke.log`, and `.workspace/desktop-test-PID/` receiver logs
and screenshots. Reproduce: `QT_QPA_PLATFORM=wayland WAYLAND_DISPLAY=wayland-0
scripts/check-desktop.sh` (one shell line); offscreen fallback is explicitly labelled.

Convenience captures: `.workspace/desktop.png`, `.workspace/desktop-prompt.png`
and `.workspace/desktop-long-ipv6.png`. The standalone demo command was also
launched on Wayland, accepted terminal repeat-attempt input, and cleaned up on q.

## Preserved backend capabilities and limits

Native isolated TCP/UDP IPv4/IPv6 enforcement, incoming direction-aware remembered
scope, bounded NFQUEUE retention and authenticated policy/monitor API remain.
Optional Wine 11.19 and direct dwproton-11.0-4 adapters retain verified ordinary
listeners, inheritance/duplication, restart recovery, two-prefix attachment and
IPv6/dual-stack behavior. See WINE.md and [historical evidence](HISTORY.md).

TCP permissions authorize initiation; existing accepted connections are not
continuously reauthorized or disconnected by rule changes. Runtime snapshots
retain their documented race/threat-model limits. Scoped link-local Wine policy,
real games, full UMU/Steam/container behavior, VPN coexistence, other distributions
and arm64 remain unverified. No host firewall/network/security/services, installed
runtimes, existing prefixes or launcher settings were changed.

# Current status

Branch `milestone/backend`; use `git rev-parse HEAD` for the current snapshot.
**A running native Qt 6 desktop client now controls the real isolated backend.**
Launch from the repository root with `scripts/demo-desktop.sh`.

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

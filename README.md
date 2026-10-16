# FlowGate

A native Qt 6 desktop application with an independent Go backend. **Normal launch shows real host application/socket activity read-only.** No firewall rules, interception or host protection. The accepted prompt workflow remains a separate isolated lab.

## Explicit host firewall evaluation (opt-in)

The new incoming-first controller is implemented and verified in disposable
namespaces. **It has not been activated on this host.** Review
[the activation, Stop and recovery contract](docs/HOST-CONTROL.md) before running:

```sh
scripts/evaluate-host.sh  # explicit host activation; automatic stop after 5 minutes
# In a second, ordinary-user terminal:
.workspace/desktop/flowgate-desktop --socket /run/flowgate-api/control.sock
```

Saved one-hour and persistent permissions, a basic Rules list and Disable/Delete
are available in this mode. Normal launch below remains read-only. No GUI sudo,
service installation or implicit activation. Existing VPN/mark configurations can
cause a deliberate preflight refusal.

## Launch the live host monitor

```sh
scripts/run-desktop.sh
# Optional collection delay (default 2s; range 500ms–30s):
scripts/run-desktop.sh --interval 3s
```

No synthetic traffic is generated. Expand applications into processes and sockets;
search names, paths, PIDs or endpoints; sort/filter; select full details and copy
fields. Shared sockets appear once; unidentified sockets remain individual entries.
UDP is labelled bound or connected. Initiation direction is **Unknown**.

**Stop:** close the window, or press **Ctrl+C in its launching terminal**. The
launcher stops only its observer and removes its private socket. Every launch uses
an independent mode-0700 `.workspace/host-monitor-*` directory; duplicate launches
never unlink another socket. Logs remain. No service, autostart or root is needed.
This differs from the lab, which keeps enforcing after its GUI closes.

Visibility is limited by the current user, proc access and current network namespace.
Owners can be inaccessible or gone. The UI reports partial coverage and collection
errors; observation never produces Allowed events or enables policy actions. No Wine
helper starts or attaches to a game prefix. Rates and domain/location data are not
invented. See [visual references and differences](docs/VISUAL.md) for the NetLimiter 5
layout target, recreated with our Qt components and FlowGate branding.

For a separately managed observer (stop with Ctrl+C):

```sh
. scripts/go-env.sh
mkdir -p .workspace/my-monitor
chmod 700 .workspace/my-monitor
.workspace/flowgate observe --socket "$PWD/.workspace/my-monitor/control.sock" --interval 2s
# Another terminal:
.workspace/desktop/flowgate-desktop --socket "$PWD/.workspace/my-monitor/control.sock"
```

An existing socket is refused. Use another private directory rather than deleting
another process's socket. Closing a separately connected client leaves that observer running.

## Launch the desktop demo (explicit enforcement lab)


From the repository root:

```sh
scripts/demo-desktop.sh
```

Requires Qt 6 Widgets/Network/Test development files, CMake, a C++17 compiler,
Go >=1.24 and Python 3. The **lab only** also requires nftables, util-linux `unshare`
and iproute2. These dependencies
are available on the tested CachyOS x86-64 host. No package installation is performed.
A graphical session is required; the script uses the current display, or this
user's existing `wayland-0` socket if display variables are absent.

The command builds both programs, creates a private disposable namespace, starts
native UDP receivers and the real daemon, then opens the unprivileged desktop
client **outside** that namespace. One datagram is sent exactly once. A native
non-modal prompt and the persistent pending list show its application, endpoints,
attribution, deadline and backend-provided permission scope.

- Choose **Allow** to release the retained datagram, or **Block** to drop it.
- **Once** is the default. **Remember · 1 hour (memory only)** uses the exact
  application/revision/user/protocol/direction/address/service-port preview.
- Press **Enter in the launching terminal** for another attempt. Type **2–8** for
  a different local service port, which remains subject to its own permission.
- The terminal prints the private run directory. `receiver-41001.log` gains
  `RECEIVED` only upon delivery. No payload is logged.
- Lab prompts last **60 seconds**. The backend default remains 15 seconds.
- Closing/dismissing a prompt grants nothing. Closing the window leaves the lab
  enforcing. Type **q** or press **Ctrl+C in the terminal** to clean up its processes
  and namespace. Only this demo's objects are removed; logs remain in `.workspace`.

To build and connect to an existing private lab API:

```sh
scripts/build-desktop.sh
.workspace/desktop/flowgate-desktop --socket /absolute/private/directory/control.sock
# Use control.sock.monitor for read-only monitoring.
```

The socket field plus **Connect** changes the selected endpoint. A disconnected
client disables decisions and refreshes state on reconnect, without replaying
answers. Recent decisions are bounded **client-observed, current-backend-session**
history, not an audit log. The backend remains authoritative.

## Focused host-monitor checks

```sh
QT_QPA_PLATFORM=wayland WAYLAND_DISPLAY=wayland-0 scripts/check-monitor.sh
# Automated fallback, not a real display check:
QT_QPA_PLATFORM=offscreen scripts/check-monitor.sh
```

Tests use workspace native loopback fixtures for TCP listening/connecting/established,
IPv4/IPv6, UDP bound/connected, shared descriptors, process exit and path identities.
They check mutation denial and Qt search/filter/sort/selection/copy/reconnect. Only
one existing lab Allow smoke runs for shared UI/API changes; accepted Wine/native
matrices are reused. Evidence remains in `.workspace`.

## Focused desktop checks

```sh
QT_QPA_PLATFORM=wayland WAYLAND_DISPLAY=wayland-0 scripts/check-desktop.sh
# Without a graphical session (automated checks only):
QT_QPA_PLATFORM=offscreen scripts/check-desktop.sh
```

Qt tests click actual prompt/main-window buttons against the real namespace
backend and inspect receiver logs. They also check remembered scope, expiry,
read-only mode, disconnect and client closure. Generated screenshots/logs live in
`.workspace/desktop-test-PID/`. Synthetic metadata tests cover long paths, IPv6
rendering and API errors; they are not additional network-family validation.

## Backend and runtime adapter

```sh
. scripts/go-env.sh
go build -o .workspace/flowgate ./cmd/flowgate
.workspace/flowgate doctor
.workspace/flowgate sockets
.workspace/flowgate pending --socket /absolute/private/directory/control.sock
```

The core has no Qt, KDE, graphical-session, systemd, NetworkManager or cloud
dependency. Its authenticated v1 Unix API preserves separate monitor and mutation
permissions. Incoming remembered rules use the remote address and local service
port, unrestricted client source port; outgoing rules preserve destination scope.
TCP authorization controls connection initiation, not continuous ownership or
forced disconnection of admitted connections. See [semantics](docs/SEMANTICS.md).

The optional existing Wine/Proton owner-table adapter is preserved. Ordinary
IPv4/IPv6 TCP/UDP fixtures, dormant handles, duplication and explicit test-session
attachment were verified on the builds documented in [WINE.md](docs/WINE.md).
It is disabled by default; real games and full UMU/Steam/container integration
remain unverified. This desktop increment does not launch Wine or games.

[Current status](docs/STATUS.md) · [Plan](docs/PLAN.md) ·
[Handoff](docs/HANDOFF.md) · [Historical evidence](docs/HISTORY.md)

Desktop branding: CMake `-DFLOWGATE_PRODUCT_NAME=NewName`. CLI branding:
`go build -ldflags '-X main.productName=NewName'`. Binaries use native shared
libraries; no static/portable deployment claim. Other distributions and arm64
remain unvalidated. Durable rules and bounded manual host enforcement are now implemented; production
service integration, wider coexistence, packaging, charts and bandwidth control remain deferred.

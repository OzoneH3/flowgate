# Qt development client

Run these commands from the repository root. The client opens in read-only
mode. Host evaluation and the isolated enforcement lab are explicit actions.

## One window: Activity and optional five-minute control

```sh
scripts/run-desktop.sh
```

Activity opens read-only. Select **Incoming connections** (default) or **Incoming and outgoing connections**,
then click **Start 5-minute evaluation**, read the short
explanation, then authenticate with system sudo in the launched Konsole terminal.
The same window attaches only after the controller's generation and active API
state are verified. Activity continues through a separate read-only connection.

Use Pending & recent decisions for Allow/Block and Rules for saved permissions,
**Create rule…** from a pending request, then **Edit**, Enable, Disable and Delete.
The structured prompt separates source/destination ports; the editor previews exact
application/revision/UID scope and expiry before saving. See [rule semantics](../docs/RULES.md).
Outgoing control holds new native TCP/UDP while awaiting approval; it is opt-in. **Stop evaluation** opens terminal authentication
and reports stopped only after confirmed cleanup. Closing the window leaves an
active evaluation running under its original deadline. **Status / recovery…**
provides the independent privileged check/recovery path; disconnect means unknown.

**This development launcher activates nothing until explicitly requested.** Start requires installed Konsole, Python 3 and an existing sudo
policy permitting the controller command. Qt never collects a password. Refusals
and cancelled authentication leave Activity available. See
[the exact activation, Stop and recovery contract](../docs/HOST-CONTROL.md).

The terminal alternative for bounded evaluation remains `scripts/evaluate-host.sh`.
That path does not install a service or change sudoers. Separately, the prepared
release installer installs the persistent FlowGate daemon in monitoring mode;
`update-and-start.sh` can restore an explicitly selected protection mode after
verification. See [deployment and rollback](../docs/DAILY-DEPLOYMENT.md).

## Launch the live host monitor

```sh
scripts/run-desktop.sh
# Optional collection delay (default 1s; range 500ms–30s):
scripts/run-desktop.sh --interval 3s
```

No synthetic traffic is generated. Observation and control have independent status
indicators. Expand applications into processes and sockets;
search names, paths, PIDs or endpoints; sort/filter; select full details and copy
fields. Shared sockets appear once; unidentified sockets remain individual entries.
UDP is labelled bound or connected. Initiation direction is **Unknown**.

**Stop:** close the window, or press **Ctrl+C in its launching terminal**. The
launcher stops only its observer and removes its private socket. Every launch uses
an independent mode-0700 `.workspace/host-monitor-*` directory; duplicate launches
never unlink another socket. Logs remain. No service, autostart or root is needed.
An explicitly started evaluation also keeps enforcing after the GUI closes, until
Stop or its original five-minute deadline. The observer alone belongs to this launcher.

Visibility is limited by the current user, proc access and current network namespace.
Owners can be inaccessible or gone. [Native ownership details](../docs/ATTRIBUTION.md)
explain categories and bounded recovery for sockets retained after main-thread exit. The UI reports partial coverage and collection
errors; observation never produces Allowed events. Decision controls require an
authenticated, active control connection. No Wine
helper starts or attaches to a game prefix. Real TCP IPv4/IPv6 payload rates and observed-byte totals appear in Activity.
UDP metrics show unavailable; partial aggregates carry `*`. Unidentified sockets
share one collapsible presentation group, with individual evidence in details.
See [traffic accounting](../docs/TRAFFIC.md). An optional
[UDP collector experiment](../docs/UDP.md) and explicit Activity Enable/Stop actions
are implemented. Isolated UDP4/6 receiver, lifecycle and actual Wayland-rate checks passed.
Build the optional collector with `scripts/build.sh udp`, then explicitly enable
extended monitoring in Activity; Stop affects collection only.
Read UDP.md before host use. Domain/location data are not invented. See [desktop presentation and verification](../docs/VISUAL.md).

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
- Lab prompts last **60 seconds**. The `serve` and `host-start` default to 30 seconds; `serve-lab` defaults to 15 seconds.
- Closing/dismissing a prompt grants nothing. Closing the window leaves the lab
  enforcing. Type **q** or press **Ctrl+C in the terminal** to clean up its processes
  and namespace. Only this demo's objects are removed; logs remain in `.workspace`.

To build and connect to an existing private lab API:

```sh
scripts/build.sh desktop
.workspace/desktop/flowgate-desktop --socket /absolute/private/directory/control.sock
# Use control.sock.monitor for read-only monitoring.
```

The socket field plus **Connect** changes the selected endpoint. A disconnected
client disables decisions and refreshes state on reconnect, without replaying
answers. Recent decisions are bounded **client-observed, current-backend-session**
history, not an audit log. The backend remains authoritative.

## Focused integrated workflow checks

```sh
QT_QPA_PLATFORM=wayland WAYLAND_DISPLAY=wayland-0 scripts/checks/check-unified.sh
```

The real controller runs only in disposable veth namespaces. Qt exercises the
same-window Activity/control workflow, receiver delivery, saved-rule expiry and
re-enable, Stop, timeout, loss, notifications and closure. Authentication is a
narrow simulated seam; a separate terminal-bridge check uses a simulated sudo
command with the real namespace controller. Actual host sudo activation remains
for explicit user evaluation. Existing protocol and Wine evidence is reused.

## Focused host-monitor checks

```sh
QT_QPA_PLATFORM=wayland WAYLAND_DISPLAY=wayland-0 scripts/checks/check-monitor.sh
# Automated fallback, not a real display check:
QT_QPA_PLATFORM=offscreen scripts/checks/check-monitor.sh
```

Tests use workspace native loopback fixtures for TCP listening/connecting/established,
IPv4/IPv6, UDP bound/connected, shared descriptors, process exit and path identities.
They check mutation denial and Qt search/filter/sort/selection/copy/reconnect. Only
one existing lab Allow smoke runs for shared UI/API changes; accepted Wine/native
matrices are reused. Evidence remains in `.workspace`.

## Focused desktop checks

```sh
QT_QPA_PLATFORM=wayland WAYLAND_DISPLAY=wayland-0 scripts/checks/check-desktop.sh
# Without a graphical session (automated checks only):
QT_QPA_PLATFORM=offscreen scripts/checks/check-desktop.sh
```

Qt tests click actual prompt/main-window buttons against the real namespace
backend and inspect receiver logs. They also check remembered scope, expiry,
read-only mode, disconnect and client closure. Generated screenshots/logs live in
`.workspace/desktop-test-PID/`. Synthetic metadata tests cover long paths, IPv6
rendering and API errors; they are not additional network-family validation.

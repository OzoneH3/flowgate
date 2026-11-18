# FlowGate

FlowGate is an application firewall and socket monitor with an independent Go
backend, an Electron desktop, and a Qt development client. The installed root
service supports continuous incoming or incoming-and-outgoing protection;
desktop clients run unprivileged. Saved permissions belong to verified
applications, users and supported Wine prefixes, not their launchers.

## Install or update a release

The [standalone package workflow](docs/STANDALONE-RELEASE.md) uses `make package`,
`make preflight`, `make install`, `make recover` and `make uninstall`.
The checkout-based commands below remain available for development.

Run from a clean, committed `master` checkout:

```sh
# Preview a local update without preparing or installing a bundle:
./scripts/update-and-start.sh --local --profile preserve --dry-run
# Prepare, check, install, verify, and relaunch the GUI:
./scripts/update-and-start.sh --local --profile preserve
```

`--local` skips upstream access. `--profile preserve` keeps the existing protection
mode; on a new installation it selects monitoring. Omitting `--profile` also
preserves the mode. To explicitly enable Both from another mode, use
`--profile both --acknowledge-outgoing-blocking` after reviewing Essential
networking and root-local recovery. Continuous protection has no automatic
countdown; no DNS/DHCP/service permissions are added automatically. Preparation and candidate
compatibility checks precede stopping the current protection. Authentication uses
sudo or the optional [passwordless local update helper](#passwordless-local-updates).

To prepare without installing, use `scripts/prepare-release.sh`. Its matched
backend and Electron bundles live under `.workspace/`. For a deliberate
monitoring-only installation, use `python3 scripts/install-prepared.py --bundle PATH`
with the backend bundle printed by preparation. See
[deployment and rollback](docs/DAILY-DEPLOYMENT.md) and
[current command options](scripts/README.md).

The installer provides `flowgate.service` and its startup guard. Protection state
is separate from service state: a running daemon can be monitoring, active,
starting or degraded. Check the GUI's reported state rather than assuming that a
running service means protection is active. Closing the GUI does not stop the
installed daemon or its protection. Explicit Stop returns to monitoring; a
failure can retain fail-closed interception until recovery.

Source HEAD, the installed daemon and the running GUI may differ. The GUI header
shows its release and recorded build date/time and flags a different daemon
build. Use `flowgate version` on the specific binary being inspected; historical
host states in the linked evidence documents are not current status reports.

Maintained source/operational scope: [STATUS.md](docs/STATUS.md).

## Connect to the installed daemon

```sh
scripts/run-electron.sh --daemon /run/flowgate-api/daemon.sock
```

This development launcher builds the checkout's Electron client and attaches to
the existing daemon and companion monitor socket. It does not install a release
or start protection. The released GUI is launched by the updater. Activity,
prompts and stored-rule operations depend on the authenticated account's
capabilities. The root daemon grants machine administration to its configured
administrator UID; clients do not gain authority from their display labels.
See [authorization](docs/AUTHORIZATION.md).

## Network compatibility

Compatibility checks inspect live interfaces, firewall rules, queues and routing
marks without vendor-specific exemptions. TUN traffic remains subject to ordinary
application rules. WireGuard and XFRM interfaces are currently refused; conflicting
or unprovable mark operations also refuse activation. Passing preflight is not a
guarantee for every VPN configuration or a forwarded-traffic enforcement claim.
The old `tailscale-inspect` command has been removed. Use the diagnostics below.

## Diagnose before explicit activation

```sh
. scripts/go-env.sh
go build -o .workspace/flowgate ./cmd/flowgate
.workspace/flowgate doctor
.workspace/flowgate doctor --json
```

Doctor is read-only, never requests sudo or starts enforcement/collection.
“Ready” applies only to the named completed check; “Not checked” includes privilege
and intentionally unattempted queue/BPF attachment. Activation additionally requires the selected profile to pass live compatibility
checks. A read-only diagnostic result does not itself activate protection.
See [diagnostics and actionable startup errors](docs/DIAGNOSTICS.md) for the exact
optional user-run privileged inspection command and existing Stop/recovery paths.

## Development desktop clients

```sh
scripts/run-electron.sh
# Qt observer / bounded evaluation client:
scripts/run-desktop.sh
```

Without an existing daemon/controller argument, these launchers start their own
read-only observer. They do not install a service or automatically enable
protection. Electron provides Activity, live charts, pending requests, saved-rule
editing, decision history, and capability-gated protection controls.

**Keep running in the tray** defaults to enabled for new preferences; an explicit
opt-out is preserved. With it enabled, closing the main window hides it.
**Quit FlowGate…** exits the client and cleans up its owned observer, while an
independent daemon continues running. See [Electron behavior](electron/README.md).

The Qt client has a smaller workflow set; it is not feature-equivalent to
Electron. Both clients use conditional rule deletion. Qt preserves exact uint64
versions; Electron refuses versions above JavaScript's safe integer range rather
than submitting rounded values. Neither automatically retries deletion.

The following observer and Qt evaluation instructions describe development and
isolated test workflows, separately from the installed service above.

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
application/revision/UID scope and expiry before saving. See [rule semantics](docs/RULES.md).
Outgoing control holds new native TCP/UDP while awaiting approval; it is opt-in. **Stop evaluation** opens terminal authentication
and reports stopped only after confirmed cleanup. Closing the window leaves an
active evaluation running under its original deadline. **Status / recovery…**
provides the independent privileged check/recovery path; disconnect means unknown.

**This development launcher activates nothing until explicitly requested.** Start requires installed Konsole, Python 3 and an existing sudo
policy permitting the controller command. Qt never collects a password. Refusals
and cancelled authentication leave Activity available. See
[the exact activation, Stop and recovery contract](docs/HOST-CONTROL.md).

The terminal alternative for bounded evaluation remains `scripts/evaluate-host.sh`.
That path does not install a service or change sudoers. Separately, the prepared
release installer installs the persistent FlowGate daemon in monitoring mode;
`update-and-start.sh` can restore an explicitly selected protection mode after
verification. See [the current audit status](docs/NETLIMITER-AUDIT-2026-10-23.md#follow-up-status--23-october-2026-after-installation).

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
Owners can be inaccessible or gone. [Native ownership details](docs/ATTRIBUTION.md)
explain categories and bounded recovery for sockets retained after main-thread exit. The UI reports partial coverage and collection
errors; observation never produces Allowed events. Decision controls require an
authenticated, active control connection. No Wine
helper starts or attaches to a game prefix. Real TCP IPv4/IPv6 payload rates and observed-byte totals appear in Activity.
UDP metrics show unavailable; partial aggregates carry `*`. Unidentified sockets
share one collapsible presentation group, with individual evidence in details.
See [traffic accounting](docs/TRAFFIC.md). An optional
[UDP collector experiment](docs/UDP.md) and explicit Activity Enable/Stop actions
are implemented. Isolated UDP4/6 receiver, lifecycle and actual Wayland-rate checks passed.
Build the optional collector with `scripts/build.sh udp`, then explicitly enable
extended monitoring in Activity; Stop affects collection only.
Read UDP.md before host use. Domain/location data are not invented. See [visual references and differences](docs/VISUAL.md) for the NetLimiter 5
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

The packaged daemon includes the Wine/Proton owner observer. Its runtime and
prefix selection follows the installed configuration; supported runtime discovery
can launch an observer in an existing prefix. The standalone read-only observer
launcher is a separate mode. Runtime support is capability/build-gated, and
missing or ambiguous ownership remains explicit. Helper lifecycle coverage does
not prove every runtime's full attribution path or every game launch. See the
current integration and observer-lifetime sections of [WINE.md](docs/WINE.md).

[Current status](docs/STATUS.md) · [Plan](docs/PLAN.md) ·
[Handoff](docs/HANDOFF.md) · [Historical evidence](docs/HISTORY.md)

Desktop branding: CMake `-DFLOWGATE_PRODUCT_NAME=NewName`. CLI branding:
`go build -ldflags '-X main.productName=NewName'`. Binaries use native shared
libraries; no static/portable deployment claim. Other distributions and arm64
remain unvalidated. Durable rules, continuous service protection, matched release
packaging and live charts are implemented. Charts contain bounded observation
history, not a durable usage ledger. Bandwidth rate limits, QoS, quotas and
recurring schedules remain unimplemented. TCP rules govern new admissions;
changing a rule to Block does not terminate already-admitted TCP connections.

### Passwordless local updates

To authorize the current desktop account once, run from this checkout:

```sh
sudo /usr/bin/python3 -I scripts/setup-passwordless-update.py
```

This installs a root-owned `/usr/local/libexec/flowgate-update-helper` and an
account-specific `/etc/sudoers.d/flowgate-local-update` rule. It does not install
a release or change protection. After setup, the ordinary updater automatically
uses the helper without a password, including when run by an agent:

```sh
./scripts/update-and-start.sh --local --profile preserve
```

If an installed daemon cannot be queried, `--recover-stopped` explicitly permits
monitoring-only recovery. It is a recovery option, not the normal update path.

**Trust boundary:** authorizing local updates grants the selected account the
ability to install code that runs as root. Bundle hashes check consistency, not
a trusted publisher signature. Only enable this for an account whose local
source/builds you trust. The authorization is not tied to a login group and does
not grant a general passwordless Python or shell command.

The helper accepts only check, candidate preflight, staged monitoring install,
and the explicitly requested Wine-discovery configuration operation. Existing
bundle verification, candidate compatibility checks, rollback and protection
restoration remain in effect. The helper keeps its staging code in root-owned
storage; it does not import Python modules from the checkout. A broken or
unauthorized installed helper refuses the update before stopping protection.
Its staging code can be refreshed by rerunning the one-time setup when needed.

To revoke passwordless updates:

```sh
sudo rm /etc/sudoers.d/flowgate-local-update /usr/local/libexec/flowgate-update-helper
```

The updater then returns to its existing sudo authentication path. Removing the
helper does not uninstall FlowGate or change running protection.

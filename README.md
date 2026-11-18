# FlowGate

FlowGate is a Linux application firewall and socket monitor. Its installed Go
service runs as root and can protect incoming traffic or both incoming and
outgoing traffic. The Electron desktop and Qt development client run unprivileged.
To inspect a host from a source checkout, start with the
[read-only diagnostics](#diagnose-before-explicit-activation).

**Process discovery can fail.** A process may exit before FlowGate inspects its
socket, access restrictions may hide the owner, or several applications may
share the socket. When FlowGate cannot verify which application owns the
traffic, it cannot use that application's saved permission for the decision.
[Process and socket attribution](docs/ATTRIBUTION.md)

## What FlowGate controls

- **Firewall.** Allow or block supported TCP and UDP traffic by verified
  application, user and direction. TCP rules govern new connections. Changing a
  rule to Block leaves already-admitted TCP connections open. [Rule semantics](docs/SEMANTICS.md)
- **Wine and Proton.** On supported runtimes, permissions distinguish Windows
  executables and Wine prefixes. The launcher regression exercises two Windows
  programs in one prefix and repeats one in a second prefix. A receiver checks
  delivery after Allow and Block and after relaunch with a remembered rule.
  [Tested runtimes and scope](docs/PROTON-LAUNCHER-REGRESSION.md)
- **Bandwidth controls (experimental).** Upload and download caps and traffic
  priorities apply to eligible native application sockets. Download shaping
  covers established TCP on supported routes. UDP downloads and VPN/TUN paths
  fall outside that profile. Quotas and recurring schedules are unimplemented.
  [Zone limits and priorities](docs/ZONE-SHAPING.txt) · [Download coverage](docs/DOWNLOAD-LIMITER.txt)
- **Usage history.** Live charts show recent activity. Administrators can also
  enable durable history for 1, 7 or 30 days. Totals reflect what the collectors
  observed and can have gaps across restarts or periods without collection.
  [Observed usage history](docs/USAGE-HISTORY.md)

## Install or update a release

### Standalone package

The standalone release candidate targets **Linux x86-64 with systemd**. At
revision `a488e44`, GitHub had no published installer. [GitHub Releases](https://github.com/OzoneH3/flowgate/releases)

Install the [build prerequisites](docs/STANDALONE-RELEASE.md), then run these
commands in order from a fresh, clean checkout.

```sh
scripts/build.sh electron
make package
```

The first command downloads the pinned Electron runtime. At `a488e44`,
starting with `make package` alone compiles the UI and then stops at the
missing runtime. The package build writes the archive, offline bootstrap and
SHA-256 receipts to `.workspace/dist/`.

For an existing archive and bootstrap, verify their SHA-256 digests against
values from a trusted source before installation. The
[standalone guide](docs/STANDALONE-RELEASE.md) covers preflight, installation,
recovery, rollback and removal.

### Checkout-based updater

This development workflow requires prepared backend and Electron bundles for the
exact revision in [the release pin](deployment/default-release). At `a488e44`,
the pin was `5083546`, which was absent from the public Git history. A fresh
public checkout therefore stops at the missing-bundle check, even on a dry run.

Once both pinned bundles are in `.workspace/`, preview and apply the update
from a clean, committed `master` checkout.

```sh
# Preview a local update without preparing or installing a bundle:
./scripts/update-and-start.sh --local --profile preserve --dry-run
# Check and install the prepared bundles, verify the result, and relaunch the GUI:
./scripts/update-and-start.sh --local --profile preserve
```

`--local` skips upstream access. `--profile preserve` keeps the existing protection
mode; on a new installation it selects monitoring. Omitting `--profile` also
preserves the mode. To explicitly enable Both from another mode, use
`--profile both --acknowledge-outgoing-blocking` after reviewing Essential
networking and root-local recovery. Continuous protection has no automatic
countdown; no DNS/DHCP/service permissions are added automatically. Candidate
compatibility checks precede stopping the current protection. Authentication uses
sudo or the optional [passwordless local update helper](#passwordless-local-updates).

On a clean `master` checkout at the approved revision, `scripts/prepare-release.sh`
builds matched backend and Electron bundles under `.workspace/`. For a deliberate
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

See the [Qt client guide](desktop/README.md) for the live monitor, five-minute
host evaluation, isolated demo and desktop checks.

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

[Current status](docs/STATUS.md) · [Integration map](docs/INTEGRATION.md) ·
[Development handoff and historical records](docs/HANDOFF.md)

Desktop branding: CMake `-DFLOWGATE_PRODUCT_NAME=NewName`. CLI branding:
`go build -ldflags '-X main.productName=NewName'`. Binaries use native shared
libraries; no static/portable deployment claim. Other distributions and arm64
remain unvalidated.

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

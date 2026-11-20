<img src="electron/assets/flowgate.png" alt="FlowGate app icon" width="96" align="right">

# FlowGate

**See which apps are online and decide what they can connect to.**

FlowGate is a Linux application firewall and network monitor. See live traffic
by app, allow or block connections, and look up past firewall decisions from
the desktop. The per-app monitoring and control workflow takes inspiration from
[NetLimiter](https://netlimiter.com/).

[Try the desktop](#try-the-desktop) · [Install FlowGate](#install-flowgate) ·
[Documentation](#documentation)

![FlowGate Activity view with a full-width traffic chart above the app table and details for the selected demo app](docs/images/flowgate-main-window.png)

*Activity opens with the traffic chart above the app table. Select a row to
see its details, or return to the all-applications overview to give the table
the full width.*

## What you can do

- **See network activity.** Browse active sockets by app and process, watch
  live upload and download charts, and opt in to keeping 1, 7, or 30 days of
  data. [Usage history](docs/USAGE-HISTORY.md)
- **Decide what gets through.** Allow or block supported TCP and UDP traffic by
  verified application, user, and direction. Make a temporary choice at a prompt or
  save a rule for future connections. [How rules work](docs/SEMANTICS.md)
- **Find out what the firewall decided.** Look up recorded firewall decisions
  and their reasons. Usage and decision records reflect what FlowGate observed.
  Both can have gaps. [Decision Log](docs/DECISION-LOG.md)
- **Set separate rules for Windows apps.** With supported Wine and Proton
  runtimes, FlowGate distinguishes Windows executables and Wine prefixes.
  [Tested runtimes and scope](docs/PROTON-LAUNCHER-REGRESSION.md)
- **Limit bandwidth (experimental).** Apply limits and priorities to eligible
  native app traffic. Download limits cover established TCP on supported routes.
  [Limits and priorities](docs/ZONE-SHAPING.txt) ·
  [Download coverage](docs/DOWNLOAD-LIMITER.txt)

![FlowGate Ask prompt for an outgoing TCP connection from a disposable app, with its remote endpoint, Remember options, duration, and Allow and Deny buttons visible](docs/images/flowgate-ask-remember.png)

*An outgoing Ask prompt with Remember expanded and a five-minute duration selected.*

## Try the desktop

From a source checkout, run this as your desktop user. The launcher builds the
Electron app and starts a local read-only observer for live Activity. See the
[desktop prerequisites](electron/README.md) for Go, Node, npm, Python and
Electron runtime requirements.

```sh
./scripts/run-electron.sh
```

This preview requires no service installation or firewall activation. To use
rules and protection, connect the desktop to an installed FlowGate daemon.

## Install FlowGate

The standalone release candidate targets **64-bit x86 Linux with systemd**.
Check [GitHub Releases](https://github.com/OzoneH3/flowgate/releases) for a
prebuilt candidate. If you download one, follow the installation guide to
verify the archive and offline installer before running them as root.

To build from source:

1. Check the [build and system requirements](docs/STANDALONE-RELEASE.md).
2. Run `make package` from a clean, committed checkout. It builds FlowGate,
   runs the release checks, and writes the archive, offline installer, and
   SHA-256 receipts to `build/dist/`.
3. Follow the [standalone installation guide](docs/STANDALONE-RELEASE.md) to
   verify the files, run preflight, and install. The same guide covers rollback
   and uninstall.
4. Open **FlowGate** from the application menu or run `flowgate-ui`.

To upgrade an existing installation from a clean, committed checkout, run
`make update` as your desktop user. It builds the package, verifies the archive's
digest, runs preflight, installs with sudo, and reloads the installed desktop.

A fresh install starts in **Monitoring**. When you're ready to enable
protection, review essential networking first. Then choose **Incoming only**
or **Incoming + outgoing**, select **Check readiness**, and use **Start protection**.
The system service runs as root and continues running when the desktop closes.
Use **Stop protection** to return to monitoring. [Essential networking](docs/ESSENTIAL-NETWORKING.md)

## Good to know

- **An app needs verified ownership.** When a socket is shared, its owner has
  exited, or FlowGate can't inspect it, the app's saved permission cannot be
  applied on the strength of a guess. [How ownership is verified](docs/ATTRIBUTION.md)
- **A newly created or enabled Block can disconnect open TCP connections.**
  FlowGate does this during active protection when the Block becomes the winning
  decision and FlowGate can verify the exact socket, its owner, and the connection
  direction. Starting protection preserves open connections. A later winning
  Block can still disconnect them. [Connection and rule semantics](docs/SEMANTICS.md)
- **Local can include VPN peers.** For example, a remote desktop connection to
  `192.168.23.155` over `ppp0` is automatically classified as Local. Choose
  **Local** to scope a rule to that zone. Configured prefixes can override
  automatic classification. [Automatic zones](docs/AUTOMATIC-ZONES.md)
- **VPN support depends on the setup.** TUN traffic is subject to ordinary
  application rules. WireGuard and XFRM interfaces currently prevent activation.
  Use the read-only checks to investigate firewall, routing, or VPN conflicts.
  [Network compatibility](docs/COEXISTENCE.md) · [Diagnostics](docs/DIAGNOSTICS.md)

## Diagnose before explicit activation

Run `flowgate doctor` if FlowGate is installed, or build the command from your
checkout. Doctor reports what it could check without changing firewall settings
or requesting sudo.

```sh
. scripts/go-env.sh
go build -o build/flowgate ./cmd/flowgate
build/flowgate doctor
```

Use `doctor --json` for structured output. FlowGate also runs live compatibility
checks when you enable protection. [Read the diagnostic and recovery guide](docs/DIAGNOSTICS.md)

## Documentation

| I want to… | Read |
| --- | --- |
| Use Activity, prompts, the tray, and saved rules | [Electron desktop guide](electron/README.md) |
| Know who can see traffic or edit rules | [Authorization](docs/AUTHORIZATION.md) |
| Check supported Wine/Proton versions and attribution | [Wine and Proton guide](docs/WINE.md) |
| Prepare a developer release or recover an installation | [Deployment and rollback](docs/DAILY-DEPLOYMENT.md) · [Script reference](scripts/README.md) |
| Work on the Unix API, Qt client, or core | [API](docs/API.md) · [Qt client](desktop/README.md) · [Integration map](docs/INTEGRATION.md) |
| Review project status and test evidence | [Status](docs/STATUS.md) · [Historical records](docs/HANDOFF.md) |

<details>
<summary>Checkout-based updates and developer tools</summary>

Use [the checkout updater](docs/DAILY-DEPLOYMENT.md) only with matched backend
and Electron bundles for the exact [pinned revision](deployment/default-release).
A fresh public clone may not contain that revision. The updater needs both
`build/daily-releases/<revision>/` and
`build/automatic-zone-releases/<revision>/` for that pin. From a clean
`master` checkout, preview the update and then apply it.

```sh
./scripts/update-and-start.sh --update --local --profile preserve --dry-run
./scripts/update-and-start.sh --update --local --profile preserve
```

With no arguments the script opens the installed desktop. The `--local`
option skips fetching and still requires the prepared bundles for the pinned
revision. This workflow preserves the existing protection mode. The
[standalone guide](docs/STANDALONE-RELEASE.md) covers the source package
workflow and migration.

Connect a checkout build to an existing installed daemon with
`./scripts/run-electron.sh --daemon /run/flowgate-api/daemon.sock`. The
launcher attaches without starting or stopping the daemon. Compare the builds
shown in **Help → About** or run `flowgate version` on a particular binary.

The optional [passwordless local update helper](docs/DAILY-DEPLOYMENT.md#passwordless-local-updates)
applies to checkout-based updates.

</details>

# FlowGate

**See which apps are online and decide what they can connect to.**

FlowGate is a Linux application firewall and network monitor. See live traffic
by app, allow or block connections, and look up past firewall decisions from
the desktop. The per-app monitoring and control workflow takes inspiration from
[NetLimiter](https://netlimiter.com/).

[Try the desktop](#try-the-desktop) · [Install FlowGate](#install-flowgate) ·
[Documentation](#documentation)

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
There is currently no installer on [GitHub Releases](https://github.com/OzoneH3/flowgate/releases).

1. Check the [build and system requirements](docs/STANDALONE-RELEASE.md).
2. Run `make package` from a clean, committed checkout. The archive, offline
   installer, and SHA-256 receipts go to `.workspace/dist/`.
3. Follow the [standalone installation guide](docs/STANDALONE-RELEASE.md) to
   verify the files, run preflight, and install. The same guide covers rollback
   and uninstall.
4. Open **FlowGate** from the application menu or run `flowgate-ui`.

A fresh install starts in **Monitoring**. When you're ready to enable
protection, review essential networking first. Then choose **Incoming only**
or **Incoming + outgoing**, select **Check readiness**, and use **Start protection**.
The system service runs as root and continues running when the desktop closes.
Use **Stop protection** to return to monitoring. [Essential networking](docs/ESSENTIAL-NETWORKING.md)

## Good to know

- **An app needs verified ownership.** When a socket is shared, its owner has
  exited, or FlowGate can't inspect it, the app's saved permission cannot be
  applied on the strength of a guess. [How ownership is verified](docs/ATTRIBUTION.md)
- **TCP rules govern new connections.** Setting a rule to Block leaves
  already-admitted TCP connections open. [Connection and rule semantics](docs/SEMANTICS.md)
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
go build -o .workspace/flowgate ./cmd/flowgate
.workspace/flowgate doctor
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
A fresh public clone may not contain that revision. From a clean, committed
`master` checkout with the prepared bundles in `.workspace/`, preview the
update and then apply it.

```sh
./scripts/update-and-start.sh --local --profile preserve --dry-run
./scripts/update-and-start.sh --local --profile preserve
```

This workflow preserves the existing protection mode. The
[standalone guide](docs/STANDALONE-RELEASE.md) covers the source package
workflow and migration.

Connect a checkout build to an existing installed daemon with
`./scripts/run-electron.sh --daemon /run/flowgate-api/daemon.sock`. The
launcher attaches without starting or stopping the daemon. Compare the builds
shown in the desktop header or run `flowgate version` on a particular binary.

The optional [passwordless local update helper](#passwordless-local-updates)
applies to checkout-based updates.

</details>

### Passwordless local updates

<details>
<summary>Setup, permissions, and removal</summary>

The updater normally uses sudo. To authorize the current desktop account to
install local builds without an interactive password prompt, run this once from
a trusted checkout.

```sh
sudo /usr/bin/python3 -I scripts/setup-passwordless-update.py
```

This grants that account the ability to install local code that runs as root.
The helper is root-owned and restricts commands to the updater's supported
operations. Bundle hashes check consistency. Use only trusted local source and
builds. The updater still verifies the bundle and checks compatibility before
it stops existing protection.

Remove the authorization and helper to return the updater to ordinary sudo.

```sh
sudo rm /etc/sudoers.d/flowgate-local-update /usr/local/libexec/flowgate-update-helper
```

</details>

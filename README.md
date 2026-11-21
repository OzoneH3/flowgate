<img src="electron/assets/flowgate.png" alt="FlowGate app icon" width="96" align="right">

# FlowGate

**See which apps are online and decide what they can connect to.**

FlowGate is a Linux application firewall and network monitor inspired by
[NetLimiter](https://netlimiter.com/).

[Try the desktop](#try-the-desktop) · [Install FlowGate](#install-flowgate) ·
[Documentation](#documentation)

## Features

- See live traffic per app and opt in to 1, 7 or 30 days of [usage history](docs/USAGE-HISTORY.md).
- **Allow, Block or Ask** for inbound and outbound TCP/UDP. Answer once or [save a rule](docs/SEMANTICS.md).
- Review decisions and their reasons in the [Decision Log](docs/DECISION-LOG.md).
- Set per-executable rules within each prefix on [supported Wine/Proton setups](docs/PROTON-LAUNCHER-REGRESSION.md).
- **Experimental** [bandwidth limits and traffic priorities](docs/ZONE-SHAPING.txt) for eligible native apps.

## Supported systems and limitations

**Standalone target: x86-64 Linux with systemd.** A popup pass means the receiver got the held TCP payload after **Allow Once**.

| Tested system | Recorded result |
| --- | --- |
| Debian 13.7 (headless) | Firewall rules and UDP checks passed. |
| Ubuntu 26.04.1 GNOME (Wayland) | Headless rules passed. Popup passed. |
| Fedora 45 GNOME (Wayland) | Rules passed. Popup passed. Stock firewalld blocked readiness on a later build. |
| Kubuntu 26.04.1 and CachyOS, both Plasma (Wayland) | Popup passed on both. |
| Mint 22.3 Cinnamon and Xubuntu 26.04.1 Xfce (X11) | Popup passed on both. |
| Pop!_OS 24.04 COSMIC (Wayland) | Popup passed once. Repeats inconclusive. |
| CachyOS Hyprland (Wayland) | Popup passed with UFW off. Approval unverified with stock UFW. |
| openSUSE Tumbleweed Plasma (Wayland) | Stock firewalld readiness passed. Popup delivery unverified. |

A later sweep launched all nine desktops without verifying delivery. [Full compatibility matrix and tested builds](docs/COMPATIBILITY.md)

App rules require [verified socket ownership](docs/ATTRIBUTION.md). VPN compatibility depends on the setup. WireGuard and XFRM interfaces [block activation](docs/SEMANTICS.md).
Download limiting covers [eligible established TCP connections](docs/DOWNLOAD-LIMITER.txt).

![FlowGate Activity view with download and upload totals in the traffic chart header, the app table below, and the selected app’s Overview at right](docs/images/flowgate-main-window.png)

*The Activity view shows simulated traffic. On wide windows,
the inspector sits beside the traffic chart and app table.*

![FlowGate Ask prompt for an outgoing TCP connection from Atlas Sync, with endpoint details, rule scope, and a row of For a while buttons beneath Allow and Deny](docs/images/flowgate-ask-remember.png)

*An outgoing Ask prompt with a five-minute rule duration. The For a while
buttons use the one-minute duration below Next request.*

## Try the desktop

As your desktop user, clone the repository and run the preview. The first run
downloads the locked Electron dependencies and Go modules, builds the app, and
opens live Activity with a private read-only observer. Press Ctrl+C in the
launch terminal to stop the preview. [Desktop prerequisites](electron/README.md)

```sh
git clone https://github.com/OzoneH3/flowgate.git
cd flowgate
./scripts/run-electron.sh
```

## Install FlowGate

From a clean checkout of the revision you want to install, run the following as the
intended desktop administrator. First check the
[build and host requirements](docs/STANDALONE-RELEASE.md#requirements).

```sh
make update
```

This command builds the checked-out commit, verifies the archive, runs preflight
and installs with sudo. In a graphical session it opens the matching installed
desktop. To upgrade from public `master` later, run `git pull --ff-only`,
review the new revision, then run `make update` again. To open the installed app at any time, use
the application menu or run `flowgate-ui`.

Run `make help` for individual build, package, install and recovery commands.
The [standalone guide](docs/STANDALONE-RELEASE.md) covers staged installation,
checksum verification for a candidate downloaded from [GitHub Releases](https://github.com/OzoneH3/flowgate/releases),
and rollback. The [verification record](docs/STANDALONE-RELEASE.md#verification-record)
identifies the audited builds and the guest checks still pending.

A fresh install starts in **Monitoring**. When you're ready to enable
protection, review essential networking first. Then choose **Incoming only**
or **Incoming + outgoing**, select **Check readiness**, and use **Start protection**.
The system service runs as root and continues running when the desktop closes.
Use **Stop protection** to return to monitoring. [Essential networking](docs/ESSENTIAL-NETWORKING.md)

During active protection, a new or re-enabled Block can disconnect an open TCP
connection if it wins and FlowGate verifies the socket, owner and direction.
Starting protection preserves open connections. [Established TCP control](docs/ESTABLISHED-TCP-CONTROL.md)

VPN peers can fall in the **Local** zone. Configured prefixes can override the
automatic classification. [Automatic zones](docs/AUTOMATIC-ZONES.md)

## Diagnose before explicit activation

On a standalone installation, run `/usr/local/lib/flowgate/current/flowgate doctor`.
From a source checkout, use the commands below. Doctor reports what it could
check without changing firewall settings or requesting sudo.

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
| Package a standalone release, recover or uninstall | [Standalone release guide](docs/STANDALONE-RELEASE.md) |
| Maintain a pinned checkout deployment or attach a development desktop | [Developer deployment guide](docs/DAILY-DEPLOYMENT.md) · [Script reference](scripts/README.md) |
| Work on the Unix API, Qt client, or core | [API](docs/API.md) · [Qt client](desktop/README.md) · [Integration map](docs/INTEGRATION.md) |
| Review project status and test evidence | [Status](docs/STATUS.md) · [Historical records](docs/HANDOFF.md) |

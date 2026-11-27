<img src="electron/assets/flowgate.png" alt="FlowGate app icon" width="96" align="right">

# FlowGate

**See which apps are online and decide what they can connect to.**

FlowGate is a Linux application firewall and network monitor inspired by
[NetLimiter](https://netlimiter.com/).

[Features](#features) · [Tested systems](#supported-systems-and-limitations) ·
[Try the desktop](#try-the-desktop) · [Build, install or update](#install-flowgate)

## Release candidate 16

**Known firewall issue on openSUSE Tumbleweed:** one test connection delivered a
36-byte payload while a process-specific TCP Block was enabled. The final
decision matched the broader application Allow. The cause is unresolved. Treat
process-specific Blocks over a broader Allow as unreliable on this candidate.

RC16 adds permission-popup scaling, refreshes the Pending requests inspector,
and checks the selected shaping interface at startup. The Linux x86-64 package
and its checksum receipts are on the [RC16 prerelease page](https://github.com/OzoneH3/flowgate/releases/tag/flowgate-v0.1.0-rc.16).

## Features

- **Inspect connections.** Activity groups sockets by application and process. Use the traffic chart and connection analyzer to investigate a connection, or enable 1, 7 or 30 days of machine-wide observed usage history. [Usage history and privacy](docs/USAGE-HISTORY.md)
- **Decide on requests.** Allow or deny a held connection once, grant a supported temporary process permission, or review the scope of a saved rule. The Pending requests inspector shows the selected connection. Permission popup scale can be set from 75% to 125%. [Desktop guide](electron/README.md)
- **Manage policy.** Create Allow, Block or Ask rules by direction, protocol, address and port. Scope a rule to an application or a verified process, set an expiry, and inspect which rule won in the Decision Log. [Rule editor](docs/RULES.md) · [Decision Log](docs/DECISION-LOG.md)
- **Identify Windows applications.** Supported Wine and Proton runtimes can attribute a connection to its Windows executable, user and prefix. [Runtime requirements](docs/WINE.md)
- **Shape traffic experimentally.** Set upload and download limits or traffic priority on an eligible interface. Saved settings can apply when an application starts. Wine shaping requires a verified live outgoing TCP socket. [Shaping controls](docs/ZONE-SHAPING.txt) · [Traffic priority](docs/TRAFFIC-PRIORITY.txt)

## Supported systems and limitations

The standalone package targets **x86-64 Linux with systemd**. The daemon can
run headless. The Electron desktop runs on X11 and Wayland.

RC16 passed **229/230 API cases** on ten profiles and **220/243 desktop
journeys** on nine graphical profiles. The API suite included real connections with
receiver counts as well as configuration checks. Desktop journeys exercised the packaged GUI with fixture
requests. These are the original results from run `1795817718246162010`.

| Tested system | Session | API passed | Desktop journeys passed |
| --- | --- | ---: | ---: |
| Debian 13 | Headless | 23/23 | — |
| CachyOS Hyprland | Wayland | 23/23 | 24/27 |
| CachyOS Plasma | Wayland | 23/23 | 25/27 |
| Fedora 45 Workstation (GNOME) | Wayland | 23/23 | 25/27 |
| Kubuntu 26.04.1 Plasma | Wayland | 23/23 | 23/27 |
| Linux Mint 22.3 Cinnamon | X11 | 23/23 | 25/27 |
| openSUSE Tumbleweed Plasma | Wayland | 22/23 | 25/27 |
| Pop!_OS 24.04 COSMIC | Wayland | 23/23 | 24/27 |
| Ubuntu 26.04.1 GNOME | Wayland | 23/23 | 24/27 |
| Xubuntu 26.04.1 Xfce | X11 | 23/23 | 25/27 |

- **Firewall enforcement:** openSUSE recorded the process Block failure described above. Application rules depend on verified socket ownership. Protection readiness depends on the host firewall and VPN configuration; WireGuard and XFRM devices remain unsupported. [Attribution](docs/ATTRIBUTION.md) · [Protection scope](docs/SEMANTICS.md)
- **Tray and popups:** stock Fedora GNOME had no tray host. On the other eight desktops, the runner could not complete the keyboard tray journeys. Bottom-right, above-window permission prompts remain unverified on GNOME and COSMIC. [RC16 compatibility details and earlier runs](docs/COMPATIBILITY.md) · [Popup placement](docs/ROADMAP.md#todo--permission-popup-placement)
- **Traffic limits:** download limiting covers eligible established TCP connections. Interface discovery and readiness checks determine where shaping can run. [Download limiter](docs/DOWNLOAD-LIMITER.txt)

## Desktop screenshots

![RC16 Pending requests showing Atlas Sync selected, Beacon Relay queued and the selected connection’s endpoints and permission controls](docs/images/flowgate-main-window.png)

*Select a pending connection to inspect its process, endpoints and available decisions.*

![RC16 permission popup for Atlas Sync showing an outgoing TCP request, rule scope and Allow or Deny controls](docs/images/flowgate-ask-popup.png)

*Both screenshots use simulated requests. In the popup, **This connection only**
applies to **Allow once** and **Deny once**. The **Always** buttons use the
reviewed rule scope.*

## Try the desktop

As your desktop user, clone the repository and run the read-only preview. The
first run downloads the locked Electron dependencies and Go modules, builds
the app, and opens live Activity with a private observer. The preview leaves
system installation and protection settings alone. Press Ctrl+C in the launch
terminal to stop it. [Desktop prerequisites](electron/README.md)

```sh
git clone --branch flowgate-v0.1.0-rc.16 https://github.com/OzoneH3/flowgate.git
cd flowgate
./scripts/run-electron.sh
```

## Install FlowGate

For the published RC16 binary, download the archive, Python installer and both
checksum files from the release page. Compare the archive and installer against
the SHA-256 values in the release notes before running preflight and install.
[Offline installation instructions](docs/STANDALONE-RELEASE.md#install-a-downloaded-package-offline)

To build RC16 yourself, use a clean checkout of the release tag. The following
commands build and verify the package. [Build and host requirements](docs/STANDALONE-RELEASE.md#requirements)

```sh
(
  set -eu
  make package
  bundle="$(make -s archive-path)"
  cd "$(dirname "$bundle")"
  sha256sum -c -- "$(basename "$bundle").sha256" flowgate-release.py.sha256
)
```

`make package` also runs `make check`. It puts the archive,
`flowgate-release.py`, and both `.sha256` receipts in
`build/dist/<release-id>/`. Untagged commits get a development version with
their short Git SHA.

To install or update from the current checkout, run `make update` as the
intended desktop administrator. It checks both receipts, runs preflight and
install with sudo, then reloads FlowGate in a graphical session.

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

## Check host readiness

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
| Review priorities, project status, and test evidence | [Audit and roadmap](docs/ROADMAP.md) · [Status](docs/STATUS.md) · [Historical records](docs/HANDOFF.md) |

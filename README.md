# FlowGate — backend laboratory milestone

A Go Linux application firewall prototype with structured attribution, Allow/Block/Ask policy and a CLI pending queue. **Native isolated enforcement works. An explicit Wine 11.19 broker mode controls independent applications with visible client socket FDs. Server-only listeners and dormant shared Windows handles remain observation boundaries; this is not universal Wine/game protection.**

## Build and verify

Requires Go >=1.24, Linux socket diagnostics, nftables, util-linux `unshare`, iproute2 and Python 3. No privileged installation. All commands start in the repository root.

```sh
. ./scripts/go-env.sh
go build -o .workspace/flowgate ./cmd/flowgate
.workspace/flowgate doctor
.workspace/flowgate sockets
.workspace/flowgate process $$
scripts/check.sh
# Optional actual Windows PE tests: Wine, Clang/lld and Wine development headers
scripts/check.sh --wine
# Current increment: broker-mode Wine, inheritance boundary, rule scope, one-shot UDP
scripts/check-increment.sh
```

The optional PE build script uses this host's `/usr/include/wine` and `/usr/lib/wine/x86_64-windows` layout. Adjust those paths on other distributions. It creates and uses only `.workspace/wine-prefix`; it never uses an existing prefix. No game downloads or launcher changes.

## Interactive isolated demo

```sh
scripts/lab.sh
# Commands below run INSIDE that disposable namespace:
.workspace/flowgate serve-lab --parent-netns "$FLOWGATE_PARENT_NETNS" &
python3 -m http.server 8080 --bind 127.0.0.1 >.workspace/run/http.log 2>&1 &
python3 -c 'import urllib.request; print(urllib.request.urlopen("http://127.0.0.1:8080").status)' &
.workspace/flowgate pending
# Copy the pending ID, then:
.workspace/flowgate decide --id REQUEST_ID --action allow --scope once
# A retained initial packet is released after identity revalidation. Exiting this shell destroys the namespace.
exit
```

`--scope application` creates an in-memory one-hour permission for application revision, user, initiation direction and protocol. Incoming scope is the observed **remote address plus local service port**, with any client source port. Outgoing scope keeps the destination address and destination port. JSON `remembered_filter` previews the exact match. `--scope once` keeps the full TCP connection identity or UDP tuple (30 seconds). The first UDP datagrams can be retained until timely approval; no retry is required for packets within the retention bounds. Block/timeout drops them.

Wine broker attribution is **disabled by default**. To exercise the documented non-sharing model, set `FLOWGATE_WINE_BROKER=/usr/bin/wineserver` for the daemon and attribution CLI. The path pins an actual executable identity, not a name exemption. Read [Wine evidence and assumptions](docs/WINE.md) before enabling it. The increment script opts in only for its dedicated fixtures.

For outgoing tests use `serve-lab --direction outgoing`. The lab installs **one selected hook per run**, not simultaneous bidirectional host protection. `scripts/outgoing.py` demonstrates this. Keep all processes in the lab shell so `/proc` visibility is complete enough for the prototype.

Read-only attribution of an incoming listener:

```sh
.workspace/flowgate attribute --protocol tcp --direction incoming \
  --local 127.0.0.1:8080 --remote 127.0.0.1:50000
```

A JSON rule array can be supplied with `serve-lab --rules PATH`; see [semantics](docs/SEMANTICS.md) for schema and precedence. Rule schema 2 adds explicit address/port fields; legacy schema 0/1 exact `remote` endpoints retain their meaning. CLI JSON is the additive v1 presentation; no GUI, names from DNS, icons or traffic rates are fabricated. The monitor API at `control.sock.monitor` rejects mutations. Both sockets require a private directory and peer credentials; callers see/control their own attributed flows, with UID 0 as administrator inside the namespace.

## Scope and evidence

See [status and validation](docs/STATUS.md), [semantics and limitations](docs/SEMANTICS.md), [research/reuse](docs/RESEARCH.md) and the [authoritative plan](docs/PLAN.md).

No Qt, systemd, NetworkManager, cloud or package-manager dependency in the core. The test harness uses no init system. CachyOS x86-64 is directly tested; Debian/Ubuntu, Fedora, arm64, Flatpak, Proton games and VPN coexistence are unverified. The default build on this host links libc/libresolv; it is not claimed portable or static.

Brand display is a build variable: `go build -ldflags '-X main.productName=NewName' -o .workspace/flowgate ./cmd/flowgate`. Module/API identifiers are deliberately separate from display branding. SQLite, desktop integration and packaging for a privileged service are deferred until attribution is strong enough for host deployment.

### Experimental transparent Wine/Proton census

The optional lab adapter now tests ordinary IPv4/IPv6 TCP listeners and UDP without
modifying the target application, including dormant inherited handle detection.
It remains disabled by default. Supported builds, snapshot limitations, launcher
inspection and reproducible commands are in [docs/WINE.md](docs/WINE.md); current
evidence and remaining work are in [docs/STATUS.md](docs/STATUS.md).

For already-running workspace test sessions, use `runtime-discover` and
`serve-lab --attach-prefixes PREFIX[,PREFIX] --runtime-bins DIR[,DIR]`. No manual
per-prefix helper environment is required. `scripts/check-runtime.sh` reproduces
the lifecycle, two-session attachment and IPv6 checks sequentially. See WINE.md
for Wine/Proton setup and the explicit connection-initiation contract.

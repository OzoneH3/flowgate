# FlowGate — backend laboratory milestone

A Go Linux application firewall prototype with structured attribution, Allow/Block/Ask policy and a CLI pending queue. **Native isolated enforcement works. Wine process identities are distinct, but shared wineserver descriptors currently prevent safe application-specific Allow. This is not a production host firewall or a completed Wine milestone.**

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
# A TCP retransmission now completes. Exiting this shell destroys the namespace.
exit
```

`--scope application` creates an in-memory one-hour permission for the exact application revision, user, initiation direction, protocol and remote IP:port. It is deliberately explicit; incoming remote scope includes the client's source port. `--scope once` permits that TCP connection (SYN sequence included) or that UDP tuple for 30 seconds. UDP must retry its dropped first datagram. `--action block` uses the same scopes.

For outgoing tests use `serve-lab --direction outgoing`. The lab installs **one selected hook per run**, not simultaneous bidirectional host protection. `scripts/outgoing.py` demonstrates this. Keep all processes in the lab shell so `/proc` visibility is complete enough for the prototype.

Read-only attribution of an incoming listener:

```sh
.workspace/flowgate attribute --protocol tcp --direction incoming \
  --local 127.0.0.1:8080 --remote 127.0.0.1:50000
```

A JSON rule array can be supplied with `serve-lab --rules PATH`; see [semantics](docs/SEMANTICS.md) for schema and precedence. CLI JSON is the v1 presentation; no GUI, names from DNS, icons or traffic rates are fabricated. The monitor API at `control.sock.monitor` rejects mutations. Both sockets require a private directory and peer credentials; callers see/control their own attributed flows, with UID 0 as administrator inside the namespace.

## Scope and evidence

See [status and validation](docs/STATUS.md), [semantics and limitations](docs/SEMANTICS.md), [research/reuse](docs/RESEARCH.md) and the [authoritative plan](docs/PLAN.md).

No Qt, systemd, NetworkManager, cloud or package-manager dependency in the core. The test harness uses no init system. CachyOS x86-64 is directly tested; Debian/Ubuntu, Fedora, arm64, Flatpak, Proton games and VPN coexistence are unverified. The default build on this host links libc/libresolv; it is not claimed portable or static.

Brand display is a build variable: `go build -ldflags '-X main.productName=NewName' -o .workspace/flowgate ./cmd/flowgate`. Module/API identifiers are deliberately separate from display branding. SQLite, desktop integration and packaging for a privileged service are deferred until attribution is strong enough for host deployment.

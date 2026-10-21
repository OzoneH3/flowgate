# Wine runtime attribution

Current integration is described in the final section. Earlier sections preserve
the FD-only boundary and the initial experiment; their unverified cases are
superseded only by the explicit new evidence below.

## Evidence and supported model

Observed locally: Wine 11.19, `/usr/bin/wineserver`, x86-64 Wine PE fixtures. Matching upstream tag was inspected, not assumed identical to every distribution patch:

- [server/sock.c at wine-11.19](https://github.com/wine-mirror/wine/blob/wine-11.19/server/sock.c): socket objects retain Unix FDs; the server implements creation, bind/listen and accept/async operations. A server descriptor is not necessarily passive bookkeeping.
- [ntdll Unix server.c](https://github.com/wine-mirror/wine/blob/wine-11.19/dlls/ntdll/unix/server.c): `server_get_unix_fd` requests a handle FD, receives it via SCM_RIGHTS and caches eligible descriptors. A Windows handle need not already have a visible client Unix FD.
- [ntdll Unix socket.c](https://github.com/wine-mirror/wine/blob/wine-11.19/dlls/ntdll/unix/socket.c): several operations fall back to server handling; FIONREAD obtains the Unix FD. This explains the observed plain-TCP versus polling-TCP difference.
- [ws2_32 socket.c](https://github.com/wine-mirror/wine/blob/wine-11.19/dlls/ws2_32/socket.c) and [server/handle.c](https://github.com/wine-mirror/wine/blob/wine-11.19/server/handle.c): duplication/inheritance can create additional Windows handle references. WSADuplicateSocket uses handle duplication. Direct WSADuplicateSocket execution is not claimed tested; CreateProcess inheritable handles were tested.

No Wine code was copied into the implementation. Source snapshots for inspection are generated under `.workspace/wine-source`.

The opt-in `FLOWGATE_WINE_BROKER=/usr/bin/wineserver` enables a **non-sharing ordinary-client model**, not an assertion that all possible recipients are known. Acceptance requires exactly one socket, two observed holders, a resolved Windows client image, and a broker whose live executable matches the configured file's device/inode. Both must have the same UID, namespaces and explicit canonical prefix. Reciprocal UNIX_DIAG_PEER evidence must connect their current Unix socket descriptors. This is stronger than name/prefix matching and preserves the entire holder set. The fingerprint includes process start times, executable revisions, socket cookie and broker-channel inodes. Delayed release resolves all evidence again.

Default mode remains conservative. Other versions/runtimes, missing peer/FD evidence, hidden processes and multiple visible clients are not silently accommodated. No trust is granted to every process called wineserver. A name, prefix or Steam ID alone never authorizes traffic.

## Receiver results and limitations

`wine-increment.py` runs alpha and beta concurrently using one runtime/prefix. Both Allow-alpha/Block-beta and Block-alpha/Allow-beta pass for single-send UDP and for TCP listeners that call FIONREAD before accepting. Each remembered permission has the client's own image/revision key. TCP FIONREAD is a labelled fixture behavior, not an injected fix or a claim that arbitrary applications perform it.

`wine-boundary.py` reproduces four distinct states:

1. A plain TCP listener before accept exposes only wineserver's FD. No client can be selected; it remains blocked.
2. Parent alpha and inherited child beta both materialize their Unix FDs: all three holders are reported, traffic is denied, and an earlier pending approval becomes stale.
3. Child beta inherits a Windows handle but waits before touching it. Only alpha and wineserver appear in `/proc`. **The opt-in model cannot see the dormant second recipient.** This is a demonstrated counterexample to treating descriptor holders as the complete recipient set.
4. Alpha exits while beta is dormant: only wineserver holds the Unix FD; attribution denies. After beta materializes the FD, it gains its own association and a different fingerprint.

Thus the supported threat model excludes cross-process dormant handle sharing, arbitrary same-user descriptor manipulation, runtime tampering and external multiplexing proxies. The opt-in mode is useful for ordinary independently owned fixture sockets under those assumptions; it is not reliable transparent enforcement for every Windows application. Default mode does not take this assumption. No game/Proton validation is implied.

## Historical next step before runtime-table observation

The missing observation is the mapping from a server socket object to **every live Windows handle reference**, including creation, inheritance, duplication, close and client exit before FD-cache materialization. A syscall hook observing only socket creation or SCM_RIGHTS cannot reconstruct dormant Windows handles. Full Wine-protocol/lifecycle tracking would require matching-version protocol parsing or focused probes and explicit loss handling; a generic eBPF subsystem does not solve that automatically.

The smallest optional alternative is a fresh network namespace and dedicated Wine server instance per opt-in launch, so the namespace can identify a launch even when the only visible descriptor belongs to its broker. A separate prefix (or a disposable prepared prefix copy) may be needed to avoid Wine's shared-server rendezvous; do not silently rewrite existing prefixes or launcher settings. This is proposed, not implemented or required by basic native operation. It does not separate helper processes within that launch or traffic already multiplexed by an external relay. Any implementation should remain explicit and validate receiver behavior before claiming coverage.

## 2026-10-16: optional runtime-table adapter (result B)

The earlier FD-only boundary is preserved; it is no longer the only available
observation. `internal/identity/table.go` plus `experiments/wine-table/probe.c`
implements an explicitly enabled **IPv4 incoming TCP-listener/UDP census**.
It does not change the Windows target or installed runtime. The PE helper runs
beside the fixtures in their prefix. This is a practical next product path;
launch isolation is not required by these results.

### Selected evidence and alternatives

`GetExtendedTcpTable(OWNER_PID_LISTENER)` and `GetExtendedUdpTable(OWNER_PID)`
expose endpoint/Windows-PID rows. In the inspected Wine 11.19 source,
`enum_handles_of_type` visits each process handle table, and
`get_tcp_connections`/`get_udp_endpoints` serialize each socket handle's owner.
This includes inherited references before a Unix FD is materialized. The
[iphlpapi implementation](https://github.com/wine-mirror/wine/blob/wine-11.19/dlls/iphlpapi/iphlpapi_main.c)
and [NSI TCP implementation](https://github.com/wine-mirror/wine/blob/wine-11.19/dlls/nsiproxy.sys/tcp.c)
carry those rows to the public API. No implementation source was copied.

| Candidate | Concrete information / decision |
| --- | --- |
| Public runtime owner tables | Selected: current handle holders and endpoints, no tracing privilege or internal protocol layout. Requires a helper in that server session and functioning NSI services. |
| `SystemExtendedHandleInformation` | PID/handle/type, but Wine's Object field is zero; cannot alone join a handle to the kernel socket. |
| Server debug/protocol observation | Could follow handle operations; debug output is not established as a complete loss-detectable census. A protocol observer must decode version-specific requests, replies, inheritance and reuse. Not implemented. |
| Syscall/eBPF socket hooks | See kernel sockets or FD transfers, not dormant Windows handles. Server handle-table probes would need internal symbols/layouts and separate privilege validation. Not needed or attempted here. |

Creation, bind/listen, duplication, inheritance and close affect the server's
current handle tables. Snapshots observe the resulting holder set, **not every
intervening event**. An operation requester, a handle holder and an actual
receiver remain distinct concepts. A shared socket yields multiple candidates,
even before either recipient calls recv/accept. Repeated handles in one process
are deduplicated; multiple processes are not merged by executable name.

### Corroboration, generations, bounds and recovery

The adapter preserves raw Unix FD holders. It adds separate Windows PID + process
creation-time + full-image-path rows. It requires one kernel socket, complete
visible FD coverage, the configured broker executable, matching namespace/user/
prefix, and a reciprocal Unix peer channel from the uniquely mapped observer
image to that broker. Windows paths must resolve to a currently corroborated
mapped executable revision; deleted-image mappings are rejected. No fabricated
Linux PID is assigned to a Windows owner; API authorization uses the broker's
corroborated UID, while policy uses the Windows application's own key/revision.

Two matching runtime snapshots bookend a second kernel-cookie/FD census.
Fingerprints include the socket cookie, native process starts/revisions, Windows
process generations, selected holder set, image revision and observer-instance
generation. Delayed decisions and retained-packet release repeat the resolution.
An observed listener replacement, holder change or observer failure cannot reuse
the old pending/cached result. Unknown/multiple holders never receive a single-app
Allow. The configured table path does not fall back to the weaker FD association
for that runtime when its evidence fails.

Limits: 256 KiB helper table buffer, 4096 rows, 1 MiB output/parser bound, one
outstanding request, two-second response deadline per snapshot, no retained
payload. Runtime APIs can allocate their own internal temporary tables; this is
not a cap on the entire Wine runtime's memory. API errors, truncated output,
EOF, overflow, version mismatch and deadlines disable the observer until explicit
daemon restart. There is no event stream whose lost events could silently leave
an old incremental model. Undetected runtime enumeration bugs remain outside the
supported build assumptions.

Late observer startup works: a current census reconstructs the holder set.
Wine's prefix must finish initialization; an incomplete prefix initially returned
error 2 from the owner-table API and was correctly rejected. A wineserver restart
invalidates the peer/process evidence and normally terminates its helper. Recovery
requires starting a new daemon/helper and new decisions; no old model is restored.
Direct server-restart recovery has not been separately exercised.

### Supported builds and exact results

- Installed Wine `11.19`, broker SHA256
  `b724233cd9e71f529c0ae30c090c862ac0d0ecfe760e604a2e1cdae160ab9fa6`.
- Installed `dwproton-11.0-4`, version file `1781221333 dwproton-11.0-4`,
  bundled `wine --version`: `wine-11.0 (CachyOS)`, helper reports `11.0`;
  broker SHA256 `3f84ad1bc5116a82ec54ee15588f000dbc5d570c9c77c6007d82545d375fd792`.
  [Upstream wine-11.0 server source](https://github.com/wine-mirror/wine/blob/wine-11.0/server/sock.c)
  is a baseline, not a claim that vendor patches match it byte-for-byte.

Both builds passed real alpha/beta ordinary TCP (no FIONREAD) and one-shot UDP
Allow/Block, reversed, in one runtime/prefix. Both passed late census of dormant
inherited TCP and UDP handles, parent exit leaving only the child's row, receiver
delivery after child release, denial of a still-shared dormant TCP listener,
listener replacement/stale approval rejection, and observer-loss rejection of a
retained UDP datagram. The helper never duplicates or touches target socket handles.

The ordinary same-user snapshot threat model excludes malicious runtime/helper
changes, hidden external descriptor recipients, and adversarial transfer/ABA races
between the final census and NFQUEUE verdict. A cookie identifies the kernel
socket generation, not a Wine handle-object generation. Numeric handle reuse,
WSADuplicateSocket, IPv6 Wine ownership and arbitrary other runtime builds still
need dedicated tests. Close/process-exit and new-listener generations were tested;
that is not complete event coverage. Existing allowed TCP connections retain the
baseline conntrack fast path: this prototype controls initiation and does not
continuously reauthorize accepted-socket transfers. UDP and new TCP attempts are
rechecked. Do not advertise this as comprehensive hostile-process isolation.

### `lwp` and reproduction

Inspected `/home/flowgate-user/user_config/scripts/lwp` (resolved Bash script). It chooses
the newest-by-directory-mtime `dwproton-*` under
`$HOME/.steam/steam/compatibilitytools.d`, passes `PROTONPATH`, `WINEPREFIX` and
`STEAM_COMPAT_DATA_PATH` to `umu-run`, and normally defaults to `$HOME/Games/pfx`.
Its third argument accepts an absolute prefix override. Paths containing `#Hv`
force its shared RenPy prefix; these fixtures do not contain that marker.
Neither the original launcher nor its existing prefixes were modified/executed.

`scripts/acceptance/proton-fixture.sh` reproduces the selected Proton setup with a fixed
workspace-only prefix. It calls Proton's `runinprefix` (direct Wine child) to keep
helper stdin intact; Proton `run` goes through steam.exe and did not preserve this
interactive probe channel. `--init` uses Proton getcompatpath/winepath to initialize the prefix without steam.exe. UMU's runtime
installation/update layer and game-specific fixes are bypassed, Python bytecode
writes disabled, and all caches redirected to `.workspace`. This validates the
installed Proton runtime, not full UMU, pressure-vessel or Steam game integration.

```sh
. scripts/go-env.sh
go build -o .workspace/flowgate ./cmd/flowgate
scripts/build.sh windows
scripts/build.sh wine-table
# Complete Wine prefix setup once, in the disposable namespace:
scripts/lab.sh sh -c 'export WINEPREFIX="$PWD/.workspace/wine-prefix" TMPDIR="$PWD/.workspace/tmp" XDG_CACHE_HOME="$PWD/.workspace/cache" XDG_CONFIG_HOME="$PWD/.workspace/config" WINEDEBUG=-all WINEDLLOVERRIDES="mscoree,mshtml=" DISPLAY= WAYLAND_DISPLAY=; wineboot -u; wineserver -w'
scripts/lab.sh python3 scripts/acceptance/wine-table-test.py
scripts/lab.sh python3 scripts/acceptance/wine-table-lifecycle.py
export FLOWGATE_TEST_PROTON=/home/flowgate-user/.steam/steam/compatibilitytools.d/dwproton-11.0-4
export FLOWGATE_TEST_STEAM=/home/flowgate-user/.steam/steam
scripts/lab.sh scripts/acceptance/proton-fixture.sh --init
scripts/lab.sh python3 scripts/acceptance/wine-table-test.py
scripts/lab.sh python3 scripts/acceptance/wine-table-lifecycle.py
```

Run these sequentially. Tests set `FLOWGATE_WINE_TABLE_RUNNER`,
`FLOWGATE_WINE_TABLE_HELPER`, `FLOWGATE_WINE_TABLE_VERSION`, `WINEPREFIX` and
`FLOWGATE_WINE_BROKER` explicitly for `serve-lab`. The normal CLI remains unchanged;
the table adapter is not enabled by a broker variable alone. No real games,
Heroic/Lutris/Flatpak, VPN or additional distribution support is implied.

## Current integration: lifecycle, attachment and IPv6

### Lifecycle evidence and contract

`fixtures/windows-lifecycle.c` uses actual WSADuplicateSocketW and recipient
WSASocketW, without target injection or runtime changes. Both tested builds expose
the recipient in the public table at duplication preparation, before construction.
The tests record original/prepared/constructed/original-closed/final-closed rows,
recipient delivery, and actual reuse of a numeric Windows socket handle. Kernel
socket cookies change on close/rebind even when the process and numeric handle do
not. A retained UDP decision becomes stale at duplication preparation or reuse.
After the recipient constructs the socket, shared ownership is denied at an active
receiver. A transient FD-materialization change can first produce conservative
“ownership changed during census”; the stable shared census remains ambiguous.

An accepted TCP socket is also duplicated to beta. The already-approved connection
continues after alpha closes its accepted reference. This passes the **connection
initiation** product contract; it is not a bypass of a promised continuous-ownership
check. Rule replacement/deletion/expiry still affects new decisions and UDP,
without clearing marks on already-approved TCP. See SEMANTICS.md.

### Discovery and explicit attachment

`runtime-discover --runtime-bins DIR[,DIR]` reads `/proc`, broker executable identity,
SHA256, prefix, UID, namespaces, process start and helper peer count. It never
launches Wine or interprets a command from application metadata. Runtime bin
directories are explicitly trusted user input, not inferred executable commands.
Broker hashes are diagnostic evidence, not a build allowlist. Discovery reports
all matching brokers as candidates; attachment must negotiate a complete schema-2
owner census from the selected live broker before it can resolve an application.
The supported contracts are Wine 10.0 and the Wine 11.x owner-table family.
Wine 10.0 is validated with GE-Proton10-34; Wine 11 with Wine 11.19, DWProton 11.0
and GE-Proton11-6 (Wine 11.0). Other Wine 10 releases are not inferred compatible.
A different version outside those contracts,
malformed/incomplete census or unavailable helper produces an explicit attribution
failure. This is version-family compatibility, not proof of every vendor patch.
The first negotiated version is pinned for the observer generation. Exact broker,
UID, prefix, namespace, socket-cookie and executable corroboration remain required;
launch ancestry never grants permission. A successful census does not itself Allow
traffic. Read-only discovery cannot claim that attachment has already succeeded.

`serve-lab --attach-prefixes PREFIX[,PREFIX] --runtime-bins DIR[,DIR]` uses the same
observation pipeline, without per-prefix environment assembly. Each selected
prefix must already have exactly one live supported broker, be canonicalized
inside this checkout's `.workspace`, and have a workspace TMPDIR. The PE helper
must also resolve inside `.workspace`. Symlink escapes are rejected. The helper
runs as the caller, whose UID must equal the runtime's; host privileged-root
attachment is refused. UID zero mapped to the unprivileged lab user is permitted.
Foreign network/mount namespaces are not silently entered.

The child receives a small explicit environment and structured executable/argument
values. `WINESERVER=/usr/bin/false` prevents creating a replacement server if the
intended server disappears. Successful attachment requires the original broker
generation still to exist and the uniquely mapped helper to have reciprocal Unix
peer evidence to it. Cleanup kills only the helper process launched by FlowGate.
At most four runtime directories, four selected observers and 32 discovered
sessions are allowed. Discovery checks a five-second deadline; attachment checks
a ten-second total deadline with a two-second helper-response deadline. Ordinary
filesystem/proc reads are bounded in size, not hard real-time operations. There
is one attachment attempt, no automatic retries, and failure never selects the
weaker broker model. A separate observer/fingerprint belongs to each prefix.

Server death is sticky failure. A replacement server with the same prefix/path
cannot reuse the previous session generation. Explicit daemon restart/attachment
creates a new observer and new pending IDs. Both tested builds passed this case
and cross-prefix same-executable/service-port permission isolation. During forced
wineserver SIGKILL tests, ntsync clients sometimes remained alive and held their
sockets. The **test harness** cleans up only that disposable prefix's PE processes
before restarting; FlowGate does not kill application clients. Proton environment
paths can have trailing slashes, so the harness canonicalizes them. Earlier
relative-path discovery and broad IPv6 scope checks were corrected; final evidence
comes from the sequential runner, not intermediate failed runs.

Helper pipe schema is now explicitly `1`, with runtime version and requested
family in each response. Requests are `t4`, `u4`, `t6`, or `u6` followed by newline.
Unknown schema/version/family, malformed/incomplete data, EOF or deadline disables
the observer; unit tests exercise mismatches and sticky rejection. Existing helper
exit receiver tests are retained; new receiver tests cover server loss/recovery.
This is a snapshot census, not a complete handle-event stream or protection
against hostile same-user ABA transfers between observation and verdict.

### IPv6 matching

The helper uses the IPv6 OWNER_PID TCP/UDP table variants and emits address,
port, family and scope ID. Kernel diagnostics preserve AF_INET/AF_INET6 and read
INET_DIAG_SKV6ONLY. Known v6-only sockets cannot claim IPv4 flows; unknown v6-only
state stays a plausible candidate and cannot justify a v4-to-v6 table Allow.
Multiple plausible kernel sockets remain ambiguous, without guessed precedence.
IPv4-mapped addresses compare canonically but retain their observed family.

Both builds passed ordinary `::1` TCP/UDP Allow/Block and reversal, dual-stack `::`
wildcard reception over IPv4 and IPv6, mapped IPv6 binds, and a v6-only wildcard
beside a separate IPv4 application on the same port. Wine reports scope ID 1 for
loopback too; it is preserved, but does not make `::1` a link-local address.
Link-local/zone-sensitive policy is rejected until Windows-to-kernel interface
mapping is implemented. Non-loopback IPv6 and additional runtime builds are not
claimed validated. IPv6 was neither disabled nor broadly allowed.

### Reproduce this increment

Use the initialized workspace prefixes from the earlier commands. New tests clone
only the workspace prefix (preserving symlinks) for their second test session.
The original `lwp` was read again and is unchanged. Direct helper attachment uses
the selected runtime's Wine binary, and fixture setup uses `runinprefix`; neither
is full UMU/Steam/container integration or permission to touch game prefixes.

```sh
# Builds and runs all new tests sequentially in disposable namespaces:
scripts/checks/check-runtime.sh
FLOWGATE_TEST_PROTON=/home/flowgate-user/.steam/steam/compatibilitytools.d/dwproton-11.0-4 \
FLOWGATE_TEST_STEAM=/home/flowgate-user/.steam/steam scripts/checks/check-runtime.sh

# Inside an existing scripts/lab.sh shell, after fixtures are listening:
.workspace/flowgate runtime-discover --runtime-bins /usr/bin
.workspace/flowgate serve-lab --parent-netns "$FLOWGATE_PARENT_NETNS" \
  --attach-prefixes "$PWD/.workspace/wine-prefix,$PWD/.workspace/wine-session-second" \
  --runtime-bins /usr/bin
# For direct Proton sessions, select its .../files/bin directory and actual pfx paths.
# Another terminal in that same lab can use the existing pending/decide CLI/API.
```

`--wine-helper` optionally selects the built workspace helper; its default is
`.workspace/windows/table-probe.exe`. Legacy explicit environment configuration
remains for old tests, but cannot be combined with `--attach-prefixes`. Source
`scripts/go-env.sh` before manual Go commands. No additional privileges or runtime
updates were required. Existing game prefixes and launcher configuration remain
untouched.

## Launch provenance and permission scope (display; keys unchanged)

Observed host launch (read-only /proc, 2026-10-19): `bash ~/user_config/scripts/lwp
DS2.exe` → `python3 /usr/bin/umu-run DS2.exe` → srt-bwrap → pv-adverb → `python3
…/dwproton-11.0-4/proton waitforexitandrun` → Wine (`umu.exe`, `DS2.exe`,
`crs-handler.exe`, wineserver). `lwp` sets `WINEPREFIX=STEAM_COMPAT_DATA_PATH=
~/Games/pfx/<exe name without extension and spaces>` (RenPy `#Hv` paths share
`~/Games/pfx/RenPy`; a third argument overrides). Proton normally runs Wine in
`$STEAM_COMPAT_DATA_PATH/pfx` (`~/Games/pfx/DS2/pfx` exists; which prefix the
historical rundll32.exe used was not captured). Per-game by this script's
convention only — nothing FlowGate can verify.

Remembered rules bind the application key `UID + kind + prefix + executable
path` (+ file-stamp revision). Consequences, stated in `permission_target`:

- Proton's `rundll32.exe` maps `…/dwproton-11.0-4/files/lib/wine/x86_64-windows/
  rundll32.exe`. Two games with **different prefixes** produce **different keys**
  for that same file (tested: `scripts/acceptance/provenance-wine.py`, real Wine 11.19).
- In a **shared prefix** (umu default `~/Games/umu/umu-default`, `lwp`'s RenPy
  prefix, an explicit shared third argument), one Remember on the helper covers
  every game using that prefix. The UI therefore says "rundll32.exe in prefix X
  (shared by every game using this prefix)" and never "this game only".
- Another Proton build is another file path → another key; a Proton update that
  rewrites the file keeps the key but changes the revision (new prompt).
- For a while binds PID + start ticks: a relaunch is never covered. Under the
  broker model (two visible holders) it is unavailable and the target says so.

Provenance groups Activity rows under the game ("DEATH STRANDING 2: ON THE BEACH ·
DS2.exe", ProductName read from the real DS2.exe) and names the game in the
prompt ("via rundll32.exe") only for `evidence: verified`. Historical case (b) —
rundll32.exe PID 1195586, ended, ancestry never captured — stays without a game.

Verification: `go test ./internal/identity -run 'Provenance|Ancestry|Markers|
WineExe|Environment|PermissionTarget'`; `scripts/lab.sh python3
scripts/acceptance/process-rules-isolated.py --binary B --native N --run .workspace/RUN
--provenance` (SIMULATION: native fixture renamed to Proton paths, fake
umu-run/pv-adverb/proton scripts in `scripts/acceptance/provenance-sim`, real receivers);
`scripts/lab.sh python3 scripts/acceptance/provenance-wine.py --binary B --run
.workspace/RUN --prefix-source .workspace/wine-prefix --pe
.workspace/windows/alpha.exe` (real Wine processes, simulated launcher chain).
Real UMU/Proton/pressure-vessel launches were not executed.


## Current outgoing Proton support

The real `lwp` regression and current collector contract are documented in
[PROTON-LAUNCHER-REGRESSION.md](PROTON-LAUNCHER-REGRESSION.md). This supersedes the
older listener-only experiment for outgoing TCP on brokers with a validated live owner-census contract. Windows socket ownership, not Python launch ancestry or a global
wineserver permission, selects the application rule. Activity carries that
application separately from its Unix FD-holder evidence.

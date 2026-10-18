# Optional UDP collection owned by the root daemon

## Implemented; authenticated isolated kernel acceptance passed

The existing `serve` Go daemon now owns **one optional native helper** and feeds
its snapshots directly into Activity. No second Go collector process or UDP Unix
server is created. TCP and UDP arrive through the same Activity endpoint. Basic
startup leaves UDP disabled and does not load BPF, bind NFQUEUE, change nftables,
routes or Tailscale. Collection and enforcement remain separate.

New test binary: **`.workspace/flowgate-udp-daemon`**. The running host monitor
PID2095594/generationa0109011f97dad19dd723e7e483d7860 remains on its existing build,
non-enforcing, with no UDP attachment. It was not restarted or overwritten here.
Frontend consumer work is separate; it has not been integrated in this increment.

## Configuration and authority

A future explicitly authorized daemon launch can include:

```
serve --socket /run/flowgate-api/daemon.sock \
  --database /var/lib/flowgate/rules.db --uid 1000 --administrator \
  --udp-helper /absolute/reviewed/udp-collector --allow-traffic-control
```

These are arguments to the reviewed Go executable, **not an instruction to start a
second database writer**. A future host rollout needs the existing generation-
checked monitor Stop, retained executable/configuration and exclusive database
handoff from INTEGRATION.md. No host rollout/attachment is performed in this task.
Missing optional helper/BTF does not prevent daemon startup. The helper defaults
to `udp-collector` beside the executable; an explicit override must be absolute.
A matching ELF/protocol helper is pinned at startup into the already-validated
root API directory (0700 owned copy, bounded32MiB). Start executes only that copy,
never a request-supplied path. Rebuild/install fixes require a deliberate daemon
restart to pin the newly reviewed helper. Shutdown removes only its own copy.

Permissions are independent, additive fields:

- `can_view_measurements`: authorized Activity visibility, not proof of available
  counters. Existing observation UID/administrator scope still applies.
- `can_control_traffic`: Start/Stop authority. UID0 on the primary can administer
  collection; the selected administrator needs explicit root configuration
  **`--allow-traffic-control`**, which requires `--administrator`.
- `can_manage_rules` and `can_decide` do **not** confer collector authority.
- The read-only companion can view authorized status/Activity but cannot Start or
  Stop, including for an administrator. Ordinary peers cannot stop machine collection.

The helper filters the current network namespace, optionally all socket UIDs;
there is no namespace traversal. Administrator Activity includes system-service
and shared/unknown counters with honest ownership evidence. Ordinary projection
withholds foreign/mixed-UID rows; unresolved ownership never exposes machine UDP
bytes, even if socket-creation UID matches. Same-UID visible owners may see their
socket once, with partial coverage. Global miss counts and conditional loss details
are withheld from ordinary peers; their measurement view remains explicitly partial.
No shared/unidentified presentation group becomes a policy identity.

## API v1 contract

Capability: **`daemon-udp-monitor-v1`**. Capability is supported protocol, not
permission or BPF readiness. Existing `list` and `traffic-status` return:

```json
{"traffic_monitor":{"state":"disabled","available":true,"reason_code":"disabled","reason":"Explicit Start required; no collector attached","netns":"net:[fixture]","scope":"machine","partial":false,"missed_operations":0},"permissions":{"can_view_measurements":true,"can_control_traffic":true}}
```

Existing response generation/mode/enforcement/permission fields remain. Status:

- `state`: disabled, starting, active, stopping or failed.
- `available`: static helper/build/BTF inspection passed, **not** successful load.
- `reason_code`, `reason`: bounded actionable failure/support/lifecycle reason.
- `generation`: collector-attempt identity, absent/empty before first attempt;
  stable from starting through active/Stop. Restart creates a new one.
- `netns`, `scope` machine/self, `partial`, `missed_operations`, `collected`.
  Miss count is withheld for ordinary scope. Successful send/receive operations
  before cookie registration make coverage partial; missing bytes are not invented.

Start/Stop on primary:

```json
{"version":1,"operation":"traffic-start","generation":"<daemon-generation>","collector_generation":"<current collector generation or empty initially>"}
{"version":1,"operation":"traffic-stop","generation":"<daemon-generation>","collector_generation":"<current collector generation>"}
{"version":1,"operation":"traffic-status"}
```

Both mutations check the daemon generation and exact current collector generation.
`generation_conflict` means a new daemon; `collector_conflict` means the attempt
changed. Refresh status and obtain new user intent; never retry an old Stop against
a replacement. `forbidden` means no primary lifecycle authority; `unavailable`
means no manager in this mode. `collector_unavailable` covers static support,
retry bound, or Stop still pending; the attached status/reason explains the result.
Read status never starts/loads anything. No helper/configuration arguments are
accepted over IPC.

Start is asynchronous: starting is **not active**. Active requires actual load,
attachment and a valid first sampler result. Repeated current-generation Start
while starting/active returns that same run; stale repeated requests conflict.
Stop is serialized and bounded (2seconds response wait); disabled confirms owned
helper termination. A stopping/error response requires polling, not new Start.
There are at most3 start attempts per minute and no automatic retry/restart.
Lifecycle status and Activity are independently sampled; compare their collector
generations/timestamps and show a gap during transitions instead of combining old
UDP data with a new status. Client request epochs must discard replies started
before a mutation/reconnect.

Helper startup is bounded5seconds; each registration/reply exchange has a3second
watchdog including pipe writes. Diagnostics retain at most4096 stderr bytes.
Failure does not stop the Go daemon/TCP/rules. It exposes failed/unavailable, never
measured zero. GUI exit/client disconnect does not stop the owned helper. Unexpected daemon
death closes helper stdin, causing native exit and owned link/map cleanup; SIGKILL
can leave the inert pinned executable file, never a persistent BPF pin.

After lost ACK, fetch authoritative `list`/`traffic-status`. Do not automatically
replay Start or Stop, launch the legacy prototype, or infer success from an open
API socket. Reconnect must recheck capability, permissions, both generations and
state. No collector lifecycle request changes pending verdicts or stored policy.

## Measurement/compatibility

The selected-UID prototype and daemon manager share the same sampler and native
counter implementation. Machine scope adds a UID-filter switch; netns filtering,
cookie registration and successful-return byte arithmetic are retained. Programs
are renamed `fg_udp_sent`/`fg_udp_received` without changing their tracepoint hooks.
TCP transport bytes (including upload retransmissions) and UDP API-return bytes
remain separately labelled; incompatible aggregates are not summed. These are
application perspectives, not unique internet usage; VPN transport and inner
application traffic are distinct layers and are not guessed/deduplicated.

UDP counts successful send return bytes and non-PEEK/non-ERRQUEUE receive return
bytes, including the documented truncation/MSG_TRUNC semantics in UDP.md. It does
not count wire headers or prove delivery. Connected/unconnected sockets retain
**one total across all peers**, not repeated per-peer totals. Limits remain2048
registered cookies, no retained closed-socket/peer history. Namespace/cookie,
registration time and collector generation prevent lifetime mixing. Rates use
monotonic sample time, warm up on restart/reassociation, become unavailable on gaps,
and preserve TCP baselines across UDP generations. Unknown ownership does not
reset the root socket's counters, but ordinary projection withholds them.

Rebuilt prototype `udp-start` remains available and selected-UID API compatible.
Both paths use a native abstract Unix ownership socket local to the network
namespace (`flowgate.udp.accounting.v1`), without filesystem locks/pins. A second
helper refuses before loading. Startup also inspects existing legacy tracing
programs named sent/received and refuses; an unrelated matching name may cause a
conservative refusal. New renamed programs in different namespaces do not collide.
Unmodified older binaries do not participate in this lock; do not run them alongside
collection. External administrator configuration changes are not continuously
attested. Separate prototype snapshots are never merged into daemon counters.

Minimum requirements: optional clang/BPF/libbpf/bpftool build tools and native
libraries (Go does not link libbpf), matching helper machine protocol marker,
kernel BTF and sock_send_length/sock_recv_length tp_btf hooks. Load/attach and
inspection of pre-existing tracing programs require initial-user-namespace BPF/
perf/admin permissions allowed by that kernel. User-namespace CAP_NET_ADMIN is
insufficient. Missing/denied support remains explicit; no security-setting bypass.

## Focused verification and exact next action

```
scripts/check-daemon-udp.sh
# Additional initial-user-namespace kernel check; run interactively as desktop user:
scripts/check-daemon-udp.sh --kernel
```

Default run uses disposable user/net/PID/mount namespaces and actual production
serve/API/helper. It passed actual denied-load -> failed -> Stop, read-only denial,
both generation guards, ongoing TCP, unchanged empty rules, unchanged nftables and
IPv4/IPv6 routing snapshots. Actual error: `collector_inspection_denied: ... Operation
not permitted`. Native helper and CO-RE build passed. Race/vet tests cover serialized
Start/Stop, helper/protocol failure, restart generation/rate baselines, bounded
retries, explicit permissions and privacy/shared/unknown projection. Synthetic
lifecycle/rate tests establish implementation behavior, **not kernel accuracy**.

The --kernel run is interactive (desktop-user sudo); an earlier agent `sudo -n`
attempt was refused and not retried. It overlays only the authorized runtime/storage
paths in its private mount namespace, backed by workspace files; it never uses the
host monitor DB.

**Kernel acceptance passed** (user-authenticated, `--kernel --reuse-build`):
`.workspace/daemon-udp-1792270674-2133903/{verification.log,result.json,
artifacts.sha256}`. Real UDP4 and UDP6 connected/unconnected/multi-peer API byte
counts equal native receiver/send fixture counts; one owned helper; duplicate
Start; namespace exclusion of a second helper; Stop; restart baseline (no spike);
stale Stop rejected; owned helper SIGKILL -> failed -> restart; TCP continuous;
ordinary self projection withholds a foreign root socket and has no lifecycle
authority; rules/database unchanged; nftables and IPv4/IPv6 routes unchanged.
Combined sample: 3.00s, daemon+helper CPU 0.020s, RSS 20736KiB (probe time in
callers excluded). No live-host BPF was attached.

Actual unprivileged sandboxed Wayland consumer Enable -> failed -> Stop was verified
against an owned isolated daemon; TCP remained available and GUI exit left daemon/
collector state intact. UI evidence is in the frontend worktree
`.workspace/daemon-udp-ui-JBH2BD`; it does not demonstrate measured kernel UDP.
Its code remains UI-owned and is not merged here.

Evidence: `.workspace/udp-consolidate-tests.log`, `udp-daemon-verification.log`,
`udp-daemon-final-fixture.log`, `udp-daemon-kernel-attempt.log`,
`daemon-udp-*/actual-load-error.json`/`api-example.json`. Baseline with UDP denied:
3.00seconds,0.010s daemon CPU,22068KiB RSS in the final fixture
(21648KiB in the preceding run). This is TCP/observer idle cost only,
**not consolidated BPF overhead**. The prepared privileged branch records a bounded
combined sample when authenticated; probe time charged to callers is excluded.

First authenticated --kernel run (`.workspace/daemon-udp-1792270174-2127523`)
passed receiver-backed UDP4 and UDP6 accounting, then stopped at the harness's
helper lookup after Stop/restart: `AssertionError: []`. Diagnosis: Go forks the
helper from whichever OS thread runs the Start goroutine, and
`/proc/PID/task/TID/children` is per-thread, so reading only the main thread's
file is nondeterministic (first lookup in that run happened to succeed). The
helper was alive: the preceding step had just measured new-generation rows, which
become unavailable when the helper exits. Reproduced without privilege
(`.workspace/repro-children.log`: main-thread file 26/40, union 40/40;
`.workspace/native-pid-test.log`: `[]` with live forking thread). The harness now
takes the union over all daemon tasks and requires exactly one direct child whose
pinned path and SHA-256 match the reviewed helper. No daemon code changed. The
harness now also appends to `<run>/verification.log` so passed stages survive a
later failure, and records `artifacts.sha256`. `--reuse-build` skips race/vet/build
and reuses the existing workspace artifacts.

For UI test attachment only, `check-daemon-udp.sh [--kernel] --reuse-build --hold
[--traffic]` keeps an owned daemon with the collector **disabled** and writes
`<run>/ready.json` (`socket`, `monitor_socket`, both under `<run>/api/`). Plain
`--hold` waits on stdin; `{"operation":"transfer"}` drives owned UDP4/6 fixtures.
`--traffic` adds one UDP4/6 + TCP exchange per second and atomically replaces
`<run>/receiver.json` after each exchange: per fixture `family`, namespace-local
`pid`, `cookies`, cumulative `uploaded`/`downloaded`. Fixtures persist across
collector Stop/Start. End with a `quit` line, `touch <run>/quit`, or Ctrl+C
(stdin EOF ends plain `--hold` only); the harness then removes fixtures, daemon and
helper. Userns mode demonstrates real load failure; --kernel needs the interactive
isolated permission path. It never accepts host mode.

## Captured authenticated API example (isolated fixture only)

Real production serve in the disposable user namespace, before denied native
load. Response excerpts include no unrelated inventory. This is not kernel-byte
accuracy evidence.

```json
{
  "request": {
    "version": 1,
    "operation": "traffic-start",
    "generation": "d50eaef1392caa088c6a251d1bf331b3",
    "collector_generation": ""
  },
  "response": {
    "version": 1,
    "generation": "d50eaef1392caa088c6a251d1bf331b3",
    "permissions": {
      "can_view_measurements": true,
      "can_control_traffic": true,
      "role": "administrator",
      "observation_scope": "machine",
      "policy_scope": "machine",
      "can_manage_rules": true,
      "can_decide": false
    },
    "traffic_monitor": {
      "state": "starting",
      "available": true,
      "reason_code": "starting",
      "reason": "Awaiting actual BPF load/attach and first sample",
      "generation": "87e247abe732ce04158bbc95cf7ccfe1",
      "netns": "net:[4026534404]",
      "scope": "machine",
      "partial": false,
      "missed_operations": 0,
      "collected": "0001-01-01T00:00:00Z"
    },
    "enforcement": {
      "profile": "",
      "state": "stopped",
      "detail": "Non-enforcing root daemon: observation and stored policy only; no queue or firewall rules; optional UDP accounting is separately controlled",
      "stops_at": "0001-01-01T00:00:00Z"
    },
    "capabilities": [
      "conditional-rule-delete-v1",
      "explicit-administrator-v1",
      "monitor-stop-v1",
      "policy-explanations-v1",
      "observed-rule-create-v1",
      "daemon-udp-monitor-v1"
    ]
  }
}
```

The following authoritative status reported the actual failure:

```json
{
  "state": "failed",
  "available": true,
  "reason_code": "permission_required",
  "reason": "BPF helper did not report READY; helper: collector_inspection_denied: cannot exclude an older tracing collector: Operation not permitted\n",
  "generation": "87e247abe732ce04158bbc95cf7ccfe1",
  "netns": "net:[4026534404]",
  "scope": "machine",
  "partial": false,
  "missed_operations": 0,
  "collected": "0001-01-01T00:00:00Z"
}
```


## Evaluation continuity evidence

The focused real-BPF fixture `.workspace/evaluation-udp-1792313673-2574300` passed
UDP4/6 accounting continuity across incoming evaluation Start/Stop with the same
daemon/helper/collector generation and socket baselines. Exact byte counts and
separate Allow/Block receivers, TCP and Decision Log checks passed; foreign rules
and routes unchanged. See INTEGRATION.md for the precise source and combined UI
release. Host accounting remains on its existing build; no rollout occurred.

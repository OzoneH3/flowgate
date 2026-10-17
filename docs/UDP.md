# Optional UDP accounting — verified in isolation

The authenticated run `.workspace/udp-verified-o2oghdyo` passed the full native
IPv4/IPv6 receiver and lifecycle suite on x86-64 CachyOS kernel 7.2.9-2-cachyos,
plus actual unprivileged Wayland measured-rate checks (**3/3**, UID 1000).
`verification.log`, `wayland.log` and `result.json` preserve the evidence; the latter
records binary hashes, namespace, kernel and UID. Actual captures are
`udp-measured-wayland.png` and `udp-measured-narrow.png` in the same directory.

No verifier/attachment/accounting failure was demonstrated. Earlier EPERM was a
permission limitation of the user namespace; the user authenticated the scoped
initial-namespace privilege needed to load probes into the disposable test run.
Live-host collection and host networking/firewall changes were not performed.

## Selected source and byte contract

Two CO-RE `tp_btf` programs attach to the kernel's `sock_send_length` and
`sock_recv_length` tracepoints. These take the actual `struct sock`, return length
and flags, rather than guessing from a tuple or the caller's PID. They record
only UDP AF_INET/AF_INET6 sockets of the explicitly selected UID and current
network namespace. Hook registration is global, but non-target namespaces/UIDs
produce no records; there is no payload, address, PID or command-line event log.
Tracepoint/BTF definitions are detected during load/attach; unsupported kernels
fail without affecting basic TCP monitoring. No kernel-version-only support claim.

- Upload: nonnegative successful send-operation return bytes. Failed sends add
  nothing. Corked/MSG_MORE or GSO sends count the API-accepted payload, not the
  later transmitted packet sizes. A later error/drop does not undo an earlier
  successful return. No remote-delivery claim.
- Download: nonnegative receive-operation return bytes, excluding MSG_PEEK and
  MSG_ERRQUEUE. Ordinary truncation counts the returned copied length, excluding
  discarded remainder; input MSG_TRUNC can return/count the full datagram length.
  Repeated peeks count nothing. Zero-length successful datagrams add zero bytes.
- No IP/UDP/link headers or machine-wide statistics. No queue-occupancy estimates.
  Drops before a successful receive are not counted as download. GRO/GSO are
  represented by the API-returned aggregate length, not packet/datagram counts.
- Only operations reaching these tracepoints are covered. Kernel-bypass paths and
  future changes to the hook contract are not guaranteed. Datagram edge semantics
  passed the user-authenticated IPv4/IPv6 receiver comparison; kernel bypass and
  offload variants were not separately exercised.

TCP retains its transport payload definition (including upload retransmission).
UDP is labelled **API-reported socket bytes**. Mixed TCP/UDP application/process/
Unidentified aggregates say **Mixed sources**, not a misleading sum. Each socket
still has numeric rates/totals. No per-peer split is claimed: connected and
unconnected sockets show one total across all peers, never repeated per remote.

References inspected: matching installed 7.2.9-2-cachyos kernel trace header and BTF,
[tracepoint declaration](https://github.com/torvalds/linux/blob/master/include/trace/events/sock.h),
[call sites](https://github.com/torvalds/linux/blob/master/net/socket.c),
[UDP receive/send implementation](https://github.com/torvalds/linux/blob/master/net/ipv4/udp.c).
All collector code is our own; generated BTF headers/skeletons stay in `.workspace`.

## Stable identity and bounded state

The selected network namespace, 64-bit diagnostic socket cookie and collector
generation define accounting lifetime. Inet_diag assigns cookies and registers
up to 2048 current selected-UID UDP sockets in a non-LRU map. No PID, FD or tuple is
used as the BPF key. UDP Activity row IDs now also omit changing endpoints, so
connect/disconnect does not replace a still-live socket row; namespace, cookie,
inode, protocol and family remain part of the key. TCP IDs are unchanged. Shared descriptors count once, and SO_REUSEPORT sockets have
separate cookie keys; attribution stays with the existing conservative observer.
The expanded native fixture suite verified shared FD handoff, closure/rebind,
SO_REUSEPORT selection and controlled collector Stop/restart against actual counters.

A socket may send/close before its first registration. Such events are not
invented or assigned to a reused endpoint: `missed_operations` increases and
coverage is visibly partial. Every unmatched target operation increments this
counter, including pre-registration/zero-cookie operations. Counters are updated
atomically without an event stream, so there is no ring-buffer overflow. Registration
failure/census overflow fails the collector; it does not silently evict into
apparently complete totals. Closed cookies are removed on the next one-second
census; no peer history or closed-socket history is retained.

Totals start at cookie registration, labelled observed since that time. Rates use
the collector's monotonic sample_ns clock; repeated snapshots have no fresh rate
instead of a zero sample. First samples warm up without rates; reset/new
registration starts a new interval without a spike. Owner reassociation preserves
socket totals. Missing/stale/disconnected collector data is unavailable, not zero.
Health exposes generation, namespace, missed count and collection time. The API
retains up to 2048 rows; the ordinary Activity response exposes UDP health and
per-row measurements without duplicating the collector's full cookie map.

## Privilege, activation and Stop

Ordinary startup remains read-only and unprivileged:

```sh
scripts/run-desktop.sh
```

Build the optional collector separately (does not load it):

```sh
scripts/build-udp.sh
```

Requires clang with BPF target, bpftool, libbpf development headers/pkg-config and
kernel BTF. These are present here (libbpf 1.7.0); no packages were installed.
The helper dynamically links libbpf/libelf/libc and compression dependencies; it
is not a static portable binary. Go's basic monitor does not link libbpf.

The Activity action **Enable extended traffic monitoring** asks explicitly,
launches Konsole/system sudo, and leaves Qt unprivileged. The tested prototype
remains opt-in; live-host coexistence and other kernels are not validated. The held terminal shows authentication or BPF errors.
Cancellation/refusal leaves TCP and the Unidentified group available. There is no
firewall activation, sudoers change, service, autostart or automatic retry.

The equivalent explicit collection-only terminal command is (not run on the host
during development):

```sh
sudo .workspace/flowgate udp-start --uid "$(id -u)"
# In another unprivileged terminal, or Stop extended monitoring in Activity:
.workspace/flowgate udp-stop
```

The selected user's `/run/flowgate-traffic/UID/api.sock` is mode 0600 in root-owned
validated ancestors. The root supervisor pins a private executable helper copy
before launch; later workspace builds cannot replace it. IPC accepts only v1
list/Stop, authenticates SO_PEERCRED and rejects policy mutations. Clients require
a root-owned peer and matching network namespace. It cannot start helpers from API
metadata. Stop affects this collector only; firewall state is untouched. Closing
Qt does not stop it; Stop or Ctrl+C in its terminal does. No BPF pins are created;
closing the owned links/maps detaches them. A supervisor crash closes the helper
pipe, causing helper exit. SIGKILL can leave a stale Unix pathname; startup refuses
to overwrite it. Stale-socket recovery is not automated in this experiment.

Load requires initial-user-namespace CAP_BPF and CAP_PERFMON (or applicable
CAP_SYS_ADMIN fallback), permitted BPF/perf policy and BTF tracepoint support.
CAP_NET_ADMIN inside a disposable user namespace is insufficient. No tracing,
security or sysctl settings were changed to bypass that restriction.

## Verification and next authenticated step

Reused real kernel evidence: user-reported UDP4/UDP6 PASS output and local
`.workspace/udp-privileged-1792255664/collector.log` (READY). Earlier C/BPF, API,
Go/race/vet, TCP and read-only desktop results remain indexed in STATUS.md.

The expanded one-command workflow builds the application/test fixtures as the
**ordinary desktop user**, authenticates only its disposable namespace, and runs
native alpha/beta receivers under that user's UID. It checks:

- UDP4/UDP6 connected/unconnected/wildcard and multiple-peer counts, loopback,
  truncation, repeated PEEK, failed sends and idle zero rates.
- Shared descriptors, parent exit into a distinct executable, unchanged socket
  totals, final close, and SO_REUSEPORT selected-receiver counts.
- Exact local-port rebind with a new cookie, old-state removal, collector Stop/
  disconnect/restart with fresh baselines, and visible pre-registration misses.
- A Wayland Qt process **outside** the namespace, UID nonzero, consuming the
  namespace observer through a private Unix socket. It captures actual measured
  rows, numeric sorting, stable selection, Unidentified and narrow-window behavior.
- Bounded collector+helper process CPU/sum RSS and map occupancy, with registered-
  transfer misses checked separately from a deliberate pre-registration miss.
  This CPU figure excludes probe time charged to the calling application; BPF
  kernel statistics are not enabled globally.

Run from your desktop terminal, without prefixing the script itself with sudo:

```sh
cd /home/flowgate-user/Apps/flowgate
scripts/check-udp-isolated.sh
```

The script requests system sudo only for `unshare --net --pid --fork --mount-proc`
and the namespace harness. It brings up only that namespace's loopback. BPF
records are filtered to that namespace and UID. The unprivileged coordinator opens
Qt, preserves fixture logs, then cleans up the namespace processes; nothing installs
or changes host routes, firewall, tracing settings, services or permissions.
Artifacts are retained under `.workspace/udp-verified-*/`: `verification.log`,
`wayland.log`, result metadata and measured/narrow screenshots. Binary hashes and
kernel identity are recorded with successful results.

## Recorded outcome and remaining limits

The expanded run passed all cases listed above. Actual steady-transfer collection
used 3.52s elapsed, 0.010s collector+helper CPU (0.28% of one CPU), 14916KiB sum RSS,
and 85/2048 registered rows. No capacity limit was reached and registered-transfer
misses were 0. The run deliberately created one unregistered datagram: the final
miss counter is 1 and the UI correctly marks partial coverage. No attempt is made
to infer missing bytes. BPF execution time charged to fixture callers is not
included in the collector process CPU measurement.

The reuseport case uses two receiver sockets owned by one fixture; kernel-selected
socket counts were independently compared. Distinct alpha/beta applications and
cross-executable shared-FD handoff were separately exercised. PEEK, ordinary
truncation, MSG_TRUNC, failed sends, multi-peer traffic and idle were checked over
IPv4/IPv6. GRO/GSO, kernel-bypass paths, adversarial same-user FD changes, other
kernels/distributions and live-host load/coexistence remain unverified. Ordinary
collection still needs the initial BPF/perf privileges and supported tracepoints.

The post-run `UDP fixture: Success` line was a teardown diagnostic: a dormant
fixture child saw EOF when its parent was terminated before handoff. EOF now exits
quietly; `.workspace/udp-cleanup-check.log` checks IPv4/IPv6 teardown. No measured
operation or production counter path changed. Vulkan_INCLUDE_DIR was an optional
Qt configure warning, not a failed build or a missing requirement for this utility.

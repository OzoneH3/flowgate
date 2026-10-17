# Optional UDP accounting — implemented experiment, kernel verification blocked

The optional collector and desktop plumbing build, but **UDP kernel accounting
has not passed receiver verification here**. The existing user namespace cannot
load even a trivial BPF program (`EPERM`), and a scoped `sudo -n unshare --net ...`
attempt requires interactive authentication. Do not treat compilation, synthetic
API/UI tests, or real UDP fixtures with unavailable counters as accounting proof.
Do not enable this on the host before completing the isolated test below.

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
  are selected from source inspection and fixture behavior, **not yet verified
  against the loaded BPF program**.

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
used as the BPF key. Shared descriptors count once, and SO_REUSEPORT sockets have
separate cookie keys; attribution stays with the existing conservative observer.
Those lifecycle cases still need privileged receiver verification.

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
launches Konsole/system sudo, and leaves Qt unprivileged. It is marked experimental
pending isolated validation. The held terminal shows authentication or BPF errors.
Cancellation/refusal leaves TCP and the Unidentified group available. There is no
firewall activation, sudoers change, service, autostart or automatic retry.

After isolated validation, the exact equivalent explicit terminal command is:

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

## Verification and next authorized step

Built C/BPF and Go/Qt successfully. Focused Go race/vet, real Wayland unavailable/
cancel handling and synthetic mixed-source display passed. A **synthetic helper**
exercised the actual private API, mutation refusal and Stop/cleanup in a namespace.
Real unprivileged datagram fixtures exercised IPv4/IPv6 connected/unconnected
traffic, multiple peers, PEEK/truncation/failed-send return semantics; they are not
BPF-counter verification. Existing TCP receiver/UI tests remain green.

Evidence: `.workspace/udp-load-denied.log`, `.workspace/udp-isolated-denied.log`,
`.workspace/udp-api-final.log`, `.workspace/udp-go.log`, `.workspace/udp-wayland-final.log`,
`.workspace/udp-tcp-receiver-regression.log`, `.workspace/udp-tcp-regression.log`.
The last file covers the preserved single Unidentified grouping. No BPF event-loss,
UDP collector overhead or receiver-accurate UDP counters can be reported yet.

Prepare/review this precise additional privileged operation:

```sh
. scripts/go-env.sh
go build -o .workspace/udp-test-driver ./fixtures/udpdriver
scripts/build-udp.sh
scripts/check-udp-isolated.sh
```

The last command uses system sudo to create a **new** network/PID/mount namespace,
bring up only its loopback and run the workspace verification driver. BPF is
filtered to that namespace/UID; no live-host UDP data or firewall changes are
requested. The fixture driver's direct helper path is test-only, not a production
security-directory bypass. Review fixes after verifier output before trusting host
activation. Follow with shared/reuseport, reuse/restart/loss and a real unprivileged
Wayland UDP-rate journey; these remain unverified, not passed.

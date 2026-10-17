# Activity traffic accounting

## Implemented coverage

Normal `scripts/run-desktop.sh` collects real **TCP IPv4/IPv6** upload/download
rates and observed transferred bytes without root, packet capture, nftables,
NFQUEUE, eBPF, services or Wine helpers. No activation is necessary. The existing
five-minute evaluation is independent and remains explicit. The optional UDP collector passed isolated kernel/Wayland verification and is
never automatically started. See UDP.md for activation and coverage.

The bounded socket census requests `INET_DIAG_INFO` and reads Linux `TCP_INFO`
`tcpi_bytes_sent` and `tcpi_bytes_received`. Responses shorter than the fields are
unsupported, not zero. Runtime field availability is tested, not inferred from
kernel version. Requires Linux INET_DIAG/TCP diagnostics and permission to query
the current network namespace. The verified host is x86-64 CachyOS kernel
7.2.9-2-cachyos; other kernels/distributions/architectures are not newly validated.

Upload counts transmitted **TCP payload bytes, including retransmissions**;
download counts received TCP payload accepted by TCP, not reads by the process.
IP/TCP/link headers and pure ACK traffic are excluded. Socket queue occupancy is
never used as traffic. Offload segmentation does not multiply payload totals.
Loopback shows the sender's upload and receiver's download on their separate
sockets: they are two application perspectives, not an interface-wide total.
The same shared socket is displayed/counted once, not once per descriptor holder.

**Basic unprivileged UDP accounting is unavailable** for IPv4/IPv6.
The inspected UDP diagnostic interface does not supply transferred-byte counters.
No per-peer UDP totals or application UDP estimates are claimed. The optional UDP.md adapter supplies API-reported payload counts when explicitly
loaded, and passed the isolated native lifecycle/Wayland suite. The Enable action is
explicit and collection-only; basic UDP remains unavailable
without that collector.

Kernel source references inspected (public UAPI, no implementation code copied):
[tcp.h](https://github.com/torvalds/linux/blob/master/include/uapi/linux/tcp.h),
[tcp_get_info](https://github.com/torvalds/linux/blob/master/net/ipv4/tcp.c),
[udp_diag](https://github.com/torvalds/linux/blob/master/net/ipv4/udp_diag.c).

## Lifetimes and rates

Each socket uses namespace, diagnostic cookie, inode, family, protocol and endpoints,
not PID or tuple alone. Totals are counter differences **observed since the first
sample**, never lifetime totals. This baseline and its timestamp appear in details.
First samples have observed total zero but unavailable rates. Differences divided
by monotonic elapsed time produce B/s, normally sampled about once per second plus
collection cost. Idle measured connections return to 0 B/s. A user's configured
slower refresh produces average rates over that interval, not instantaneous peaks.

Missing sockets/counters remove their sample state; counter decreases, observer
restart or a gap over 60 seconds begin a new baseline with unavailable rates.
Closing sockets are removed, not retained as cumulative history. Very short
connections between censuses can be missed. Socket payload counter sampling and
process census are not atomic. Ownership changes preserve socket measurements,
but suppress the rate for that transition interval. Application/process totals
sum their **currently visible uniquely held sockets' observed intervals**, not
historical bytes exclusively transferred by that owner. Shared sockets stay outside
individual application aggregates. Missing coverage is `—`, never zero; `*` marks
partial aggregates. Details give measured/total socket counts. Listeners and
TIME_WAIT generally have no supported traffic counters, also making groups partial.

State is bounded by 2048 current rows; no rate history is retained. Existing bounded
process caching still checks PID/start and executable revision and refreshes metadata
within 5 seconds; no process scan or executable hash is performed per packet.
Observer jobs remain serial, and API polling does not launch collection jobs.
Errors clear live state; old snapshots are not displayed as fresh after reconnect.

## Unidentified group and ownership evidence

One stable, initially collapsed **Unidentified (N)** group contains unknown and
nonexclusive/shared sockets. Each child has its protocol/endpoints/state/traffic
and its own ownership explanation. Search/filter change the displayed group count
and sums. Expanded/collapsed state survives refresh/filter and disappearance/reentry
within the window. Stable socket IDs retain selection as ownership becomes known;
measurements are not duplicated or reset by that presentation move.

This is not an application identity or a permission target. Known executable groups
continue to use application key/revision and PID/start identities. The observer
reports only what it saw:

- **Unknown owner:** no matching visible FD. Census-wide inaccessible directories
  are reported as a possible coverage limitation, not proof of this socket's owner.
- **Owner inaccessible:** an FD holder was observed but executable access was denied.
- **Owner changed during inspection:** process identity/exit checks changed.
- **Owner metadata unavailable:** a holder was seen but identity could not be validated.
- **No userspace socket inode:** kernel diagnostics returned inode zero, commonly
  TIME_WAIT; no descriptor association is available.
- **Shared socket:** multiple visible holders, counted once and individually listed
  in details. Truncated ownership stays explicitly marked.

A process can retain sockets from another namespace; the collector scans visible
process descriptors rather than guessing association from a process's current
namespace. Sockets outside the observer's namespace are outside coverage. Names,
ports, interpreter/Wine labels and inaccessible PIDs are never used to invent owners.

## Reproduce

```sh
QT_QPA_PLATFORM=wayland WAYLAND_DISPLAY=wayland-0 scripts/check-traffic.sh
```

Ordinary workspace loopback fixtures compare exact 262144-byte upload and 131072-byte
download bursts on TCP4/TCP6, check idle, separate executable paths, shared holders,
hidden ownership, real visibility restoration, observer restart and closure.
Synthetic Go tests cover counter reset, cookie/endpoint reuse and missing samples;
numeric endpoint reuse is not claimed as exercised by the real fixture. Qt uses
actual traffic for table/sort/partial aggregation and a separate synthetic snapshot
for deterministic regrouping. No firewall or privileged collection is used.

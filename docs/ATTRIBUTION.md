# Native Activity ownership

## Privileged visibility and administration

The selected-UID limitation describes the ordinary prototype endpoint. A root
`serve`/host controller now supports an explicit selected-peer administrator grant
and machine-visible native Activity; ordinary privileged-endpoint peers receive a
self projection. See AUTHORIZATION.md. Root can reduce proc visibility gaps but
never converts shared, ownerless or namespace-invisible sockets into guessed
applications. Accounting/socket IDs remain unchanged by API privacy projection.
The separate UDP prototype remains selected-UID; no machine-wide BPF change is made.


## Current implementation

The read-only observer associates current-network-namespace diagnostic sockets
with visible `/proc` descriptor links by **inode**, keeping namespace, family,
protocol and diagnostic cookie in the existing stable socket identity. It never
uses ports, names or a PID alone to invent an owner. IPv4-mapped IPv6 sockets
retain their IPv6 family and inode/cookie; their address presentation is unmapped.
No endpoint-based ownership workaround was needed.

A native process can call `pthread_exit` in its main thread while workers retain
sockets. Linux then leaves `/proc/TGID/fd` empty and `/proc/TGID/exe` unavailable.
The observer now detects the zombie leader and scans its live task directories,
up to 256 entries per such group, within the existing global 8192-task/131072-FD/
two-second limits. It does **not** scan every host thread. Each worker is identified
by its own TID/start ticks; `thread_group_pid` and row evidence explain its original
TGID. Group generation and worker generation are checked again. Private FD tables
of workers with a still-live leader remain outside this fallback's coverage.

After process inspection, the matching FD link is read again. Closed/replaced FDs
cannot keep an association merely because the earlier scan saw that inode. This
narrows a race; it is not atomic observation or proof against hostile FD transfer.
The five-second process metadata cache now also checks proc UID and network/mount
namespace links, in addition to PID/start and executable path/revision. Detected
inaccessible/changing holders remain a warning even if another holder was readable.
No last-known identity is substituted for a current holder.

These changes are **observation-only**. `Resolve`, enforcement authority, packet
retention, rule matching, TCP accounting and the optional UDP kernel adapter are
unchanged. A recovered display identity may still be unsupported for enforcement.

## Additive API evidence (v1 remains compatible)

- `activity.ownership_counts`: counts of `ownership_category` over current rows.
- Row `ownership_category`: `visible-holder`, `shared`, `no-userspace-inode`,
  `holder-changed`, `holder-inaccessible`, `holder-metadata-unavailable`,
  `holders-truncated`, or `unknown`. These describe evidence, not guessed causes.
- Row `display_application`, optional: supplied only when every validated visible
  holder has the **same native application key, revision and UID**. The full owner
  set remains present. Mixed applications, unresolved/Wine identities, truncated
  lists and known incomplete holder inspection get no common display association.
  This field is never a permission target or input to `Resolve`.
- Process `thread_group_pid`, optional: the group of a recovered live worker.
  `pid` is that worker's Linux TID, and its stable ID uses that TID/start time.

Frontends may opt into the common display association. Existing Qt presentation
still keeps multi-holder sockets under the one Unidentified group; no frontend
files changed here. Each socket is still one row and accounting key. Association
changes preserve measurements/baselines and suppress one transition rate interval,
under the existing traffic contract.

## What Unknown means

`no-userspace-inode` means diagnostics supplied inode zero (e.g. TCP TIME_WAIT).
These expected ownerless kernel rows do not, alone, make a snapshot incomplete.
A zero inode is not guessed back to an old owner. `holder-changed` requires an
observed holder and failed generation/FD recheck. `holder-inaccessible` requires
seeing its FD and being denied executable access. Otherwise an unresolved socket
stays `unknown`, including a non-dumpable process whose FD links were never visible.

Global inaccessible directory counts do **not** prove a particular socket's owner
is inaccessible. Socket UID is the creation credential, not current ownership;
other-UID unknown rows mention that difference but are not relabelled with an
unproven cause. Namespace mismatch cannot generally be established from a missing
FD link. Sockets outside the observer namespace, hidden proc mounts and private
per-thread tables remain coverage limitations rather than invented per-row causes.

### Bounded host sample (read-only, no private process metadata retained)

| Evidence | Before | After |
|---|---:|---:|
| Visible descriptor holder | 59 | 45 |
| No userspace inode | 15 | 24 |
| Unknown, nonzero inode | 29 | 29 |
| Of unknown: socket UID differs from observer | 29 | 29 |
| Of unknown: socket UID matches observer | 0 | 0 |
| Inaccessible process FD directories | 335 | 333 |
| Collection duration | 16 ms | 15 ms |

No shared, observed-exit, specific denied-owner or proved namespace-mismatch rows
were present in these host samples. This is not proof such cases never occur.
All 29 unknown rows had other creation UIDs; 13 listening TCP, 3 established TCP,
12 bound UDP and 1 connected UDP. Their exact current owners remain undetermined.
The changing totals reflect changing host traffic, **not** an accuracy benchmark.
Raw arguments/environments and unrelated executable paths were not recorded.
Evidence: `.workspace/attribution-sample/before.json` and `after.json`.

The existing privileged UDP path was assessed: its API only exposes selected-UID
cookie counts and Stop, not process metadata. Resolving these other-UID host rows
by returning privileged process details would expand the selected-user policy;
this increment does not do that. A future selected-UID ownership extension could
help non-dumpable same-UID processes, but needs dedicated authorization/filtering
validation. No new privileged daemon, host collector attachment or namespace
traversal is introduced. Basic monitoring needs no new privilege.

## Reproduce the focused checks

```sh
scripts/check-ownership.sh
scripts/run-desktop.sh
```

The first command builds small native fixtures and the backend, runs focused Go
race tests/vet and queries the real authenticated observation API. No sudo,
firewall or packet hooks. It exercises leader-exit recovery for TCP/UDP IPv4/IPv6,
same-image and distinct-executable shared holders, restricted/restored visibility
with unchanged TCP byte totals/baseline, exit removal, and confirms enforcement
`Resolve` still withholds shared application permission. Go tests additionally
exercise exact numeric FD replacement (`dup3`), mapped IPv6 accepted sockets,
cache credential/namespace invalidation, and display grouping conflict cases.
PID numeric reuse and arbitrary process-inspection timing are not claimed as
controlled live tests; existing start-time checks/cache tests are reused.

Acceptance: `.workspace/attribution-sample/final-acceptance.log`, with detailed bounded
observer sanity output under `.workspace/own-98qxzqdt/summary.json`: 3.001 seconds,
0.080 CPU seconds (2.67% one core), 20232 KiB RSS, final census 11 ms, at the test's
500 ms collection delay. This is a short CPU/RSS sanity sample, not a benchmark.
No enforcement attribution changed, so the settled firewall/UDP/Wayland suites
were reused rather than repeated. No live host collection privilege or enforcement
was activated, and no host network/security/service settings changed.

## Observation-only TCP initiation evidence

`activity-initiation-v1` adds bounded handshake evidence to Activity without
changing ownership resolution, application keys, socket IDs, traffic baselines or
enforcement. SYN-sent supplies outgoing; passive request diagnostics supply incoming.
The inode-zero test is combined with full-socket diagnostic framing so orphaned
full sockets are not assumed passive. Same-cookie request-to-accepted transition
is supported; full SYN-received/simultaneous-open contexts stay ambiguous. All other
unobserved initiation remains explicit unknown. Exact schema, lifetimes, sample
limitations and disposable fixture are in [API.md](API.md#activity-initiation-evidence).

Primary kernel sources consulted for this concrete distinction:
[tcp_diag.c request versus full diagnostics](https://github.com/torvalds/linux/blob/master/net/ipv4/tcp_diag.c),
[inet_diag.c full-socket attributes](https://github.com/torvalds/linux/blob/master/net/ipv4/inet_diag.c),
[inet_connection_sock.c accepted-child cookie transfer](https://github.com/torvalds/linux/blob/master/net/ipv4/inet_connection_sock.c).
These distinguish kernel observation from a guessed port/process relationship;
they do not make an Activity association a firewall permission target.

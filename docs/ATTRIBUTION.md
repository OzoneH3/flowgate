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
scripts/checks/check-ownership.sh
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

## Closed TCP lifecycle rows in Activity

Electron groups exact ownerless TCP `TIME_WAIT` records separately from unresolved
live sockets. See [lifecycle groups and ownership evidence](TRAFFIC.md#lifecycle-groups-and-ownership-evidence)
for the strict classification, count and filtering rules. This presentation change
uses existing observation fields and infers no previous application. Ownership,
authorization, firewall rules and accounting attribution are unchanged.

Parser and model regressions are in `electron/test/activity-lifecycle.test.cjs`.
Native checks use isolated synthetic API responses; they do not establish live
attribution coverage across workloads.

## Attribution reason categories

New event and decision-log attribution objects can include an optional
`reason_code`, alongside the existing `status` and human-readable `reason`.
The backend assigns it at the producing branch and updates it when runtime
verification replaces an earlier result. It describes the observed condition;
it grants no permission and changes no application identity or socket fingerprint.

| Codes | Meaning and limits |
| --- | --- |
| `no_socket_observed` | No matching socket was observed. This does not establish that no receiver exists, that a process exited, or that a sender closed early. |
| `namespace_mismatch` | The flow is outside the observer's network namespace. |
| `socket_census_unavailable`, `socket_changed` | Census/recheck unavailable, or socket evidence changed during attribution. |
| `multiple_candidates`, `process_visibility_incomplete` | Ownership is ambiguous, or another holder cannot be excluded. This does not establish a complete set of multicast receivers. |
| `native_owner_observed`, `runtime_owner_observed` | A native owner was observed or runtime ownership corroborated, within the existing snapshot limits. |
| `broker_client_association` | The existing broker/client association and its stated assumptions apply. |
| `runtime_identity_unverified`, `runtime_evidence_incomplete` | Runtime identity or supporting evidence is incomplete. |
| `runtime_session_changed`, `runtime_ownership_changed` | Session or ownership evidence changed. |
| `runtime_broker_unavailable`, `runtime_census_unavailable`, `runtime_capability_unavailable`, `runtime_observer_unavailable` | A required runtime component, census or capability is unavailable. The original reason retains the specific evidence; the category does not diagnose an unobserved cause. |
| `runtime_owner_ambiguous`, `runtime_holder_conflict` | Runtime ownership is ambiguous, or Linux holders disagree with runtime evidence. |
| `localhost_exempt` | The existing localhost exemption applied; this is not application identification. |

Electron displays a category in request Details, recorded-request Info and decision
log details when a valid code is present. Its tooltip (or recorded Info text)
retains the exact code. Original status and reason remain available. Older records
have no category; they are not rewritten or classified from their prose. Unknown
future codes are retained and displayed as unrecognized. Codes are bounded to 64
ASCII characters matching `[a-z][a-z0-9_-]{0,63}`; malformed optional values do not
discard the surrounding event or its evidence.

Pending revalidation uses `no_socket_observed` for its existing diagnostic when
the original socket is missing. The previous exact-text fallback applies only when the code
is absent; an unknown nonempty code cannot trigger that fallback. This does not
turn a retained request's original attribution into current socket evidence.
Activity ownership categories, unknown initiation direction, accounting gaps,
queue capacity and verdict outcomes remain separate. No new aggregate success
rate or workload coverage claim is introduced by these categories.

Some runtime refusals retain an earlier attribution status while withholding the
application identity. Neither that status nor the category substitutes for the
verified application and scope required for permission.

Validation covers resolver-generated native IPv4/IPv6 observations, legacy
revalidation, persisted records and principal projection, and the existing
synthetic two-application/two-prefix Wine isolation matrix. An isolated native
Electron journey displayed the daemon's `native_owner_observed` category in
request and log details. Known/future/absent/malformed UI cases were additionally
injected through a read-path proxy, preserving the original evidence and controls.
That journey did not produce a real `no_socket_observed` event or verify the main
Info/observer-only UI paths; it does not establish improved attribution coverage
or receiver delivery.

## Runtime names and permission authority

An executable name, parent chain, bundle argument or readable `package.json`
can describe a hosted application without proving that the runtime executes it.
Electron bundle metadata is therefore retained as **unverified display context**.
The observed native executable remains the socket identity; the bundle does not
replace its application key or revision. The prompt names the runtime and shows
an application-unverified notice. Details labels the path as an observed bundle
argument.

This withdraws the earlier inferred Electron bundle-wide permission support.
Application-wide Remember is unavailable for an unverified hosted runtime, and
old application-specific bundle/runtime rules must not authorize its connections.
Stored rules remain inspectable; they are not silently migrated into broader
native-runtime permissions. Existing Once behavior is unchanged. Process rules
remain refused for unverified runtimes. For-a-while now enforces that same refusal
when creating or matching a lease, including ended-request and local-pair paths;
the native test exposed that its earlier unavailable description was not enforced. Explicitly
configured All programs rules keep their own UID, direction and filter semantics;
the detection change creates no such rule.

Native executables under directories containing `wine` must remain native unless
runtime evidence establishes otherwise. Known Wine loader names may conservatively
signal an unresolved runtime, alongside the existing runtime-mapping checks; an
arbitrary parent-directory substring is not runtime evidence. Windows executable,
user and prefix separation still require their existing corroboration.

The detection audit reproduced unrelated native binaries named `electron`
acquiring the same bundle identity and matching the same application rule in the
in-memory evaluator, plus a native program falsely classified by a Wine-like
parent directory. These are separate from the worker-descriptor coverage gaps.
The audit used disposable processes/sockets and did not change installed rules
or establish host exploitation. Source-fix validation and remaining worker limits
are recorded with the implementation evidence.


Validation used two native fixture executables with the same synthetic bundle
argument in a private network namespace. The old daemon saved and applied an
Electron bundle rule through the normal API. Against the corrected daemon and
the same database, both executables prompted under distinct native identities;
the old rule remained listed, and Once delivered only the selected request.
Remember and For-a-while were disabled in the native GUI, and direct API attempts
to bypass those controls were refused without changing rules or leases. This is
isolated TCP receiver evidence, not an installed-host or native Wine acceptance
claim. The Wine two-application/two-prefix negative checks are model regressions.

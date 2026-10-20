# Optional event-based TCP initiation (`activity-initiation-events-v1`)

## Current verification: passed on the real kernel

Explicit shared mode completed actual direction acceptance on clean03dd0e4 and
focused helper-death acceptance on clean8548a2a. Evidence:
`.workspace/tcp-initiation-1792356931-1419542/` and
`.workspace/tcp-initiation-1792357244-1427753/`. Both use collector SHA256
86b6e8844ac8f73c357673471e726e4fdeff5b5edbc59e4331e2ab5e1c5312b3.
Real ordinary TCP4/6 active/passive/both loopback ends, exact-cookie joins,
closure/new sockets, restart old-unknown/new-known, actual owned-helper death with
old evidence cleared/new TCP observation available, foreign program preservation
and cleanup passed. No unrelated matrix repeated. One saved16-connection timing
sample is0.528ms baseline/0.620ms event, not a general performance benchmark.
There is no remaining privileged verification blocker for this configuration.

Not deployed: host daemon/UDP/enforcement unchanged. Shared mode remains an
explicit root choice; default exclusive refusal and unsupported/missing-callback
unknown semantics remain. Earlier failed/pending checkpoints below are retained
as history, superseded by these two actual successful case sets.


Implemented, not deployed. Fast completed handshakes routinely fall between the
existing inet_diag snapshots. The native fixture reproduces TCP4/TCP6 loopback
Dial/Accept/data exchange before the next observation: both established ends are
Unknown with snapshot sampling. Deliberately holding SYN is not this acceptance.
Closed sockets disappearing before any Activity snapshot are still not a historical
connection log; this increment does not add one.

## Mechanism and authority

The optional native CO-RE helper uses cgroup-v2 sockops active-established and
passive-established callbacks. Kernel `bpf_get_socket_cookie` generates/returns the
same cookie used by inet_diag; `bpf_get_netns_cookie` restricts collection to the
helper's current network namespace. A callback binds role to cookie, not a tuple,
port, PID, application name, ownership guess or byte direction. This is display
evidence, never policy/identity permission. Simultaneous/conflicting roles become
ambiguous. UDP remains connectionless with its existing explicit limitations.

Kernel mechanism references: [sockops cookie helpers](https://kernel.googlesource.com/pub/scm/linux/kernel/git/torvalds/linux.git/+/0275dc184aa007b260374af6d46fb15741c062a8/net/core/filter.c)
and [TCP callback/default handling](https://github.com/torvalds/linux/blob/master/include/net/tcp.h).
The program requests state notifications and deletes its own record on TCP_CLOSE.
It never writes reply/tuning fields, sends/drops/redirects packets or changes routing,
firewall, socket buffer sizes or timeouts. Startup defaults to refusing pre-existing effective
sockops programs at the configured cgroup rather than altering/detaching them.
The explicit shared observation mode below has separate, stricter no-field-write
semantics and remains opt-in.
External later changes to cgroup attachment/hierarchy are not a supported coverage
guarantee. Optional UDP tracing is a different mechanism and is not stopped.

Explicit root startup options on the existing `serve` daemon:

```sh
--tcp-initiation-helper /absolute/reviewed/tcp-initiation-collector \
--tcp-initiation-cgroup /sys/fs/cgroup
```

Absent helper option means disabled; no implicit attach in normal GUI/monitor
startup. The root configuration chooses coverage, not an IPC path. The bounded ELF
protocol helper is copied to a private0700 file in the validated API directory and
only that copy executes. ELF/protocol markers establish compatibility, not a code
signature or replacement for administrator review. No second privileged Go daemon,
API, policy engine, database writer or GUI privilege is introduced. No GUI lifecycle
authority is added: future deployment/enablement is a deliberate root startup step.

Attach/load/permission/helper failure keeps the Go daemon, TCP snapshots, rules,
Decision Log and optional UDP monitoring useful. No automatic retry/restart. Helper
EOF/process death closes its own BPF link/maps; no pinned BPF objects, foreign
collector detach or persistent attachment. Kernel state-notification flags on already
observed sockets may remain set until those sockets close; they do not retain a
program or permission after link destruction.

## Bounds, loss and freshness

One hash map,8192 socket records, plus a counter. No per-packet records. Full-map
insert failure or inability to subscribe to lifecycle notification increments
lost_events: this counts collection failures, not an exact number of unique missing
connections. There is no reconstruction of pre-attachment or missed evidence.
Conflict remains ambiguous; map exhaustion leaves missing sockets unknown. Cookie
lifetime, namespace and collector generation prevent endpoint/PID reuse inheritance.

The existing observer supplies at most2048 TCP cookies per query; there is no new
socket census/poll loop. Responses and diagnostics are bounded512KiB/4096bytes.
Startup watchdog5seconds; exchange watchdog1second; caller bound1.5seconds. Packet
handling never waits for this observer exchange. API consumes its cached snapshot.
No stale event rows are reused after helper failure/query timeout. New helper run
has a fresh generation/empty map: existing established sockets remain unknown,
while subsequent new connections may gain evidence. Available event evidence is
always partial history/cgroup coverage, even with zero observed loss.

Activity.tcp_initiation: state disabled/starting/active/failed/unavailable,
generation (opaque), netns, reason, partial, lost_events, collected. Capability
means protocol support, not root permission or successful load. Ordinary peers get
only their authorized Activity rows and no machine-global loss count. There is no
separate map/cookie inventory in serialized status.

Existing row.initiation retains state known/listening/unconnected/unknown/ambiguous,
optional direction incoming/outgoing, source, reason, observed_at. Event-backed
known/ambiguous entries add generation; sources are
cgroup-sockops-active-established / cgroup-sockops-passive-established. observed_at
comes from the kernel monotonic callback timestamp converted against current
monotonic/wall clocks, not the next sampling time. Complete absence of event evidence
falls back to the existing bounded handshake sampler; it does not invent direction.
Network zone and upload/download remain independent.

## Verification and exact privilege boundary

`scripts/build-tcp-initiation.sh` builds the optional helper to a separate path.
Focused race/vet passes identity/monitor/tcpinit/daemon/command and affected policy/
logging packages. Labelled synthetic executable-protocol tests cover startup,
bounded timeout/malformed output/shutdown, generation changes, exact requested
cookies, future/duplicate/unrequested records and partial loss. Projection tests
reject foreign namespace, reused cookie, old generation, closed/listening/UDP rows
and stale/failed source evidence. These are implementation checks, not kernel proof.

Real unprivileged disposable evidence `.workspace/tcp-initiation-userns-2/` and its
log reproduces fast native TCP4/6 Unknown and records actual BPF loading EPERM;
TCP Activity remains available after source failure. The single initial-namespace
noninteractive attempt returned `sudo: a password is required`, preserved in
`.workspace/tcp-initiation-kernel-1.log`. No initial-namespace successful attachment,
real event-backed arrows or active-collector overhead is claimed at this checkpoint.

Prepared user-authenticated command (fresh disposable namespace, no host daemon or
network changes):

```sh
cd /home/flowgate-user/Apps/flowgate
scripts/checks/check-tcp-initiation.sh
```

The script records exact source/diff/artifact hashes. Its intended real checks are
ordinary completed TCP4/6 and both loopback ends, closure/new-cookie isolation,
collector restart (old unknown/new known), helper crash with TCP still available,
and a short baseline/event native connection setup timing sample. Those acceptance
claims remain pending until that command actually passes; no scheduler-noise rate
comparison or broad performance claim is appropriate. Host deployment is separate.

### Initial-root fixture path correction

User-authenticated run `.workspace/tcp-initiation-1792356098-1402400` recorded clean
sourcef7b04c49 and matching release hashes, then failed **before BPF**: production
SecureDirectory correctly rejected root runtime/database paths below a user-owned
workspace ancestor. This is not a verifier rejection or successful collector check.
The fixture now reuses the existing real-UDP harness's private bind mounts over
`/run/flowgate-api` and `/var/lib/flowgate`, backed entirely by that run's workspace
api/data directories. It requires distinct mount AND network namespaces; production
path/owner validation is unchanged, no repository chown or host path mutation.
Pass progress and final success marker are saved as verification.log/result.json;
startup exits surface the actual daemon error immediately. Python/shell syntax
checks passed; the corrected privileged branch still needs the exact command above.

### Effective-program query diagnosis

Corrected fixture run `.workspace/tcp-initiation-1792356262-1404752` passed the real
fast TCP4/6 sampling-miss baseline and cleaned up, then the helper refused before
load/attach at its effective-sockops query. Its old combined message ended in
`Success`, which does **not** by itself prove a verifier failure or identify foreign
programs: that branch conflated a failed query with a nonzero returned count.
Diagnostics now distinguish `sockops_query_failed` (return/errno/count) from
`sockops_conflict` (count/flags/program IDs). The refusal behavior is unchanged;
no program is detached/overridden. Native build passed; no successful kernel source
or overhead evidence is claimed. Before another full acceptance attempt, obtain the
read-only `sudo bpftool -j cgroup show /sys/fs/cgroup effective` result and inspect
which case is actually present. Kernel query contract reference:
https://github.com/torvalds/linux/blob/master/kernel/bpf/cgroup.c (`__cgroup_bpf_query`).

## Explicit shared-hook observation (bpftune coexistence)

The user's read-only query confirmed actual root-cgroup sockops program109,
`bpftune_conn_tuner`; sysctl program99 uses a separate hook. No program/service was
stopped, detached or reconfigured. Thus the default exclusive-source refusal is
expected on this machine, not a verifier failure. Repeated unchanged runs cannot
establish active-source evidence.

A separate explicit root startup option, `--tcp-initiation-observe-shared`, selects
a bounded shared observation mode; default behavior still refuses pre-existing
sockops. The helper's matching reviewed argument is `--observe-shared`. This does
not name-match/trust a program as permission authority or create GUI lifecycle
control. It uses the ordinary independent kernel BPF link; no replacement, override,
legacy detach fallback, foreign FD ownership or persistent pins.

Shared-mode BPF **does not write callback flags, replies, tuning or packet fields**.
It records established evidence only when the existing callback flags already
include STATE notifications, needed to delete its own map entry on close. Otherwise
it increments loss and leaves that connection unknown. No flags are enabled just to
make the test pass. Return1 preserves the observational program's neutral result.
The netns-cookie filter runs before those operations: host sockets outside the
fresh fixture namespace get no collection or flag changes. Different callback order
or missing foreign lifecycle subscriptions can reduce coverage; partial/unknown
remain explicit. Cookie generation/map updates are attribution metadata, not policy.

The pre-attach effective sockops ID set is bounded to63 foreign programs. Immediately
after attach and on every bounded sample, require exactly those IDs plus the own
program ID. Any missing/additional program or query failure closes only the own link
and fails the source; cached evidence is withheld. Another administrator's external
changes cannot be undone/restored by this collector. The test records before/after
all effective cgroup program metadata and requires it to match after own cleanup.

Audit references: kernel [cgroup link/query handling](https://github.com/torvalds/linux/blob/master/kernel/bpf/cgroup.c),
libbpf [independent attach implementation](https://github.com/libbpf/libbpf/blob/master/src/libbpf.c),
and upstream [bpftune socket callbacks](https://github.com/oracle/bpftune/blob/main/src/tcp_conn_tuner.bpf.c).
Upstream bpftune already subscribes to STATE callbacks; installed behavior still
requires real kernel acceptance, not an assumption from a program's displayed name.

Native build and focused tcpinit/identity/monitor/command race+vet passed:
`.workspace/tcp-initiation-shared-{build,race,vet}.log`. The fake-executable transport
test proves the shared option is forwarded only by explicit configuration, not
successful BPF coexistence. Initial active status now correctly reports partial
coverage even before its first cookie query. **Real shared-source evidence remains
pending** until this affected case passes:

```sh
cd /home/flowgate-user/Apps/flowgate
scripts/checks/check-tcp-initiation.sh --observe-shared
```

It retains the existing fast TCP4/6, both loopback ends, same-cookie identity,
closure/new-cookie, restart/old-unknown, helper-failure fallback and bounded overhead
checks. It additionally verifies foreign program inventory after cleanup. It does
not restart the host daemon, enable enforcement or stop bpftune/UDP collection.

## Real shared kernel direction proof; helper-failure followup

Authenticated run `.workspace/tcp-initiation-1792356931-1419542`, clean source
**03dd0e4483e11b620a6d7836e870e94aac14c7cb**, successfully loaded/attached the actual
shared BPF source. Saved event-known.json proves all32 completed native TCP4/6
socket ends:16 outgoing active and16 incoming accepted, including both loopback
ends, joined by exact cookies. Partial=true, reported loss0 (not complete-history
proof). Verification.log records closure/new-cookie isolation and collector restart:
old established sockets unknown, new sockets known. All original effective programs
including bpftune109 and sysctl99 match exactly in before/after JSON, and cleanup
completed. This supersedes the earlier blanket 'no real arrows' limitation for the
explicit shared configuration; default exclusive refusal on bpftune remains correct.

The run then exposed a **fixture lookup defect** before killing the owned helper:
`task/<main-tid>/children` lists only children forked from that one Go OS thread.
No helper was found there, so the fault-injection assertion stopped. The fixture
now unions all daemon thread children, requires actual direct PPID, pinned-runtime
path/prefix and exact reviewed helper SHA256 before signaling. This reuses the
settled UDP fixture strategy. A deterministic unprivileged Go-thread fork test
passed (`.workspace/tcp-initiation-thread-lookup-test.json`), with exec TID distinct
from daemon leader and exactly the expected child verified. No collector/daemon
implementation changes were needed for this correction.

The bounded timings already existed in the saved native JSON before that failure;
recovered without rerunning to `overhead-recovered.json`: baseline527750ns vs event
620470ns for16 connections (8/family). One short loopback sample includes socket
setup, scheduling and existing bpftune; not a general overhead percentage/benchmark.
Passed direction/restart/cleanup cases need not repeat. Run only the remaining
actual helper-death fallback case:

```sh
scripts/checks/check-tcp-initiation.sh --observe-shared --failure-only
```

It checks an active source, kills only its hash/PPID/path-verified own helper, then
requires old evidence unknown, same daemon still stopped-enforcement and fresh
TCP4/6 observations available. Its result is labelled `passed-kernel-helper-failure`
separately from the preserved full direction evidence. Foreign program preservation
and own cleanup are still required. This last fault case remains pending until run.

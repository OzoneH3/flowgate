# Optional event-based TCP initiation (`activity-initiation-events-v1`)

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
firewall, socket buffer sizes or timeouts. Startup refuses pre-existing effective
sockops programs at the configured cgroup rather than altering/detaching them.
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
scripts/check-tcp-initiation.sh
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

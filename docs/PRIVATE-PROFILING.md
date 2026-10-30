# Private one-shot serve profiling

This is diagnostic support, not a UDP throughput optimization. It is off by
default and opens no network listener. The current manual capture uses the local
administrator API described in [UDP census diagnostics](UDP-CENSUS-DIAGNOSTICS.md).
Earlier diagnostic releases supported automatic startup capture; that fallback
has been removed after a launcher omitted the manual flag during deployment.

A root administrator must set both `FLOWGATE_PROFILE_DIR` (an existing
service-owned mode-0700 directory) and `FLOWGATE_PROFILE_MANUAL=1`. The launcher
must forward both. A directory alone or any other manual value disables capture.
The daemon waits for an administrator's generation-checked manual trigger and
captures once for 120 seconds; shutdown cancels it. There is no retry or automatic
second capture. Remove the temporary environment override after the window;
no second restart is needed. Preparing another run requires explicit approval.

All path components are opened without following symlinks. The final directory
is checked and pinned by its descriptor. Four new files are created exclusively
with mode 0600; existing files are never replaced. CPU and mutex profile files
are limited to 8 MiB each, summary to 2 MiB. The small start marker contains no
packet data. Errors disable diagnostics and are logged; protection continues.
Profiles contain code stacks and executable mapping metadata; keep them private.
No payloads are collected. Bounded census evidence includes endpoint addresses,
executable/prefix paths and socket/holder facts; retain it locally and privately.

The capture includes:

- Standard Go CPU samples and process user/system CPU counters at the boundaries.
- Go mutex contention samples (fraction 1/20), restoring the previous setting.
- Fixed-size elapsed histograms for socket and holder census, process facts,
  full process inspection, link queries, main policy-lock wait/hold, policy
  evaluation, verdict submission, admission and worker processing.
- Callback-to-worker elapsed time, worker-group size distribution, callback and
  parsed TCP/UDP counts, admitted/rejected counts, worker visits/completions and
  successful Allow/Drop/error verdict submissions.
- Queue-health and collector state/generation/missed-operation snapshots at the
  boundaries, plus build identity. Collector misses are measurement gaps.

CPU samples measure execution. Elapsed measurements include I/O, scheduling and
blocked time and overlap: worker processing contains identity/policy/verdict
stages; locked policy time contains evaluation; full inspection contains other
checks. Do not sum nested elapsed totals or present them as CPU percentages.
Use the CPU call tree with a consistent denominator instead. The mutex profile
is sampled aggregate contention, not a complete off-CPU timeline.

Histograms describe completed calls inside the window. Spans crossing the end
are discarded, while callback-to-worker entries beginning before the window are
excluded. Worker visits include a second visit after transfer to the census
lane, and callback-to-worker time includes admission/coalescing; neither is a
unique packet count or a receiver latency. Callbacks are not all network traffic:
conntrack bypass traffic does not enter NFQUEUE, and kernel/netlink losses can
occur before a callback. Drop verdicts include intentional Deny and refusals;
use queue-health reasons separately. API success and verdict submission do not
prove receiver delivery. Queue snapshots are adjacent to, not atomic with, the
CPU measurement boundary. Profiling introduces overhead; report it as an
instrumented normal-use observation, not an uninstrumented throughput benchmark.

No host profiling is enabled by preparing this build. The approval request must
identify the exact release, private output directory and temporary service
environment override, preserve protection/rules/collector/autostart via the
existing guarded updater, and use guarded rollback on health failure. A normal
use window generates no extra traffic. Select an optimization only after reading
that actual `serve` profile; evaluate it with profiling disabled against the
baseline under equal workloads and reversed order.

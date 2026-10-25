# Private one-shot serve profiling

This is diagnostic support, not a UDP throughput optimization. It is off by
default and does not open a listener, add an API operation, or install a signal
handler. Diagnostic release `25dbb1a90e81f6fc2a150231cae699db87e430f3` was explicitly
approved and deployed; its one capture finished and the temporary override was
removed. `bbee9b56d4ba10634142bfdff65edb6f60a6973e` remains the comparison
baseline. Performance releases require separate deployment approval.

A root administrator may set `FLOWGATE_PROFILE_DIR` in the service environment
to an existing root-owned directory with mode 0700. The diagnostic build waits
20 seconds after `serve` readiness, then targets one 60-second window (timer scheduling can add a small overrun;
actual elapsed time is recorded).
Shutdown cancels the capture. There is no retry or automatic second capture.
Remove the temporary environment override after the window; no second restart
is needed. Prepare a new output directory for a future explicitly approved run.

All path components are opened without following symlinks. The final directory
is checked and pinned by its descriptor. Four new files are created exclusively
with mode 0600; existing files are never replaced. CPU and mutex profile files
are limited to 8 MiB each, summary to 64 KiB. The small start marker contains no
packet data. Errors disable diagnostics and are logged; protection continues.
Profiles contain code stacks and executable mapping metadata; keep them private.
No payloads, endpoint samples, process listings or profiling labels are collected.

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

# FlowGate status

This is the maintained status page. Historical deployment and acceptance notes
are in [STATUS-HISTORY.md](STATUS-HISTORY.md) and
[HANDOFF-HISTORY.md](HANDOFF-HISTORY.md). They do not describe the live host.

## Implemented

- Linux application blocking for supported incoming/outgoing TCP and UDP.
- Verified executable/user identities and supported Wine runtime/prefix identities;
  unknown or ambiguous ownership stays explicit and cannot inherit a launcher rule.
- Durable rules, bounded decision log, continuous service/guard, explicit Stop and
  root-local recovery, matched Electron releases and optional GUI login startup.
- Sampled TCP/UDP usage, queue pressure diagnostics, bounded UDP observation batches
  and reuse of native holder inspection within one verified census.
- Bounded reconciliation of native threads joining or leaving a proven shared
  descriptor table, with fresh member identities, runtime checks and final topology
  verification. Ambiguous, unreadable or repeatedly changing evidence still refuses.
- Administrator-reviewed exact outgoing TCP network-endpoint rules, including
  traffic with no userspace owner. These explicitly cover every matching program.

Experimental bandwidth shaping and traffic priorities are included in matched
releases with the documented partial coverage. Quotas and recurring schedules
are not implemented. Usage counters are partial observations, not
wire totals or proof of delivery. Opt-in durable usage history checkpoints these
partial observations into a separate private bounded store, with authenticated
user projection and explicit restart/retention gaps; see
[USAGE-HISTORY.md](USAGE-HISTORY.md). Storage/API/GUI validation has separate
scope and does not turn partial observations into billing or delivery evidence.

## Current UDP attribution candidate (2026-10-30)

The current inspected host release is `966d7886c41ee7805bdce905494d501d2ef4be7e`,
with protection initially stopped. A later read-only check found a concurrent
activation; this task did not activate or override it, deploy, or restart it.
The default update pin remains `508354633cf234139525a79b2507a999f60acc9d`.
The source corrects repeated Wine UDP discovery using bounded dispatch hints and
necessary-condition prefilters while retaining fresh full ownership/runtime checks
and current per-packet policy. In the documented isolated 125-packet/s comparison,
allowed delivery improved from 6,112/7,500 to 7,500/7,500 and attribution-capacity
counter deltas from 5,146 to 20: zero in the allowed-delivery window, 20 in the
Deny/Ask-only window. Deny/prefix isolation and live policy edits passed.
Inspection latency and deliberate-overload loss remain; the stopped-protection CPU
observation is separate. See [the measured scope and limitations](UDP-ATTRIBUTION-CAPACITY.md).
Shaping and Electron behavior are unchanged; their prior evidence is reused.

## Historical profiling and releases (through 2026-10-25)

The following records describe earlier experiments and deployments, not the
current installed version, update pin or protection state.

The deployed diagnostic backend/GUI release is
`25dbb1a90e81f6fc2a150231cae699db87e430f3` (2026-10-25), based on performance
baseline `bbee9b56d4ba10634142bfdff65edb6f60a6973e`. The approved guarded
update preserved Both protection and all 78 current rule documents exactly,
collector/Wine configuration and GUI autostart. A single 60.000479-second
normal-use profile completed; its temporary override was removed without a
second restart. The service stayed healthy, with zero unexpected restarts.

That quiet instrumented window contained 134 NFQUEUE callbacks (73 UDP, 61 TCP),
zero admission/fairness/overflow counter increases, and 46 collector measurement
misses. Process CPU was 15.964921 seconds (26.61% of one core). It did not reproduce
overload and has no wire/receiver denominator. No connectivity problems were
reported. The actual CPU profile identified holder census/validation, particularly
fresh task-stat reads, as the target; nested call-tree totals are not additive.
Evidence: `.workspace/serve-profile/deploy/analysis.txt` and private profiles.

That deployment includes the GUI shutdown fix, census thread-churn reconciliation,
practical native UDP inspection refresh (fresh per-batch facts, full classification
initially/on refresh, 10-second refresh scheduling and 30-second hard reuse age),
and UDP scheduling/evaluation changes. A fresh per-packet link query runs outside
the policy lock; recent-endpoint overtaking is bounded to two turns. Idle packet
slots can be borrowed and reclaimed; global/byte bounds remain unchanged.

The diagnostic support is off unless explicitly enabled; the approved capture
has finished. It adds no throughput fast path, public endpoint or policy/cache
relaxation; see [PRIVATE-PROFILING.md](PRIVATE-PROFILING.md). Four
subsequent scratch batching/transport-pool experiments were rejected for failing
to demonstrate a reliable delivery/CPU improvement (`.workspace/udp-throughput/`).
The narrower holder-census task-stat experiment `66313d5` was rejected: its
69.29→67.63 CPU-second saving accompanied high-rate allowed delivery falling
663→597 and worse survivor latency. Its production reader is reverted; evidence
remains in `.workspace/holder-stat/`. It is not an approved UDP fix.
The default updater now pins exact diagnostic `25dbb1a` using
`deployment/default-release`. The coordinator checks an exact-source approval
policy before any host contact; rejected and unapproved builds cannot silently
install, including newer HEADs. Preparing a release does not approve it.
Essential-discovery census sharing was also tested with profiling disabled and
reversed order. It reduced quiet guest CPU 5.06→4.60 seconds over two 15-second
windows, but failed throughput acceptance: the main matrix used 85.81→82.88 CPU
seconds while high-rate delivery fell 2909→2652 and survivor latency worsened.
The longer confirmation did not remove the latency concern. Correctness tests
passed; that is not sufficient for a performance release. The experiment is held
off master on `research/essential-census-01a15db4` (`f872051`), with exact hashes,
receiver/counter data, failed attempts and scope in `.workspace/holder-work/`.
No new performance bundle, host capture, service restart or deployment was made.
The live pressure-time bottleneck remains unverified: the existing host capture
had zero admission rejections. No multi-queue redesign follows from these TCG
results.
These results do not establish actual-host gains or justify a multi-queue redesign.

In two reversed-order capped-VM comparisons, sustained allowed delivery was
4592/4800 versus 3619/4800 baseline, with low-rate allowed delivery 480/480
and denied delivery zero. High-rate/burst loss remains, including some low-rate
traffic under stress. These are receiver results in a 1-vCPU TCG guest, not a
live QUIC acceptance claim. Queue/identity lifetimes and global packet/byte
limits are unchanged. These are the earlier bbee9b56 validation results;
scoped validation and failed attempts are in `.workspace/udp-admission/`.

For current status use the GUI build/protection indicators or
`/usr/local/bin/flowgate-control status`. Service “active” alone does not prove
protection. `flowgate version` describes the specific binary invoked.

## Operational boundaries and remaining work

High-rate UDP can exhaust bounded admission capacity. The measured CPU reduction
in [TRAFFIC.md](TRAFFIC.md) does not establish live QUIC overload resolution.
Private namespace race/receiver tests establish their labelled scope, not universal
host completeness; inaccessible/changing holders remain a refusal.

The census reconciliation passed the full identity race suite, deterministic
native thread join/leave tests for TCP/UDP over IPv4/IPv6, private-table and
topology-visible descriptor-transfer refusals, and 32 two-executable receiver
cases in a capped VM. Descriptor transfer without a visible topology change
remains a documented snapshot boundary. These results do not prove that the
original host-only failure or live QUIC overload has been eliminated.

Updates preserve the current protection mode by default; fresh installations stay
monitoring. Explicit outgoing activation through the updater requires acknowledgement
of default-deny/essential-networking risk. Continuous protection has no automatic
recovery countdown. Review [ESSENTIAL-NETWORKING.md](ESSENTIAL-NETWORKING.md),
[CONTINUOUS.md](CONTINUOUS.md) and [DAILY-DEPLOYMENT.md](DAILY-DEPLOYMENT.md).

Validation uses a bounded TCG guest for native/kernel execution. Build/model checks
and native UI checks have separate evidence. No deploy, broad permission or live
host mount is implied by a test result.

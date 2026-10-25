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

Bandwidth shaping, priorities for network scheduling, quotas and recurring
schedules are not implemented. Usage counters are partial observations, not
wire totals or proof of delivery. Opt-in durable usage history checkpoints these
partial observations into a separate private bounded store, with authenticated
user projection and explicit restart/retention gaps; see
[USAGE-HISTORY.md](USAGE-HISTORY.md). Storage/API/GUI validation has separate
scope and does not turn partial observations into billing or delivery evidence.

## Current source versus deployed software

The recorded deployed backend/GUI baseline is
`bbee9b56d4ba10634142bfdff65edb6f60a6973e` (2026-10-25). Both-direction
protection, all 75 rules, collector settings and GUI autostart were preserved;
service health verification reported zero restarts. A subsequent 300-second
normal-use sample recorded 140 admission rejections, with endpoint-only
last-observed limit masks, zero fairness displacements and zero overflow
notifications. Daemon CPU averaged 29.09% of one core. The 9,497 collector misses
were accounting gaps, not drops. No connectivity problems were reported, but
this uncontrolled sample has no receiver denominator and does not establish a
loss rate or a live QUIC fix. Evidence: `.workspace/deploy-admission-live/`.

That deployment includes the GUI shutdown fix, census thread-churn reconciliation,
practical native UDP inspection refresh (fresh per-batch facts, full classification
initially/on refresh, 10-second refresh scheduling and 30-second hard reuse age),
and UDP scheduling/evaluation changes. A fresh per-packet link query runs outside
the policy lock; recent-endpoint overtaking is bounded to two turns. Idle packet
slots can be borrowed and reclaimed; global/byte bounds remain unchanged.

New private one-shot profiling support is source/prepared-only until explicitly
approved for deployment. It adds no throughput fast path, public endpoint or
policy/cache relaxation; see [PRIVATE-PROFILING.md](PRIVATE-PROFILING.md). Four
subsequent scratch batching/transport-pool experiments were rejected for failing
to demonstrate a reliable delivery/CPU improvement (`.workspace/udp-throughput/`).
The actual deployed `serve` cost split must be measured before selecting another
optimization; TCG timings alone do not justify a multi-queue redesign.

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

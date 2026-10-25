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

Source HEAD, installed service and GUI may differ. The last recorded deployment
was `0d0249eb` on 2026-10-25: Both active, 72 rule documents preserved exactly,
matched GUI loaded, login entry refreshed, and opt-in usage history disabled.
The installed executable matched its release manifest and the service reported
zero restarts. This is a recorded acceptance snapshot, not a logout/login test.
The subsequent census thread-churn reconciliation is integrated in source but
was not included in that deployment.

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

# Queue health diagnostics

`queue-health-v1` adds the advisory `queue_health` API snapshot. The GUI shows
**Queue pressure / errors** while an active queue has recorded a rejection or I/O
failure in the last 30 seconds. The warning clears after that window; cumulative
counters remain until the bounded session history is discarded. The warning does
not change protection, permission decisions, queue bounds, deadlines or verdicts.
A healthy diagnostic snapshot is not a delivery guarantee.

Every queue run has a separate random generation and start/stop times, including
reactivations within one daemon generation. Up to eight recent queue sessions are
retained. Counters are cumulative unsigned decimal strings, saturating at
18446744073709551615 with an explicit saturation flag. Counters are sampled
individually; concurrent operations may advance them while the snapshot is read.

The counters distinguish attribution capacity, census capacity, fairness
 displacement, attribution deadlines, shutdown, retention capacity, retained
packet deadlines/shutdown, unsupported or malformed packets, missing payloads,
receive failures, verdict-send failures and self-connection compatibility failures.
Retention limits include duplicate SYN collapse and per-flow bounds: a rejection
does not by itself prove CPU overload. Policy Blocks are not diagnostic rejections.
Rejection counters count packet attempts, not confirmed kernel drops. Receive,
verdict and compatibility failures count operations. ENOBUFS counts **netlink
overflow notifications**; those notifications do not supply a lost-packet or byte
count. They are never converted into estimated packet loss.

Administrator API peers can read machine-wide per-session counters, units,
timestamps and current userspace attribution/census/active-worker/retained gauges.
Ordinary peers receive only the general advisory state and sampling time, including
on read-only endpoints. No packet payloads, addresses or inferred owners are
included. Userspace gauges do not measure kernel queue depth. Stopped sessions
have zero current gauges. Diagnostic allocation failure is reported as unavailable,
without changing enforcement behavior.

UDP collector `missed_operations` and observed-usage coverage breaks retain their
own meanings and sources; queue diagnostics do not merge with accounting totals.
The GUI warning is separate from protection status and disappears on controller
disconnect. Older daemons without this capability retain their existing behavior.

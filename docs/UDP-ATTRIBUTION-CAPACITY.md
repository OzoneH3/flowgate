# UDP attribution capacity correction (2026-10-30)

This is a prepared candidate, not a deployment or a host gaming acceptance.
The inspected installation was `966d7886c41ee7805bdce905494d501d2ef4be7e`;
protection was intentionally stopped at entry. A later read-only check found
protection active under a different request ID, with the same daemon generation.
This task did not activate it or override that concurrent change. Rules and desired
shaping still matched the initial snapshots. The default update
pin, rules, shaping, collectors, preferences and application sessions are not
changed by this work. Experimental shaping components must be retained in the
matched bundle.

## Cause and scope

Original-direction UDP is inspected on every datagram. Admission happens before
ownership and policy, so an existing Allow cannot rescue a packet rejected at
attribution capacity. The retained incident has 8,514 capacity rejections. Its
repeatedly sampled tuple has historical decisions identifying the Wine game and
an existing application Allow; this does not attribute all aggregated drops to
that game. Pending Ask retention and netlink overflow are separate counters.

The Wine path repeated a full native socket/holder census to find the broker,
repeated it inside the runtime adapter, and performed another fresh bookend.
It also fully inspected unrelated processes before checking helper relationships
and Windows-image candidates. With serialized local endpoints and bounded
admission, that service cost can outrun incoming datagrams. Private real-runtime
receiver tests reproduced the failure before changing production code.

The correction shares initial discovery within an admission and uses a bounded
Wine dispatch hint across nearby admissions: 128 entries, at most 16 recorded
holders each, 250 ms monotonic age, full flow/direction/network namespace key.
Hits do not renew age. Only complete positive Wine results can seed hints;
native/hosted and link-local cases cannot. Hints carry no application decision,
rule or authority. Every group still performs a fresh complete kernel/FD-holder
census, equal socket inode/cookie, two equal runtime-table snapshots, broker
and holder generation checks and Windows-image validation. Current holders are
published only after validation. A failed hint is invalidated and gets one fresh
discovery attempt. Each packet receives current policy evaluation.

Helper exclusion first checks the reciprocal Unix FD relationship already
required by full validation; individual unreadable/vanished FD links fall through.
The image-candidate exclusion uses exactly Inspect's Wine-runtime predicate,
bracketed by executable/process generation; errors, oversized maps or changes
fall through. It does not filter by Windows path or application name. Deleted
image and anonymous/memfd image checks remain effective.

No queue-size increase, kernel UDP Allow fast path, Wine permission cache,
application exception, helper permission inheritance or Electron-contract change
is introduced. The existing five-second attribution deadline still does not
interrupt an already executing resolver. Snapshot/ABA and inaccessible-holder
limitations remain; this is not adversarial same-user code attestation.

## Receiver comparison

Private user/network/PID namespaces; actual copied Proton 11.0-15; fresh synthetic
Windows applications and two prefixes; 120 unrelated sleeping processes model
census population. Direct Wine invocation, not launcher acceptance. Two rounds
run one allowed-then-denied endpoint alongside an unruled other-prefix endpoint.
Each offers 7,500 256-byte UDP payloads at nominal 125 packets/s over about 60.65 s.
An independent native latency probe offers 20 packets/s. Sender success counts,
unique receiver sequences, queue counters, timestamps and daemon CPU are separate.

| Measurement | Installed baseline | Final candidate |
|---|---:|---:|
| Allowed receiver, round 1 | 6,112 / 7,500 | 7,500 / 7,500 |
| Denied receiver, round 2 | 0 / 7,500 | 0 / 7,500 |
| Other-prefix receiver, each round | 0 / 7,500 | 0 / 7,500 |
| Attribution-capacity counter delta, both windows | 5,146 | 20 (all in Deny/Ask round) |
| Census-capacity counter delta, both windows | 9 | 0 |
| Wine receiver latency median / p99 | 98.92 / 130.13 ms | 58.14 / 87.55 ms |
| Daemon CPU seconds, round 1 | 163.68 / 60.68 s elapsed | 163.99 / 60.68 s elapsed |
| Daemon peak sampled RSS, whole journey | 33,868 KiB | 35,060 KiB |

Final production source confirmation: `candidate-final-reviewed`, source patch
`c8d72aec36301441c412e92a741f7035d9d7f5725cbc1356fb8a96380f653cd6`
(subsequent documentation-only reconciliation), test binary SHA256
`e5abdabaf14feefca5c082d49f4a8dad75a5d59e84f7670e622ea7586801ca4f`.
The allowed round had zero attribution-capacity rejections; all 20 final-run
rejections occurred in the Deny/Ask-only round with census limit mask 4.
The earlier candidate4 had zero in both rounds; it is retained as earlier evidence,
not substituted for this final confirmation.

Candidate native delivery was 1,213/1,213 in each window, p99 2.29 / 2.14 ms.
Attribution deadlines, verdict errors and netlink-overflow notifications did not
increase in those windows. This does not substitute for a kernel queue-drop
packet counter: that proc file was inaccessible in this user namespace.
Receiver zero loss establishes delivery for the allowed workload directly.

Unruled traffic remains Ask and intentionally delivers nothing. Candidate Ask
retention-capacity rejections were 7,481 / 7,476 and retained-deadline rejections
8 / 12; these are not attribution-capacity failures. Decision-log records contained
no `runtime_evidence_incomplete` in the final runs; logs coalesce repeated decisions,
so record counts are not per-packet counters. The incident's intermittent generic
incomplete-runtime refusals were not reproduced or independently root-caused and
remain explicit refusals, never reusable positive hints.

Eight-packet bursts, nominal 125 packets/s per Windows endpoint, delivered
1,250/1,250 allowed payloads on both builds. Baseline measured 16 attribution plus
8 census-capacity rejections across the two windows; candidate had zero. Candidate
Wine receiver median/p99 was 32.92/75.86 ms versus baseline 92.03/127.28 ms.
The rejected packets in this baseline burst experiment were not receiver loss
of the allowed stream. Do not conflate aggregate counters with an application's
loss. In this burst case daemon round-1 CPU was 26.76 versus 15.64 seconds.

Deliberate overload used sixteen Windows sockets, nominal aggregate 16,000
packets/s and 32-packet bursts. Candidate allowed delivery was 261/16,000;
Deny/other-prefix delivery remained zero. Native probe delivery fell to 22/41 and
25/41. Capacity/fairness failures were explicit; sampled daemon RSS peaked at
38,948 KiB, queues drained, and subsequent policy changes still worked. Existing
48-packet/1-MiB attribution and 24-packet census bounds are unchanged. This is
bounded failure, not overload isolation or unlimited gaming throughput.

Live Allow -> Deny -> Ask -> Allow rule edits used fresh generation/version
checks. In each 2.5-second settled window, Deny/Ask delivered zero; restoring Allow
resumed delivery. A separate real WSADuplicateSocket journey transferred the same
kernel cookie from an allowed synthetic Alpha executable to a distinct Beta:
Alpha delivered 34 payloads, Beta was independently prompted and then denied,
and Beta delivered zero. Transfer began 7.73 ms after the last Alpha reception.
Two-prefix receiver isolation and synthetic same-cookie cross-prefix holder tests
are distinct evidence; a cross-wineserver live handle transfer is not claimed.

Timing measures sender-to-receiver latency, not an attribution-only histogram.
The earlier timestamped baseline11 ran amid unrelated CPU-heavy tests and is
retained as contention-affected evidence, not the clean comparison above.
Earlier candidate attempts and broken retained fixture attempts are also retained.
No public connectivity, host game improvement, or universal zero-loss guarantee
is established. The measured Wine latency remains about 58/88 ms median/p99 versus about 2.3 ms
native p99, at roughly 2.7 daemon CPU cores. This does not establish that the
reported game rubber-banding is fixed.

## Separate CPU observation and release checks

The reported 57.8% of one core was a five-second sample with protection stopped
while monitoring/shaping remained active. Historical profiling shows holder census
and process-stat work, but it was not a stopped-protection incident profile.
The sustained comparison above shows more delivered work at similar daemon CPU,
not a fix for that separate observation. No new host profiling or load test ran.

Focused tests cover hint bounds/expiry/isolation, positive-only storage, fresh
retry orchestration, socket replacement, broker restart/exec, same-cookie other
application/prefix holders, deleted images, memfd Wine, unreadable maps/FDs and
exec during candidate filtering. Synthetic tests do not prove receiver delivery;
the real-runtime results above provide that separate evidence. Full release race,
receiver, API-permission, static and GUI build checks must accompany the manifest.
Independent review is recorded in the bundle evidence with its exact scope.

Reproduction fixture: `scripts/acceptance/wine-udp-capacity.py`, compiled
`fixtures/windows-udp-saturation.c` with timestamp mode enabled by the harness.
Run via a private single-user namespace with a distinct parent netns, loopback up,
workspace-only runtime/helper/PE/run paths. Baseline and candidate use identical
options. The default `passed` flag covers identity/workflow assertions; assess
capacity and receiver loss from the recorded counters and denominators as above.
The PE transfer fixture and its exact harness are included in release evidence.

The installed Clang 23 crashed even on `--version`; cached Clang/LLD/LLVM libraries
22.1.8 were extracted under `.workspace/udp-capacity/toolchain`. Host packages were
not changed. Compiler package hashes and full build logs accompany the candidate.

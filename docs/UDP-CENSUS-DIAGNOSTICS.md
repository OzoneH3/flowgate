# Remaining Wine UDP census investigation

The baseline interim release was `0df3273eb23488eac10b341e45dcf6973b7e2ddd`.
The retained 120-second gameplay window recorded 4,029 **host-wide** attribution
capacity drops and two census-capacity drops. All 83 sampled journal entries
named the same UDP tuple, independently identified as the game under its existing
Allow. That does not identify all 4,029 packets as game traffic or measure remote
receiver loss. User experience: improved, but still rubber-banding.

Two ownership-change refusals and one missing-socket refusal on that tuple do
not prove a false refusal: tuple stability does not establish socket-cookie,
inode, holder or process-generation stability. Old logs lack the failed
comparisons, so these cannot be reconstructed retrospectively.

## Diagnostic candidate, not a performance fix

This change preserves policy, queue bounds, scheduling, identity contracts and
all validation predicates. It adds no ownership reuse. Root must explicitly arm
manual diagnostics with `FLOWGATE_PROFILE_DIR` and `FLOWGATE_PROFILE_MANUAL=1`.
Without both settings the capture is disabled, including a missing, empty or
unknown manual flag. There is no automatic startup capture fallback. The
privileged launcher forwards only the exact manual value `1`.

An administrator can invoke `diagnostic-start` over the existing local control
API with the exact daemon generation. The read-only endpoint cannot start it;
ordinary clients cannot trigger or inspect it. The client cannot select a path,
duration or rearm. `diagnostic-status` reports armed/requested/starting/running/
finished/failed/canceled. Manual capture occurs once per process, lasts at most
120 seconds (plus profile finalization), and stops earlier on daemon shutdown.
A lost acknowledgement is reconciled through status, never replayed.

Captured timing is **elapsed**, including scheduling/blocking, and nested stages
must not be added: socket census, holder census, process inspection, complete
resolution, Wine semaphore/session/table waits, runtime queries, helper validation,
image validation, final validation, callback-to-census-worker, census lane wait,
and census service. Worker visits include retries. Process CPU deltas and CPU
stack samples are separate from elapsed time and exclude the Wine helper's CPU.
Mutex profiling samples one in 20 contention events. Hint hits, hint-busy returns,
fresh fallbacks and holder second attempts are separate counts.

Private evidence projects observations already collected by the resolver; it
adds no socket/FD/runtime queries. Bookends retain initial/fresh/recheck socket
cookies/inodes/namespaces, up to 16 holder PID/start/executable revision/prefix
facts, holder issue codes and attempts, up to eight matching runtime rows, hint
source/age, observation times and exact comparison outcomes. Missing sockets,
direct Wine process census, discovery batches and pending revalidation are
separate contexts. These are **resolver observations**, not packet verdicts:
hint failures may recover on fresh fallback, and discovery is not admission.
Use final decision records to correlate paths; generic `resolve` alone does not
distinguish every caller.

Evidence budgets: 32 resolver failure observations, 64 successful observations
(maximum one per second), and a **separate 16-event queue-rejection budget**.
Each kind/flow key gets at most four records; at most 112 quota keys exist.
Records are capped at 16 KiB; skipped/oversized observations are counted. Socket,
holder and row counts expose projection truncation. High event rates can still
omit a rare refusal: absence of evidence is not proof of absence.
Queue rejection snapshots contain census/global packet and byte counts, queued
endpoint count and active census flow keys with service elapsed time. A job
already active when capture starts has unknown elapsed time. Projection is copied
under the queue lock; encoding occurs after unlock on the rejecting callback.

The output directory must be service-owned mode 0700, with no symlink components.
Files are exclusive mode 0600: CPU/mutex profiles capped at 8 MiB each, summary at
2 MiB. Evidence includes IP addresses and executable/prefix paths; retain locally.
No packet payloads, command lines or environment contents are captured. The API
returns status only, not the private evidence.

Instrumentation has overhead. A local timer/counter microbenchmark measured about
6 ns disabled and 88 ns enabled, zero allocations; this is **not** an end-to-end
profiling overhead bound. CPU/mutex profiling, timestamps and bounded JSON capture
can perturb the result. Do not run competing builds/tests during gameplay.

## Approval and capture sequence

Prepare and verify the exact matched diagnostic bundle with existing experimental
shaping components; approval of the interim release does not authorize this build.
Proposed root-owned private output: `/var/lib/flowgate/diagnostics/udp-census-01`.
Proposed temporary service drop-in:
`/run/systemd/system/flowgate.service.d/90-census-diagnostic.conf`, containing:

```
[Service]
Environment=FLOWGATE_PROFILE_DIR=/var/lib/flowgate/diagnostics/udp-census-01
Environment=FLOWGATE_PROFILE_MANUAL=1
```

The temporary `/run` override disappears on reboot. If reboot occurs before
capture, recheck arming and readiness; do not silently recreate it or start capture.

The user must approve the exact candidate/hash, guarded install/restart and these
arming writes. Preserve the freshest protection/rules/settings and actual prior
release. Do not reuse an existing output directory or overwrite an existing
unowned drop-in. Then wait for user readiness, trigger once, confirm running,
give START, and give STOP after the bounded capture. Keep host-wide counters,
flow-specific evidence and user experience separate. No generated host traffic.

After capture, keep the inert one-shot diagnostic build running; remove only the
owned temporary drop-in and reload systemd, without restarting. The running
process retains its environment but cannot rearm; drop-in removal affects the
next service start. Retain private evidence. No automatic downgrade or second
restart is proposed.

Only after measurement, implement and compare the general cost reduction against
0df3273 in isolation, including receiver loss/latency/CPU, independent Deny, live
policy edits and socket/holder transitions. Bounded ownership reuse, if needed,
requires separate explicit approval of lifetime, invalidation and exposure window.

## Launcher correction after diagnostic deployment

The approved `e74a0228` bundle retained an experimental shaping launcher that
forwarded the directory but dropped the manual flag. It therefore ran the old
60-second startup profile without readiness. No START was issued and the planned
120-second window never ran. The private startup evidence is retained separately;
it is not the coordinated gameplay measurement. The correction forwards the
manual flag and makes the backend reject directory-only configuration. Packaging
must apply this correction to the retained experimental launcher, preserving its
shaping arguments and helper artifacts. A new exact bundle/restart needs approval.

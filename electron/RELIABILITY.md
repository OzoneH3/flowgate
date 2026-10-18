# Activity refresh reliability

Base: local `master` **5bbfc71a9a7491f61b304d19d981bbec4c011c35**; this includes
the previously released Electron history. No Go/API/schema, host lifecycle or design
changes are part of this increment.

## Demonstrated rule race

Controlled response gates, before editing:

1. Save is accepted; the next policy response contains `saved-rule` while the last
   independent list is still empty.
2. A subsequent list contains `saved-rule`; its inventory stamp changes.
3. The old client clears `control.policy` and emits: the rule disappears from Info.
4. The next independent policy response restores it.

Evidence `.workspace/reliability/blink-before.json` records list/policy IDs and
arrival times. A second bug let `await pollControl()` return immediately when an
older request was busy, including after Save. A pre-Save response could therefore
be treated as a post-Save refresh. Go's map-backed list also has no stable array
order; unchanged inventories could reset presentation signatures unnecessarily.

### Correction

- Coalesce control, policy and context reads. Main-owned mutation fences cover
  rule create/edit/delete and remembered decisions; pre-mutation reads cannot
  replace a later accepted context. No mutation replay or optimistic rule insertion.
- Join complete authorized **list → policy → confirming list** snapshots using
  equality of the full inventory, target states, permissions, enforcement and zone
  definitions. This uses existing operations, not per-rule versions as a global
  clock. If the bracket changes, defer to the next existing refresh; no retry loop.
- Publish rules and summary together. When policy associations are ahead of the
  visible Activity sequence, stage them until the corresponding observation arrives.
- Canonicalize list ordering. Ignore an older policy response without clearing an
  already accepted newer one. Role/generation/disconnection changes still revoke
  authority; metadata failures show unavailable policy rather than retaining an
  indefinitely pinned inventory. Existing expiry/staleness checks still apply.
- All rule changes remain conditional on backend identity/version/preview checks.
  External edits/deletes appear normally. Lost ACK remains unresolved until an
  explicit authoritative check; there is no automatic Save retry.

The backend owner was sent the failing sequence and a possible additive coherence
field request. No field was necessary for the bounded existing-API bracket above;
no backend source was edited. One confirmation read per policy refresh is the
cost of compatibility. There is no added polling timer or per-row query.

## Demonstrated responsiveness cost

The actual sandboxed Wayland application was traced against a private real daemon
with **509 native socket rows** (250 owned loopback TCP pairs plus fixture sockets).
Expanded Activity, selection/unit changes, quick setter, detached Info and Chart,
create/external disable/enable/delete were exercised in both matched runs.

| Measure | Before | After, matched journey |
|---|---:|---:|
| Renderer tasks over50ms |35|9|
| Total long-task time |2855ms|660ms|
| Longest renderer task |102ms|101ms|
| Frame interval p99 |125ms|55.6ms|
| Main-loop delay p99 |18.2ms|17.1ms|
| Main-loop maximum |135.8ms|133.6ms|

These are single bounded runs, not a benchmark guarantee. The roughly100ms maximum
renderer task and main peak remain; a prolonged complete lockup was **not**
reproduced. Thus the evidence supports reduced repeated stalls, not a claim that
all intermittent freezes are eliminated. Backend query latency in the final
instrumented journey: median3.7ms, p95 13.2ms, max37.1ms; it did not explain the
captured renderer long tasks.

Changes target demonstrated repeated work:

- Retain unchanged keyed table rows and update presentation-only rate cells in
  place; no whole-tbody replacement every refresh. Sorting still moves rows by ID.
  Current handlers/identity snapshots refresh when row data changes.
- Cache main's hierarchy by observation generation/sequence/collection time;
  a250ms deadline tick no longer reconstructs it or increments pane revision.
- Publish one shared pane frame only when presentation/control content changes.
  Detached charts key history fetches by observations, not unrelated pane revisions.
- Index backend-supplied application/process/row associations per policy object,
  preserving all exact identity gates rather than repeatedly scanning the batch
  for every connection. No frontend policy matching is introduced.

## Evidence and checks

All paths below are relative to this Electron worktree and are ignored artifacts.

- Before: `.workspace/reliability-before-0y7q79/{trace.json,result.json,activity.png,info.png}`.
- Matched final performance: `.workspace/reliability-cmp-IivlyR/` (same four mutation
  steps; query timings in `transport.json`).
- Extended real regression: `.workspace/reliability-after-LCBhCK/`: created rule
  remains present through five refresh samples; external disable/enable/delete;
  app/process/zone selection while a policy response is deliberately held; detached
  Info stays synchronized. A proxy drops one real Save ACK, then disconnects and
  reconnects: explicit reconciliation confirms the reserved rule with **one Save**.
  Conditional cleanup returns to0. Timings, IDs/versions, generations, request-start
  and response-arrival order are recorded without unrelated host inventories.
- `.workspace/reliability/blink-after.json`: after fix the saved list and policy
  appear together, without the intermediate null policy.
- `.workspace/reliability/cleanup.json`: exact private fixture generation/rules0.
  Owned supervisor exited0 and reported CLEANED; bulk sockets/daemon/peer were
  disposed. Host daemon, enforcement and UDP collector were untouched.

Build/typecheck and35 focused checks passed. Deterministic tests use deferred
response gates, not sleeps, for old-list-after-Save, policy/list mismatch, old-daemon
response, Activity association readiness, external changes and snapshot ordering.
Real observation pacing in the performance runner measures a bounded session;
those waits are not a product workaround. Existing receiver/enforcement evidence
was reused.

```sh
npm --prefix electron run build
node --test electron/test/inventory-coherence.test.cjs electron/test/backend.test.cjs electron/test/policy.test.cjs electron/test/panes.test.cjs electron/test/observed-rules.test.cjs electron/test/rules.test.cjs electron/test/decision-remember.test.cjs
```

Optional UI rerun only against a fresh disposable held fixture:

```sh
STAGE=after JOURNEY=1 FLOWGATE_TEST_READY=/absolute/project/.workspace/owned/ready.json node electron/test/reliability.mjs
```

## Continuous-use follow-up (2026-10-19)

Implementation base **ce8bb0f**, now integrated by the backend owner. Electron owns
only its frontend and disposable fixtures; backend owns deployment/integration.

### Remaining stacks and focused fixes

CPU profiles at **89 native socket rows** identified repeated `TrafficGraph.draw`
through unchanged `setPresentation`, forced `getClientRects` layout in chart update,
and native IPC serialization of full state on every250ms deadline tick.

- Unchanged chart settings do not redraw; same-frame unit/source/settings changes
  coalesce into one animation-frame paint. Geometry is read before legend writes.
- Deadline ticks now send only generation/time/publication, preserving real request
  deadlines and policy expiry. Full authoritative changes still publish immediately.
- Hidden/minimized panes receive a fresh frame on show rather than continuously
  rendering hidden copies. Main hide/show handles detached views together.
- Electron-local publication sequence orders pushed state against asynchronous
  initial/resume/popup snapshot replies. It is **not** a backend policy revision or
  authorization signal. Older delivery cannot remove newer rules or retarget a pane.

Same bounded normal-workload interaction, before/after: sampled chart drawing CPU
89ms→6ms; FunctionCall trace total362ms→210ms; layout/style count328→234.
Both runs had zero renderer long tasks over50ms. Main maximum144ms→137ms remains:
there is **no** claim that all freezing or the main peak is fixed.
Evidence: `.workspace/reliability-cpu-before-a7i6Yu/` and
`.workspace/reliability-cpu-after-yDVVuv/` (`*.cpuprofile`, trace and result).
Optional future stack capture: `PROFILE_CPU=1` on `test/reliability.mjs`.

### Continuous protection consumer

Capability **continuous-firewall-v1**, explicit primary
`can_control_protection`; backend contract in the backend owner's coordination
note. Separate continuous section in the existing Firewall menu:

- Actual stopped/starting/active/stopping/failed/degraded, profile incoming/both,
  requested mode and cleanup. No countdown and no active label from a preference.
- Fixed readiness/start/stop with frozen daemon generation/session, fresh Start
  nonce, no automatic mutation retry. Unknown acknowledgement is reconciled from
  current status. Older backends say unavailable; bounded evaluation stays separate.
- Only the main window can invoke lifecycle mutations. Panes share read-only status;
  rules and decisions retain their independent backend permissions.
- UI disconnect says protection unknown, not stopped. Quit does not send Stop.
  Known continuous protection with no pending decisions permits ordinary GUI exit
  without a redundant confirmation; warnings remain when requests await a decision.
- Prompts remain pinned while others arrive. Existing dismiss control says Next
  request when another awaits review; dismissal never means Deny. Old-generation
  prompts are explicitly unavailable. Lost Once ACK retains uncertainty while also
  showing the backend's actual terminal request state. Every Decide sends generation.

Real sandboxed Wayland candidate **55198b35fa65063036dce471839059807acdfdc3**,
binary754b2a9b… in a private namespace: readiness→both active; concurrent incoming
and outgoing native attempts while main hidden/Info detached; harmless repeated
Enter; expiry; explicit next request; Allow/Deny; disconnect and dropped Once ACK
(one Decide); detached process rule stable across refreshes and conditional Delete;
GUI exit leaves active protection, reopen recovers without Start replay; explicit
Stop confirms monitoring, zero rules. This is **isolated-real**, not host evidence.
Evidence `.workspace/continuous-real-5migP3/{evidence.json,*.png}`; fixture cleanup
is delegated back to its backend owner after explicit DONE. Receiver/kernel proofs
are reused; no host action was taken by the UI agent.

The bounded45-minute monitor soak is still in progress at this implementation
checkpoint; final aggregate and cleanup will follow. It uses89 sockets, periodic
native churn, pane create/close, stored-rule refreshes and deliberate disconnects.
Prompt/continuous acceptance is the separate real journey above; the monitor soak
must not be described as enforcement or pending-prompt soak evidence.

### Large-workload follow-up after the implementation checkpoint

At509 rows, the remaining periodic stalls were traced to layout of about20,000
DOM objects. The cache's old replacement algorithm left an invalidated row in the
parent until the ordering pass ended: replacing one selected row consequently
moved every following sibling. Traffic and policy refreshes also invalidated whole
rows despite unchanged visible structure.

The follow-up replaces an invalidated keyed node **in place**, separates live rate
cells from native identity/ownership/state structure, and refreshes rule strips
without replacing unchanged controls. Strip handlers select the stable row ID and
resolve current identity through Activity/main's existing rule service; no old row
snapshot grants authority. Rate sorting still uses the newest measurements.

Matched bounded509-socket profiles (ce8bb0f vs final keyed-row treatment):

| Measure | Before | After |
|---|---:|---:|
| Body insertions/moves |4628|522|
| Renderer tasks over50ms |5|1|
| Total long-task time |303ms|76ms|
| Frame interval p99 |51ms|25ms|
| Main-loop maximum including trace export (contaminated; see correction) |114ms|142ms|

The one remaining long task is initial **Expand All** (76ms), not a recurring
refresh. The main peak was subsequently isolated to diagnostic export overhead
(see correction below). A separate instrumented main IPC pass
measured maximum handler duration5.4ms and graph handler0.06ms while event-loop
maximum116ms remained; this measurement also included trace export. Native `perf`
is unavailable; no software was installed. Do not call
this complete elimination of freezing.

Main-repository evidence: `.workspace/lg-before-LG8Lyi/`,
`.workspace/lg-keyed-ByixC1/`, `.workspace/lg-phase-fu1Y02/` (CPU profiles/trace/results).
The copies use identical compiled content, isolated preferences and native scale;
a separate normal-workload soak ran in the background. These are single bounded
comparisons. Intermediate investigative profiles are not presented as improvements.

`.workspace/lg-after-67fT2l/` is the focused real follow-up for the row change:
create/stable refreshes, external enable/disable/delete, app/process/zone selection
while a read is held, detached Info and lost Save ACK/reconnect with exactly one
Save. No receiver matrix was repeated. Large fixture zero rules verified, supervisor
CLEANED/exit0; `.workspace/daily/large-cleanup.json` in this Electron worktree.
Deterministic `keyed-rows.test.cjs` reproduces the displaced-sibling negative case;
`row-structure.test.cjs` verifies traffic changes retain nodes while native
identity/ownership/state/direction changes invalidate them.

### Main-loop measurement correction

A subsequent phase-isolated experiment identified diagnostic overhead: CDP trace
export without a requested chunk size caused66.7ms of main-loop delay for a4.96MB
stream. A comparable5.27MB stream read in64KiB chunks produced10.9ms maximum.
Idle/pane operations were about10–13ms; Node CPU-profiler Start itself caused25ms.
Evidence `.workspace/daily/instrumentation-raf.json` and the owned probe script.

Earlier114–142ms main maxima included exporting roughly11MB traces; they are
**contaminated measurements**, not proof of ordinary UI blocking. The test harness
now records interaction timing before profiler/trace teardown, records teardown
separately, and uses bounded64KiB CDP reads. This is a measurement fix, not a claim
that all historical freezes were caused by instrumentation. Untraced long-session
measurements below are the runtime evidence; initial509-row Expand All remains a
measured76ms renderer task.

### Concurrent prompts and ordinary GUI exit

Real isolated candidate `b6aa38191954d538fb4af0bb9b1f5d006fa9dfa4`, binary
`bc01bada17c01b9e47a1ac21bdbf66e7a3617ed8100fbc510f2b6f8c63511e7c`,
generation `62e5652843393126f3005e98c71b9d23`, ran the final compiled frontend
in sandboxed native Wayland. `prompt-soak.mjs` passed15 one-minute cycles with
30 real requests from two different executable identities. Alternating Allow/Deny,
open expiry, dismissed views, detached Info, hidden main window, polling, deliberate
disconnects and dropped acknowledgements produced exactly15 decision writes;
no automatic replay, renderer errors, accumulated windows or repeated foreground
activation. Settled window count1, main timers5, main heap8.1–10.0MiB. These are
bounded observations, not proof of indefinite leak freedom. Once retains its TCP
admission/UDP tuple-lease semantics; terminal permission is not receiver proof.
Existing receiver evidence is reused.

Evidence in this worktree: `.workspace/prompt-soak-HwBapl/result.json`.
An earlier harness attempt `.workspace/prompt-soak-twv7li/` stopped because Escape
closed the window before Playwright's key-up returned; that harness error is not
counted as a passing run or a product crash. The corrected run reused the already
active fixture deliberately, without automatically replaying Start.

`continuous-reopen-real.mjs` then passed ordinary GUI Quit (daemon remains active),
a held request arriving while GUI was absent and recoverable before its original
deadline, and an expired absent-GUI attempt never reopened as actionable.
Evidence `.workspace/gui-reopen-B1XCg7/result.json`. Final explicit Stop/rules0
verified, all own windows closed; backend cleanup ownership returned with DONE.
No host operations or receiver/enforcement matrix reruns were performed.

### Completed45-minute monitoring soak

`.workspace/daily-soak-sRHf2o/{result,aggregate}.json` records180 samples over the
planned45-minute session with89 real socket rows,15 conditional rule cycles,
45 pane cycles,22 deliberate reconnects and45 bounded native traffic churn cycles.
The last periodic sample is at2685s; the runner continued to2700s before success.
The copied build contains the initial clock/graph/publication fixes; later keyed-row
and continuous changes have the separate final-build real journeys above. Do not
call this45 minutes of final-build continuous enforcement or pending prompts.

- Renderer tasks over50ms:0;46 frame intervals over50ms among201,916 frames.
- Main-loop maximum18.68ms, p9910.49ms, without trace-export contamination.
- Request concurrency at most2; settled window count1 and main timers5 throughout.
- Warm renderer heap5.8–31.9MiB (median15.9), main heap11.2–39.1MiB (median19.0).
  Five-minute RSS troughs return around200–212MiB; no sustained resource growth
  demonstrated. Stable DOM/listener lower envelopes; bounded GC peaks are not leaks.
- Electron metric median CPU: Browser0.08%, renderer Tab0.41% for this workload.

Owned monitor fixture generation `94aa78527bd7bb23a311c79db0cad259` was independently
read back as stopped/rules0, quit, supervisor exit0/CLEANED. Cleanup record
`.workspace/daily/cleanup.json`; own large fixture likewise cleaned. Preferences
restored by the monitor runner, all own GUI windows closed. Backend independently
verified the prompt fixture stopped/rules0 and CLEANED after DONE.

Product checkpoints `4e93f8e` and `34b29e0` are integrated by the backend owner.
Final test/docs follow-up changes no policy or runtime contract. Continuous UI
requires `continuous-firewall-v1` and explicit `can_control_protection`; Once
supplied-generation fencing pairs with backend `92d0a04` or descendants. Final real
prompt/reopen candidate was `b6aa381`; deployment preparation has advanced to
`d7c969b`, with unchanged consumer contract. Host installation/authentication remains
pending at this handoff: no host GUI check or host activation is claimed.

Remaining uncertainty: no prolonged lockup was reproduced; initial509-row Expand
All remains76ms. These bounded runs do not establish that every intermittent freeze
or indefinite resource leak is resolved. Existing rule-blink ordering safeguards,
external changes, lost ACK reconciliation and scope/identity semantics remain intact.

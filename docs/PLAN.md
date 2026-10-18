# Authoritative implementation plan

## Follow-up (not started): explicit stored Ask action

NetLimiter Blocker offers a stored per-rule Ask beside Allow/Deny. FlowGate has only
Allow/Block rules plus unmatched-application prompting during evaluation; these are
not equivalent. The Activity quick setter (UI round c772f7c2, existing APIs only)
deliberately omits Ask. Implementing it needs a separate scoped proposal: rule
schema/action, evaluator semantics versus pending/Once, monitoring-mode meaning,
Decision Log representation and older-binary compatibility.

## Completed: direct Activity rule creation

Primary capability `observed-rule-create-v1` adds generation/principal/draft-bound
30-second preview and save from a freshly verified single-holder native Activity
context. Explicit protocol/direction/address/ports/absolute expiry; identity comes
only from backend inspection. Stored-only monitoring, existing authorization,
SQLite atomic publication and precedence remain. Creation never approves pending
packets; repeated same-token saves are bounded acknowledgements, not duplicate
rules. See [OBSERVED-RULES.md](OBSERVED-RULES.md) for schema, examples, errors,
reconciliation and native/namespace limitations. New `.workspace/flowgate-creation`
build leaves the root monitor/executable untouched; eventual restart unexecuted.
Focused race/vet/API/shared-FD/SQLite checks and isolated receiver Allow->Block
passed. No frontend integration or broader matrix rerun.

## Complete: Activity policy explanation contract

Read-only generation/token/ordered-sequence batches expose configured scopes,
defaults and direction coverage without inventing historical verdicts or permission
targets. Recorded-event explanations reuse policy.Evaluate directly. Preserve the
unchanged mutation/verdict engine. UI consumption and eventual authorized monitor
restart are separate; observed-app creation now has its own explicit token API
(OBSERVED-RULES.md), never authority inferred from this read response.

## Complete: bounded Tailscale coexistence increment

Replace only the corroborated1.104.1 iptables-nft client refusal, validate opaque
writer masks/locations plus routing, keep incoming-only/admin requirement, test
actual TUN receiver/mark/copy/drop/lifecycle behavior. Preserve active monitor and
user activation boundary. Live encrypted tailnet/roaming and dynamic configuration
revalidation remain explicitly unverified; no force flag or automatic exemption.

## Current architecture direction: one root backend, unprivileged desktop

Non-enforcing native root daemon, explicit administrator grants, privacy projection
and combined Activity/policy API are implemented. Next: permission-aware frontend
attachment, integrate accounting into that process, then deliberate service and
mode-transition design. Preserve ordinary read-only startup. Tailscale component allocation/routing/hook tests passed; actual encrypted
tailnet interception and dynamic rewrites remain unverified.
See AUTHORIZATION.md. No deployment or live enforcement is part of this task.

## Complete: practical read-only diagnostics

Human/JSON doctor shares real firewall preflight, reports bounded visibility,
helper/BTF metadata, existing authorized status and explicit unchecked activation
steps. Startup refusal codes are additive; no UI or activation workflow change.
Focused controlled/namespace tests and one unprivileged host sample recorded.
The current bounded Tailscale profile is documented above; never bypass refusal.

## Complete: runnable frontend integration

Full Electron series integrated from its released clean checkpoint; Qt retained
and migrated to conditional Delete with exact uint64 handling. Main-checkout
Wayland Activity/decision/rule/tray smoke and focused Qt checks passed. Keep
`run-desktop.sh` default unchanged and use `run-electron.sh` for the alternative.
No new release gate or game work; retain the explicit host-activation boundary.

## Complete: atomic conditional rule deletion

Add generation/version-conditioned deletion under the existing edit/commit mutex;
retain explicitly unsafe legacy compatibility, provide conditional CLI, verify
concurrency/rollback/recreation/lost response and one isolated receiver path.
Caller migration is separate frontend work; contract is in API.md.

## Complete: bounded native ownership improvement

Read-only host categories sampled; native leader-exit gap reproduced and fixed.
Current FD/generation rechecks, credential/namespace cache checks and display-only
same-application evidence verified with focused fixtures/race tests. See ATTRIBUTION.md.
Keep cross-user/namespace limitations explicit; no new privileged path or frontend
integration is part of this increment.

## Complete: isolated UDP accounting milestone

1. Implement namespace/UID-filtered sock length BTF probes and bounded cookie maps.
2. Keep collection-only IPC, authentication and Stop independent of enforcement.
3. Integrate explicit activation and compatible table semantics, preserve TCP.
4. Complete build, synthetic API/lifetime/UI tests and real UDP fixtures (done).
5. Authenticated kernel UDP4/6, shared/reuseport/reuse/restart/loss checks passed.
6. Actual unprivileged Wayland measured-rate capture passed 3/3; evidence and CPU/RSS
   are indexed in STATUS/UDP. Preserve it instead of repeating the matrix.
7. Live-host collection, offload/bypass variants and other kernels remain unverified;
   keep monitoring opt-in and firewall activation separate.

## Complete: truthful Activity TCP measurements and Unidentified grouping

1. Request bounded TCP_INFO counters via read-only inet_diag; validate response lengths.
2. Track cookie/network-namespace keyed observed deltas and monotonic rates, no stale/reset spikes.
3. Clarify owner evidence and preserve shared/unknown socket measurements.
4. Add numeric traffic columns and partial aggregates in the existing Qt tree.
5. Verify controlled TCP v4/v6, idle/reuse/restart/shared cases and actual Wayland UI.
6. UDP byte metrics remain unavailable: this source has no UDP transferred-byte counters.
   No privileged collector or host hooks are introduced. Document limitations and commit.

## Complete: structured decisions, atomic editor and opt-in outgoing profile

1. Reuse shared NFQUEUE with verified hook direction; preserve replies/startup flows.
2. Keep incoming-only default; carry explicit incoming-and-outgoing profile through terminal startup, health and UI.
3. Add structured prompt and revision-checked atomic persistent rule editing (missing at actual start 9235954).
4. Test native outgoing TCP/UDP v4/v6 at receivers, scoped remembered/edit/restart behavior and Wayland prompt/editor.
5. Update current semantics and commit; no host activation or Wine work.

## Complete: one coherent desktop application

1. Independent asynchronous Activity and control connections in one window.
2. Explicit five-minute evaluation through terminal sudo; verified readiness, scoped Stop/recovery and independent countdown.
3. Safe root-owned executable snapshot; no live activation during development.
4. Useful saved-rule columns, stable selection, Enable/Disable/Delete without expiry changes.
5. Bounded native notifications/tray with a persistent pending count and no focus stealing.
6. Focused actual-controller namespace/UI evidence; reuse the prior protocol matrix.

## Accepted baseline: running desktop program

1. **Complete:** Qt 6 Widgets client connected asynchronously to the real Unix API;
   persistent pending list, selected details, native non-modal prompt, exact
   backend scope previews, Allow/Block and bounded recent decisions.
2. **Complete:** one-command native isolated demo; GUI outside the namespace,
   existing peer authorization intact, no host networking changes.
3. **Complete:** real Wayland Qt button-to-receiver checks, expiry/disconnect/
   read-only handling, rendered layout inspection and reproducible commands.
4. **Complete:** live read-only host observer and Activity tree; preserve the user-accepted lab demo. Normal launch: `scripts/run-desktop.sh`.
5. **Desktop layout:** use compact navigation, a dense activity tree, and an information panel with a chart. Display only supported actions.
6. **Historical parallel ownership (released):** integration stream owns backend/API, launch scripts, functional tests and main docs. The separate design worktree owns frontend presentation (`desktop/activity.*`, `desktop/window.*`, `desktop/main.cpp`, `desktop/CMakeLists.txt`) and `docs/VISUAL.md`. Coordinate functional frontend changes explicitly. No competing frontend rewrites.

Keep the existing Wine/Proton adapter and its evidence. Resume broader game
identification only after the running desktop workflow is useful. Do not reopen
settled backend tests without a changed code path or contradictory evidence.

Later: application/process/connection tree; quick incoming/outgoing controls;
rule editor and persistent history; launcher adapters and wider game validation;
distribution/service packaging; charts/traffic totals; optional bandwidth control.
The backend remains frontend-, desktop- and init-independent.

STATUS.md records current capabilities; HISTORY.md indexes prior backend evidence;
HANDOFF.md records reproducible continuation instructions.

Integration outcome: both NetLimiter 5 design commits reviewed and integrated without conflicts. Actual Wayland live-monitor and isolated UI Allow smokes passed. Reuse broader recorded evidence. Next: explicitly authorized host evaluation of the new bounded controller; game detection remains deferred.

## Deferred functionality from the NetLimiter comparison

The released [reference](NETLIMITER-REFERENCE.md) found no new backend dependency
for existing Activity, prompts, policy summaries or observed-application rule creation.
Firewall direction remains connection initiation, independent of upload/download.
Keep the following future backend work separate from this evaluation integration:

- Connection lifecycle history (not the Decision Log's recorded decisions).
- Persistent traffic statistics (not the bounded live Activity graph).
- Upload/download limits with actual traffic shaping semantics.
- Bandwidth priorities with actual allocation semantics.
- Reusable filters/zones, quotas and scheduling with explicit supported policy/storage.

No placeholder controls, new policy actions or accounting/VPN deduplication are
implemented by listing these gaps. They are optional roadmap items, not activation gates.

### Implemented and deployed: explicit process-instance rules

`process-instance-rules-v1` provides server-pinned native process/session targets,
process-before-application precedence, schema3 stored inactive-after-restart
inventory, preview/versioned mutation/reconciliation and Decision Log targets.
Exact scope, same-executable exec limitation, evidence and reproduction are in
[PROCESS-RULES.md](PROCESS-RULES.md). It is no longer approximated by an app grant.
Deployed in the non-enforcing root monitor (60d35a3, 2026-10-18; see INTEGRATION.md).
Stored process-rule documents are durable data; downgrade requires a reviewed
data-preserving migration/restore plan, never deleting or stripping them.

### Deferred: explicit stored Ask control

UI2 round3 and backend agreed not to add Ask during the visual fidelity pass.
The pure evaluator already accepts Ask, but Activity creation/editor paths do not.
A dedicated increment must cover matched-Ask pending attribution and immutable
Decision Log snapshots (separate from unmatched defaults and final user outcomes),
Once versus Remember collision/override semantics without changing precedence,
and legacy-editor acknowledgement so Ask cannot silently become Allow. Older
schema2/3 readers already accept Ask; a capability alone is not a downgrade guard,
so document/reader compatibility needs an explicit fail-closed design.

Proposed boundary: current native application/process targets and existing scopes,
existing tiers/priority/ID, current retention deadline/Once leases, stored-only when
monitoring; no weights/default redesign or implied receiver delivery. Dependency
estimate: one focused backend API/decision/log/compatibility increment with isolated
receiver and authenticated mutation cases, then one capability-gated UI consumer
and integration journey. No Ask control ships until that contract is implemented.
No action/API/storage or live runtime change results from this roadmap entry.

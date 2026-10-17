# Authoritative implementation plan

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

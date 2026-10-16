# Authoritative implementation plan

## User priority: running desktop program now, game detection later

1. **Complete:** Qt 6 Widgets client connected asynchronously to the real Unix API;
   persistent pending list, selected details, native non-modal prompt, exact
   backend scope previews, Allow/Block and bounded recent decisions.
2. **Complete:** one-command native isolated demo; GUI outside the namespace,
   existing peer authorization intact, no host networking changes.
3. **Complete:** real Wayland Qt button-to-receiver checks, expiry/disconnect/
   read-only handling, rendered layout inspection and reproducible commands.
4. **Complete:** live read-only host observer and Activity tree; preserve the user-accepted lab demo. Normal launch: `scripts/run-desktop.sh`.
5. **Desktop layout:** use compact navigation, a dense activity tree, and an information panel with a chart. Display only supported actions.
6. **Parallel ownership:** integration stream owns backend/API, launch scripts, functional tests and main docs. The separate design worktree owns frontend presentation (`desktop/activity.*`, `desktop/window.*`, `desktop/main.cpp`, `desktop/CMakeLists.txt`) and `docs/VISUAL.md`. Coordinate functional frontend changes explicitly. No competing frontend rewrites.

Keep the existing Wine/Proton adapter and its evidence. Resume broader game
identification only after the running desktop workflow is useful. Do not reopen
settled backend tests without a changed code path or contradictory evidence.

Later: application/process/connection tree; quick incoming/outgoing controls;
rule editor and persistent history; launcher adapters and wider game validation;
distribution/service packaging; charts/traffic totals; optional bandwidth control.
The backend remains frontend-, desktop- and init-independent.

STATUS.md records current capabilities; HISTORY.md indexes prior backend evidence;
HANDOFF.md records reproducible continuation instructions.

Integration outcome: both NetLimiter 5 design commits reviewed and integrated without conflicts. Actual Wayland live-monitor and isolated UI Allow smokes passed. Reuse broader recorded evidence. Next: user feedback; game detection and host enforcement remain deferred.

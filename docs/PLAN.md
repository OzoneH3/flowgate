# Authoritative implementation plan

## User priority: running desktop program now, game detection later

1. **Complete:** Qt 6 Widgets client connected asynchronously to the real Unix API;
   persistent pending list, selected details, native non-modal prompt, exact
   backend scope previews, Allow/Block and bounded recent decisions.
2. **Complete:** one-command native isolated demo; GUI outside the namespace,
   existing peer authorization intact, no host networking changes.
3. **Complete:** real Wayland Qt button-to-receiver checks, expiry/disconnect/
   read-only handling, rendered layout inspection and reproducible commands.
4. **Next:** refine desktop usability from user feedback (notification/tray access
   and saved socket preference are small candidates), retaining persistent pending
   state in the daemon. No production host installation without explicit scope.

Keep the existing Wine/Proton adapter and its evidence. Resume broader game
identification only after the running desktop workflow is useful. Do not reopen
settled backend tests without a changed code path or contradictory evidence.

Later: application/process/connection tree; quick incoming/outgoing controls;
rule editor and persistent history; launcher adapters and wider game validation;
distribution/service packaging; charts/traffic totals; optional bandwidth control.
The backend remains frontend-, desktop- and init-independent.

STATUS.md records current capabilities; HISTORY.md indexes prior backend evidence;
HANDOFF.md records reproducible continuation instructions.

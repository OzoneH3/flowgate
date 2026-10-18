# Activity and Rule Status

Semantics kept: `Not set` ≠ Allow; stored rules ≠ enforcement ("Stored only · firewall stopped" line);
application vs process rules stay distinct (Blocker row = selected target, `↳ App` = fallback, backend
precedence); process rules are session-bound and labelled "until this process exits"; an exited process
shows `Inactive · ended`, pills and enable toggle disabled, Delete still available; shared/unidentified
sockets get no process tier; connection In/Out means initiation and the matching column header is
highlighted for a known-direction connection; partial coverage and measurement sources remain in the
properties box and tooltips.

Keyboard safety (verified in the real journey): opening a cell with Enter focuses the popup container,
not an action, so the same key press cannot cascade into a save; Escape closes and returns focus to the
cell; after an acknowledged save focus returns to the cell. Cells are never disabled during a transient
policy-association gap (that would steal focus); the popup explains why an action is unavailable.

## Evidence

Backend 6c68f8cd0627bce69f15f4e995a3cf68fa161215 (binary `.workspace/flowgate-any-protocol`,
SHA256 7b8fbbe0…), held fixture `.workspace/ap-ui` (disposable namespaces; same-executable alpha/beta).

- Real journey `electron/test/rule-status-workflow.mjs` (`FLOWGATE_TEST_READY=<fixture>/ready.json`):
  application In cell via keyboard (Enter opens, second Enter saves nothing, Escape restores focus) →
  one-click `Allow` stores `protocol:"*"`, persistent, focus back on the cell → alpha `Out Block`
  (schema 3, session lifetime) → beta shows no own rule and the dimmed fallback → flip alpha's rule from
  the popup pill (filter and expiry unchanged, application rule version unchanged) → disable via the
  checkbox → rule deleted behind the UI, the next click reports "Rule no longer exists", nothing is
  recreated → Delete from the popup (conditional) → 860×600 popup inside the Info View. Captures in
  `.workspace/rule-status-real-RhfKWB/`. A second run with `FLOWGATE_EXIT_ALPHA=1` reached the exited
  state and exposed that the popup's Delete was disabled for an inactive target; fixed, and because that
  run consumed the fixture's alpha, the inactive popup is covered by the labelled synthetic runner.
- Synthetic (labelled) `process-presentation.mjs`: popup focus, Advanced route, exit → `Inactive · ended`,
  popup Delete-only, known outgoing / shared / unidentified connections, narrow. `presentation.mjs`:
  multiple scoped, disabled, expired rules in the status strip and rule details.
- `creation-workflow.mjs` (own disposable daemon, released binary): Advanced editor route from the popup.
- Unit: `npm test` (76). Superseded runners `activity-rules-workflow.mjs` and `process-rules-workflow.mjs`
  now alias the new journey; `policy-workflow.mjs` does not touch the setter and was not rerun.
- Host (read-only, old daemon 60d35a3 gen e47c8938): matrix renders, popup shows the `TCP | UDP`
  fallback, focus on the popup, no preview/save issued, generation/rules unchanged.

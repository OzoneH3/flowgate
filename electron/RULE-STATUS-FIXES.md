# Rule Status click/popup corrections

Base `8e160612eefd7c128f235777e3aae6b564e7a869`; no backend policy changes.

## Reproduced and corrected

- A table Blocker click selected the correct process but anchored the setter to the
  sidebar matrix. It now anchors to the clicked strip, retaining that row/direction
  across ordinary polling; filtered-away anchors close. Matrix icon/text/background
  all open the same target. Unsupported families remain non-controls.
- Detached Info delegated the entire interaction to Activity. Quick setters now stay
  in the clicked window. Only that registered Info window may use the bounded rule
  proxy: drafts, receipts and reconciliation handles are bound to its selection,
  generation and sender. All previews/saves still use the existing single main Rules
  service; process bindings are compared in full. Advanced editors/Delete confirmation
  continue in Activity. No socket, shell, filesystem or generic IPC access was added.
- Absolute positioning only considered sidebar width and could extend below the
  window. Setters use viewport coordinates, flip above an edge, clamp and scroll their
  own contents. Resize/scroll recomputes placement. Escape restores the clicked control;
  outside click dismisses an idle setter, not an already submitted mutation.
- Existing chart traces/axes already mapped download green `#9ccc65`, upload red
  `#f44336`: no swapped-line defect was reproduced. Sample details were monochrome.
  They now use the same series tokens as legend/axes/traces. Toggling retains series
  identity. Table rate highlights remain subdued gray; unknown remains `—`.

Selection/generation/policy changes invalidate idle setters. In-flight results retain
existing acknowledgement/conflict/reconciliation behavior; no blind retry. Multiple
rules have separate exact-rule action rows. Inactive Delete is retained.

## Verification and evidence

Build/typecheck and 39 focused tests: popup geometry, panes, units, model/history,
policy/process policy, observed previews, saves and conditional Delete.

`electron/test/rule-clicks-workflow.mjs` (also the pane regression entry point): labelled
synthetic unequal rates, two differently scoped rules, original-row strip after another
selection, icon/text/background, keyboard/outside/Escape, polling, narrow/detached panes,
unit/source/series identity and reconnect. No mutation calls; no renderer errors.

`electron/test/panes-real.mjs`: released isolated backend
`6c68f8cd0627bce69f15f4e995a3cf68fa161215`, binary SHA256
`7b8fbbe065001c78641eb2157b747d085a93359eab045fdffe478eb70ab83893`.
Detached setter created process incoming Allow, edited exact rule to Deny, conditional
Delete restored zero rules; GUI Quit left the daemon alive. Backend owner independently
verified generation `43be3202900fa8370b9a6761c99cc44c` and cleaned the fixture after DONE.
An earlier run failed a test locator after successful edits/cleanup; the corrected full
journey passed in `.workspace/panes-real-PLjSai/`. This is stored-policy acceptance,
not a new enforcement/receiver claim. Settled receiver/lifecycle evidence is reused.

Run: `scripts/run-electron.sh --daemon /run/flowgate-api/daemon.sock`.

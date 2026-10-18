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

## Activity compact/zone increment (base 24a5385)

| Complaint | Result | Evidence / remaining limit |
| --- | --- | --- |
| Slow popups | Fixed poll-bound readiness delay; shell renders from selected snapshot first, actions disabled during one coalesced read refresh. | Existing policy request is joined, then Activity is read after it; no new poll loop. Eight same-host automation samples: baseline shell median14.7/max18.6ms, ready median16.7/max438.4ms; fixed shell15.7/max25.9ms, ready43.4/max71.3ms. Warm readiness includes a new validation cost; these are samples, not guaranteed bounds. |
| Too much text | Partially fixed. Removed repeated stopped-firewall text; tightened popup rows and duplicate labels; technical identity remains collapsed. | Required target, direction, network/principal and consequential failures remain visible. The setter accommodates the displayed scopes. |
| Icons/mouseover | Corrected original 12px vector family glyphs, palm/check distinction, hover/pressed/focus treatment and 16px installed app icons. | Unsupported families remain inactive. |
| Proportions | Default Info45.5vw vs old38vw. | Saved pixel widths preserved; normal1280×656 and860×600 checked. Reference currently has chart closed; FlowGate's chart remains independently closeable. |
| Missing program icons | Reliable installed desktop display associations restored, including deleted/replaced image paths. | Host audit3/14 distinct observed application identities: Firefox, KRdp, KDE Connect resolved. Eleven services/runtimes had no reliable association; neutral fallbacks retained. Actual PNG loading checked in normal and detached Info. |
| “firefox (deleted)” | Friendly desktop name Firefox and clean display path; deleted-image status moved into identity details. | key/revision/executable and process binding unchanged. Icon/name describe installed desktop metadata, not proof the old running image is the replacement. |
| Local/Internet rules | Implemented authoritative zone inventories, all-program machine/current-user targets, application/process zone constraints, previews/saves and immutable-zone editing. | Released backend c0a9543. Policy is configured-prefix-v1; Internet membership is explicitly configured, not inferred connectivity. No zone traffic totals. Older daemons show unavailable controls. |
| Direction ineffective | New event metadata consumed, generation/source retained; unknown stays neutral. | Backend643b872 is implemented but real privileged BPF attachment proof remains blocked: user-namespace EPERM and initial sudo password requirement. No successful kernel-event arrows claimed. Pre-attachment established sockets and UDP remain honestly unknown where no evidence exists. |

Backend pairing: zones/metadata `c0a9543` (includes4789181), optional TCP events643b872;
backend test followups e3a5f62/464c4e7 do not change the contract. No host deployment.

Real isolated zone journey `.workspace/panes-real-71aeVT/`: machine Local incoming Block,
Internet outgoing Block, app Local incoming Allow, detached process Internet incoming Block;
exact process disable, global Block→Allow edit, advanced immutable zone, normal/narrow.
All four rules conditionally deleted; backend independently confirmed zero/stopped and
cleaned its fixture after DONE. Exact binary b4ef570eecc6f3142a29df1f63c3738beda176c7f82aea002ee2386af587242b.
Receiver semantics reuse backend evidence; GUI storage success is not a delivery claim.

Focused build/tests include zone principal/revision/expiry/receipt/permission failure,
lost-ACK reconciliation without replay, strict schema4 and exact inventory association;
labelled synthetic failure/event evidence is separate from kernel proof. Popup/pane
regression is `electron/test/rule-clicks-workflow.mjs` (zero mutation calls).

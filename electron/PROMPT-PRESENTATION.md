# Permission popup presentation acceptance

This frontend change resets each newly presented request to 520×460, preserves the current request and its controls during polling and burst arrivals, and measures rendered Remember/Details/error content for native resizing. The primary usable work-area bottom-right remains the anchor. Content scrolls when the available height is exhausted; decision controls remain reachable.

Automatic presentation has no Electron focus call, navigation focus, KWin activation, raise-and-focus, or attention request. A native shell is initialized with the application and kept mapped, transparent, minimized, and excluded from task switching between requests on KDE. Reusing that shell avoids KWin's new-Wayland-toplevel activation before its windowAdded signal. A deliberate pointer click can focus it normally. Other platforms use showInactive. No desktop configuration or persistent window rule is installed.

The handoff waits for pointer/key release, followed by an explicit 650 ms interval. Enter/Space repeats and double-click continuation are suppressed. Both native Electron and renderer gesture streams participate. New decision buttons and Remember/scope controls remain disabled until layout completes plus 650 ms. Automatic candidates with at most 1000 ms left are allowed to expire without presentation; the backend deadline is never changed. Submitted/unknown acknowledgements remain on their original request for reconciliation. Layout IPC also rejects the old request frame after retargeting.

## Compact card, For a while and ended requests

The card (`src/prompt-card.ts`, shared by the permission window and the Pending requests tab) first shows only the application, direction, remote endpoint, one protocol/local/zone line, the remaining time and the NetLimiter 5.3.28 row `Allow | Deny | ☐ Remember | ☐ For a while`. Executable, PID/start/UID, attribution, coverage, exact deadline, backend reasons (including queue retention notes), the asking rule, scope previews and revalidation diagnostics are behind one `Details` disclosure. Inline text is short; the backend's full text is under Details → Status. The decision row and the selected option's controls (Remember fields and deletion time) form a sticky dock, so they stay visible when the existing work-area cap makes the body scroll.

Remember and For a while are mutually exclusive in both directions, as observed in NetLimiter 5.3.28 (`DECISION_OPTIONS_EXCLUSIVE` in `src/process-lease.ts`). For a while appears only with `decision-for-a-while-v1`; it shows a one-line explanation and has no duration control. Allow/Deny then send `decide {scope: "for-a-while"}`. A `process_scope_unavailable` refusal decides nothing, and the request stays answerable. After the decision, the window keeps that card while its listed lease is active (unless another request is waiting) and shows `For a while: Allow · process <pid> · Out · N s left`, with lease details. The line disappears at expiry or when the lease leaves `process_leases`. The Pending requests tab lists active leases under "Temporary decisions".

An ended request keeps the ordinary card. The separate "Rule for future connections" section is removed. For a while is disabled. Allow/Deny without Remember are disabled and show "This request has ended; check Remember to save a rule for future connections". With Remember, they use `request-rule-preview`/`request-rule-save` with the selected properties and deletion time. The result reads exactly "Rule saved for future connections; this request has ended." Once a save was sent, every retry reuses that reviewed choice and token, so an unknown acknowledgement cannot create a second rule. A checked Process on an ended instance is never unchecked automatically, and saving stays unavailable until the user unchecks it.

## Verification

- Build/typecheck and all 180 existing UI unit tests passed.
- `WAYLAND_DISPLAY=wayland-1 QT_QPA_PLATFORM=wayland node electron/test/prompt-presentation.mjs` passed on a sandboxed native Wayland window, with labelled synthetic requests and a separate sandboxed typing application. Keyboard input and deliberate pointer focus used a private temporary uinput device; actual focus PID and native frame geometry were read from KWin, not inferred from Electron bounds.
- Evidence: `.workspace/connection-compact-svOe1K/placement-result.json`, `compositor.log`, `expanded-details.png`, `small.png`.
- Actual primary work area: x=2560, y=30, width=2560, height=1410. Compact/reset/collapsed: 520×460 at (4600,980). Remember with synthetic validation error: 520×652 at (4600,788). Details with long executable path: 520×936 at (4600,504).
- A compositor resize to 700×800 persisted across polling, followed by the next request resetting to 520×460. All Remember property choices and deletion times, focused selection, a 20-request equivalent burst, double-click, held/repeated Enter, and a queued expiry passed. Exactly two intended synthetic decisions were observed; the expired request never appeared.
- Constrained available-size simulation (without changing monitor configuration): the actual native window clamped to 400×400 at (4720,1040), retained the primary bottom-right anchor, and allowed scrolling to its decision controls. This exercises a smaller client work-area cap on the existing physical monitor, rather than changing the monitor's real work area.
- Existing detached-pane/hidden-main primary placement test passed in `.workspace/connection-compact-sfr183/placement-result.json`.

The final native run recorded `rememberwindowpositions` not loaded. The user disabled that external KWin script during the session; FlowGate did not change its settings. Earlier placement/focus experiments were affected by desktop restoration and concurrent focus changes, and are not the final acceptance baseline.

Existing backend/receiver acceptance is reused. No host rule, protection state, daemon lifecycle, display setting, or installed daemon was changed by this presentation work.

Launch the existing backend with:

```sh
WAYLAND_DISPLAY=wayland-1 scripts/run-electron.sh --daemon /run/flowgate-api/daemon.sock
```

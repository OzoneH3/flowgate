# Permission popup presentation acceptance

## Permission card layout

The direction banner, program and peer details, decision buttons, and rule scope controls share one window. On narrow displays the endpoint address and port stay together.

This frontend change resets each newly presented request to 520×460, preserves the current request and its controls during polling and burst arrivals, and measures rendered Remember/Details/error content for native resizing. The primary usable work-area bottom-right remains the anchor. Content scrolls when the available height is exhausted; decision controls remain reachable.

Automatic presentation has no Electron focus call, navigation focus, KWin activation, raise-and-focus, or attention request. A native shell is initialized with the application and kept mapped, transparent, minimized, and excluded from task switching between requests on KDE. Reusing that shell avoids KWin's new-Wayland-toplevel activation before its windowAdded signal. A deliberate pointer click can focus it normally. Other platforms use showInactive. No desktop configuration or persistent window rule is installed.

The handoff waits for pointer/key release, followed by an explicit 650 ms interval. Enter/Space repeats and double-click continuation are suppressed. Both native Electron and renderer gesture streams participate. New decision buttons and Remember/scope controls remain disabled until layout completes plus 650 ms. Automatic candidates with at most 1000 ms left are allowed to expire without presentation; the backend deadline is never changed. Submitted/unknown acknowledgements remain on their original request for reconciliation. Layout IPC also rejects the old request frame after retargeting.

## Compact card, For a while and ended requests

The card (`src/prompt-card.ts`, shared by the permission window and the Pending requests tab) first shows only: the application (the verified game, e.g. **Timberborn**, with the game's own icon when Activity lists it), one quiet line naming the process that actually owns the socket when it differs (e.g. `rundll32.exe`), one destination line (`To Local printing service (cupsd) · 127.0.0.1:631 · TCP`; `src/prompt-summary.ts` names a verified local peer, a remote request shows its endpoint), one short status line (countdown, `+N similar`, `limited attribution`), a small `Details` link and the NetLimiter 5.3.28 row `Allow | Deny | ☐ Remember | ☐ For a while`. The For a while duration appears only while For a while is checked; the Remember panel shows one concise label of what the rule covers before the click (`Rule for rundll32.exe in prefix …/pfx · every game using this prefix`), never a game-wide grant.

`Details` opens a separate view (`#requestMore`, `‹ Back` returns) of short labelled fields in expandable sections: Connection (direction, endpoints, protocol, zone, namespace, exact deadline), Application (executable, prefix, PID/start/UID, attribution, coverage), Launch (owner, launch, game, prefix, provenance, ancestry), Local connection (both sides with their states, peer owner and socket cookie/inode, the pair note), Rule (selected scope, Remember target, shared-with note, rule key, ONE preview without its verb, the overlap list, earlier-revision rules) and Status (backend reason, the latest result only, review message, similar requests, revalidation failure, leases). Backend paragraphs are never concatenated, both Allow and Deny previews are never rendered, and an older error is never shown after a later success.

**Local pairs.** There is no "Allow both / Deny both" and no explanation of the paired firewall hooks in the first view. When the backend has verified the exact local pair (`local-pair-v1`), a plain Allow/Deny (neither option checked) sends `decide-pair {scope: once}` for exactly that connection: the client's outgoing request and, when it exists, its incoming counterpart; otherwise the backend prepares the incoming side of that same connection only (30 s, memory only, no rule). An existing rule that decides the incoming side still decides it and is reported as a warning result. For a while and Remember keep their single-request semantics (process lease; reviewed rule for the actual helper/prefix identity).

**Click → hide.** A valid Allow/Deny click hides the permission window at once (`promptAnswered` in `src/main.ts`) and the submission continues asynchronously exactly once. Every outcome is kept in Pending requests › **Results** (`src/permission-results.ts`, newest first, 50 max): refused and unknown acknowledgements and rule conflicts are flagged and counted by a footer link until viewed; nothing is reported as success unless the backend acknowledged it. A still-pending request whose submission was refused is presented again with that result on its card. The decision row and the selected option's controls form a sticky dock, so they stay visible when the work-area cap makes the body scroll.

Remember and For a while are mutually exclusive in both directions, as observed in NetLimiter 5.3.28 (`DECISION_OPTIONS_EXCLUSIVE` in `src/process-lease.ts`). For a while appears only with `decision-for-a-while-v1`; it shows a one-line explanation (duration selector: see below). Allow/Deny then send `decide {scope: "for-a-while"}`. A `process_scope_unavailable` refusal decides nothing, and the request stays answerable. The window hides on the click like any decision; the Pending requests tab lists active leases under "Temporary decisions".

An ended request keeps the ordinary card. The separate "Rule for future connections" section is removed. For a while is enabled only while the request's exact process still runs (see below). Allow/Deny without Remember/For a while are disabled and show "Check Remember to save a rule for future connections." (or "…, or For a while for the running process."). With Remember, they use `request-rule-preview`/`request-rule-save` with the selected properties and deletion time. On a saved rule the ended request leaves Pending requests (`closedEnded` in `src/backend.ts`), the window hides, and the result ("Rule saved for future connections") is listed under Results with the rule under Rules; no ended card with another Allow/Deny row remains. Once a save was sent, every retry reuses that reviewed choice and token, so an unknown acknowledgement cannot create a second rule. A checked Process on an ended instance is never unchecked automatically, and saving stays unavailable until the user unchecks it.

## Queue reconciliation, ended-request For a while, durations

- **Reconciliation** (`queue-reconcile-v1`, `src/backend.ts` `reconcileListed`): an acknowledged Allow/Deny removes that request from the queue at once and records `(generation, id)` with the sequence number of the last `list` issued before the acknowledgement arrived. A list issued at or before that number (stale poll, reconnect read in flight) can never show it awaiting again. Only a list issued after the acknowledgement, whose `server_time` is not earlier, and that still lists it awaiting counts as a newer authoritative observation (the backend wins). Other queued requests leave only when a list reports them non-awaiting or the decide / request-rule-save / observed-rule-save response lists them in `settled`; nothing is inferred from application name or endpoint. After an unknown or rejected outcome `control.reconciling` is true and no other popup is presented, and the open card does not advance, until a list issued after the outcome has been read. The 650 ms input-release + pacing guard (`inputSettled`) is unchanged and shared by both presentation paths.
- **Ended request, process still running** (`request-for-a-while-v1`): when `request_rule.process_lease_available` is true, For a while stays enabled on the ended card. Allow/Deny then send `request-for-a-while` and create only the process lease. The result reads e.g. `For a while: Deny for process 4242 (1 min). This ended request was not delivered.` If the process exited, For a while is disabled with `The process has exited; For a while has nothing to cover.` Remember → Allow/Deny keeps using the request-rule path. The main card shows one short `This connection has ended.` (`#requestResult`); the backend's field-level reasons stay in Details (`#requestStatus`, `#revalidationDetails`).
- **Duration selector (FlowGate extension; NetLimiter's popup has no duration control)**: with `decision-for-a-while-durations-v1` the card shows `#forAWhileDuration` (15 s, 1 min, 5 min, 10 min, 30 min, 1 h; the backend's `for_a_while_durations`) and `#forAWhileExpiry` (`until 14:32` preview) inside `#forAWhileDurationWrap`, in the sticky decision row, only while For a while is checked. The default is the last choice (preference `forAWhileSeconds`, validated against the offered set, else 15 s). After the click the countdown uses the backend's returned `until`. A long lease keeps the popup card for at most 15 s; the lease stays listed under Temporary decisions. Remember stays mutually exclusive.
- **Earlier revision** (`#previousRevisionNotice`): `A rule exists for an earlier version of this application (updated executable).` when `previous_revision_rules` is non-empty. The rule ids are in its tooltip. This is display only and the rule is not applied.

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

### Destination bursts

The backend presentation group combines the same verified application key,
revision, user, direction and protocol across remote endpoints. A game or other
client contacting many servers therefore occupies one pending group. Individual
request IDs, endpoint details and deadlines remain independent. Once still
answers only the selected connection; Remember settles only requests covered by
the explicitly saved rule. Incoming/outgoing and TCP/UDP groups remain separate.
This grouping does not promise a single Once decision for an entire application.

### Short-lived requests during Remember

An explicitly checked Remember review stays on its immutable request when its
socket ends, while the backend still offers retained executable verification.
The ended request can only create a reviewed rule for future connections; it
cannot release the original flow. Unsolicited expired requests still leave the
automatic queue. Remembered saves hide only after acknowledgement; refusals and
unknown acknowledgements stay visible without automatic retries. Activity also
lists retained request identities absent from the socket census, labelled as
request evidence rather than live processes, with their captured caller details.

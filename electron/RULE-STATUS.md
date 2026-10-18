# Activity Rule Status

Follows [ACTIVITY-RULES.md](ACTIVITY-RULES.md) and [PROCESS-RULES.md](PROCESS-RULES.md).
Reference: the installed NetLimiter 5.3.28 captures (process/app quick setter, process Allow)
and the official [Activity](https://netlimiter.com/docs/user-gui-client/child-windows/activity),
[Info View](https://netlimiter.com/docs/user-gui-client/child-windows/info-view),
[Rules](https://netlimiter.com/docs/basic-concepts/rules),
[Blocker](https://netlimiter.com/docs/basic-concepts/blocker) and
[Connections](https://netlimiter.com/docs/basic-concepts/connections) pages. No new WinBoat
session was needed; earlier verified observations were reused.

## Discrepancies found in the real interaction (before → change)

| Reference | FlowGate before | Change | Dependency |
| --- | --- | --- | --- |
| Cell shows icon + action (“✓ Allow”) | Category only (“Scoped · 1”, “Mixed · 2”, “Inactive rules”); sidebar never showed Allow/Block without scrolling | Glyph + action + qualifier: “✕ Block · UDP”, “± Mixed · 1 allow, 1 block”, “○ Disabled”, “○ Inactive · ended”. Table uses compact wording | Frontend |
| Process and application rules are separate targets | Process rows showed only their own rule; a process without one read “Not set” while an app rule applied | Own status first; otherwise dimmed “↳ app fallback” from the backend’s `application_*` summary for that exact instance | Frontend |
| Popover beside the cell, two clicks | Six stacked controls, Allow/Block below the fold, an extra checkbox, then a modal repeating fields, Preview, Save (about 7 actions) | Setter opens directly below the matrix with a caret to the cell. One click on “✓ Allow UDP” runs the backend preview; inline **Draft · not saved** strip with verified target/scope/lifetime and token timer; Save is the separate acknowledgement | Frontend (existing APIs) |
| Quick setter edits the cell’s rule | Indirect “Choose a rule…” select; actions below each card | One applicable rule → that exact id/version; several → explicit one-line pick, each with “Set ✕ Block” beside it; “New separate rule…” is explicit | Frontend |
| Compact Info View | Three explanatory paragraphs between matrix and rules | One “Stored only · firewall stopped” badge in the header; precedence on group headings and in details | Frontend |
| Ask setter | — | Still absent: stored Ask ≠ FlowGate’s unmatched prompting | Backend follow-up |

Connection rows no longer repeat their holder’s status (they own no rules). Selecting a connection
shows its initiation (“This connection · Outgoing · TCP”) and highlights that column. Shared or
unidentified sockets get no “This process” tier.

## Safety properties kept

- Preview persists nothing; Save sends only the reviewed receipt. An expired token becomes
  “Review expired — nothing was saved” with an explicit **Review again**; there is no silent re-preview.
  Lost ACK → existing reconciliation (“Check save result”).
- Edits use `rule-draft {id}` + `rule-preview` with `expiry: preserve` and the listed version;
  a version mismatch is reported, not rebased. Process bindings are immutable; inactive targets
  allow Delete only. Scoped rules are never merged or widened.
- Focus: opening the setter focuses the setter group and a preview focuses the review group,
  never an action. One Enter on a cell therefore cannot trigger a change, and Save is always a
  deliberate Tab/click. Polls keep the focused control (keyed by `data-focus`) and the list scroll.
- Selection change drops an unsent draft; a save in flight or unresolved stays visible.

## Evidence

Run against exact backend 60d35a3 (`.workspace/flowgate-process`, SHA256 882556c5…), held
isolated fixture `scripts/process-rules-isolated.py --hold` (disposable namespaces, own DB).

- Real journey `electron/test/rule-status-workflow.mjs` (`FLOWGATE_TEST_READY=<fixture>/ready.json`,
  optional `FLOWGATE_EXIT_ALPHA=1`): application → alpha (one of two same-executable processes)
  → keyboard open/Escape → change its existing process rule via inline review → create a second
  process rule in one setter click → beta has no own rules and app rules keep their versions →
  beta draft token expires without saving → disable → conditional delete → 860×600 →
  alpha exit makes the session rule inactive (Delete only) → GUI exit leaves daemon generation.
- Synthetic (labelled) `process-presentation.mjs`: known outgoing connection, shared holders,
  unidentified socket, exit/draft preservation. `presentation.mjs`: multiple scoped/disabled/expired.
- Unit: `rule-chip.test.cjs` plus the existing suite (`npm test`).

Remaining differences, stated without a score: NetLimiter’s setter is a small floating overlay
with immediate action, FlowGate’s is an inline panel with a backend review step (deliberate).
NetLimiter rows are rule families (Blocker/Limit/Priority/Quota), FlowGate rows are targets
(This process / App fallback). Info View order (NetLimiter: properties before Rules), Tools set,
Windows font and icons, and Ask/weights/limits/quotas are not reproduced. No direction is known
for pre-existing host sockets until the backend observes an initiation.

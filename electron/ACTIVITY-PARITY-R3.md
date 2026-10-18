# Activity rule indicators and pane controls

## Font

The measured sizes are 12 px for body text and 15 px for titles. FlowGate keeps
`'Segoe UI', 'Noto Sans', sans-serif` and does **not** bundle a Windows font. No further fallback
guessing was done.

## Verification

- Build/typecheck; `npm test` 77/77 (new case: non-block actions never labelled Deny).
- Real popup journey `rule-status-workflow.mjs` with `FLOWGATE_EXIT_ALPHA=1` on an isolated fixture
  (released any-protocol binary): keyboard open/no cascade/Escape, one-click Allow (`protocol:"*"`),
  process Deny, sibling untouched, pill flip, checkbox disable, stale delete → conflict, popup Delete,
  860×600, alpha exit → inactive, Delete only. `.workspace/rule-status-real-mkoDhk/`.
- Pane/hover run (`.workspace/rs/panes.mjs`): 7 icons visible on hover, ▾ menu items, ✕ hides Info View,
  tab-strip ▾ restores it, chart Close/restore, persistence, popup focus on container, outside click
  closes. `.workspace/rs/r3-panes/`.
- Host read-only check: **not possible this round** — the machine rebooted during the round and the
  host daemon (`/run/flowgate-api`) was absent afterwards. Previous rounds' host evidence stands;
  rollout is the backend owner's.

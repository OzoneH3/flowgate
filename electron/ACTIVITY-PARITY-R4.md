# Activity presentation and typography

## Typography

FlowGate now bundles **Selawik** (Microsoft, SIL OFL 1.1,
`assets/fonts/LICENSE-Selawik-OFL.txt`), Microsoft's metric-compatible open alternative, and keeps
`'Segoe UI'` first so an installed Segoe UI wins.

## Verification

- Build/typecheck; `npm test` 77/77; synthetic `process-presentation.mjs` and `presentation.mjs` pass.
- Real popup journey `rule-status-workflow.mjs` on isolated fixture rsf-c779 (released any-protocol
  binary) PASS (`.workspace/rule-status-real-T8YDJk/`): keyboard open/no cascade/Escape, one-click Allow
  (`protocol:"*"`), process Deny, sibling untouched, pill flip, checkbox disable, stale delete →
  conflict, popup Delete, 860×600.
- Pane/layout run (`.workspace/rs/panes.mjs` → `.workspace/rs/r3-panes/result.json`): layout preset
  Activity-only hides Info View, Default hides chart, Default-with-Chart restores; Window menu lists
  both panes; Rate→Total relabels headers; Status shows 5 header cells (4 + filler), Details 13; chart
  menu lists Source/Window items and switching to 5 min updates the hidden select; pause toggles
  `aria-pressed`; popup focus stays on the container; outside click closes.
- Populated chart: real unprivileged TCP observer run `graphs.mjs` (`.workspace/gr-*/real-tcp-application.png`).
- Host read-only check: not possible (host daemon absent after the reboots); nothing was started.

## Verified follow-up: bundled font loading

The original R4 bundle copied Selawik correctly, but the asset protocol omitted the font files.
Consequently the original R4 running screenshots used a later installed fallback; CSS family names
and width probes alone did not establish successful font use. The fixed protocol now allows exactly
three bundled font paths with `font/ttf`, retaining CSP, sandbox and the OFL attribution.

Actual sandboxed Wayland verification on unchanged isolated rsf-c780:
`document.fonts.load` for 400/600/700 failed with NetworkError before the fix and succeeded afterward.
Evidence: UI `.workspace/round5/{before.json,font.json,before-normal.png,font-normal.png}`.
Build/typecheck and two static asset allowlist tests pass. The read-only 01e3 follow-up pane run also
passed presets, Rate/Total, Status/Details, source/window menu, pause → selection → resume, and
outside popup dismissal; no fixture rules or host state changed.

# Activity presentation

## Verification and limits

- Build/typecheck passed; 18 focused model, policy, icon and editor tests passed.
- `test/activity-measured.mjs` runs actual sandboxed Wayland with disposable Unix
  fixture endpoints. It checks the measured dimensions, descending-first numeric
  sorting/toggle, keyboard selection and policy entry, IPv6 search, one Unidentified
  group, installed/fallback icons, horizontal overflow, scroll across polling,
  keyboard sidebar sizing and pointer column resizing.
- Normal/narrow populated, filtered-empty, empty, long-path, policy panel and graph
  views inspected. Editor IPv6 input, focus and text selection survive polling;
  pending prompt controls remain readable and disabled when decisions are forbidden.
- Existing backend/evaluation/UDP/rule-mutation evidence is reused. No new real
  traffic or decision acceptance is claimed. No host endpoints were touched.

The chart is tall enough to retain source selection,
missing/partial measurement status and history semantics. FlowGate has separate
In/Out policy columns instead of NetLimiter's multi-feature Rule Status strip,
a status footer, and different Linux font metrics. At narrow width, horizontal
scrolling exposes later columns; policy remains accessible in the sidebar.
Unsupported limiter/priority/quota controls are absent. Real NetLimiter Ask prompt
behavior and exact font remain unverified.

Reproduce after `npm --prefix electron run build`:

```sh
WAYLAND_DISPLAY=wayland-0 node electron/test/activity-measured.mjs
```

The runner restores frontend preferences and closes only its own app/fixture servers.
Use `FLOWGATE_VISUAL_EVIDENCE=/absolute/project/.workspace/evidence` to choose a
capture directory. Normal launch from this worktree: `scripts/run-electron.sh`.

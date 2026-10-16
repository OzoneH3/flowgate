# Desktop presentation

The Qt interface presents an application, process and socket tree, a details pane, and a non-modal permission prompt.

## Truthful differences and remaining visual work

The initial layout has the following limits.

- Actual socket fields replace unavailable transfer-rate and priority columns.
  No rates, totals, domains, geographical flags or application icons are invented.
- The chart region explicitly says rates are not measured; it has no fake axes or
  plotted values. Read-only Rules explains that no rule is applied, with no inert
  imitation editor controls.
- FlowGate exposes only implemented Activity and pending/recent-decision tabs.
  It does not reproduce unsupported rules, quotas, priorities or scheduler tabs.
- The prompt still uses selectable plain-text connection details rather than the
  reference's full field layout. Its controls retain explicit Once and one-hour
  in-memory scope semantics, not unsupported duration toggles.
- The backend socket selector is visible. The main menu has only working local
  actions. Linux window decorations and fonts may differ from the reference.
- Narrow displays require horizontal tree scrolling. PID column width and the
  relative placement of socket counts deserve the next refinement pass.
- Pending permission controls could be stacked more compactly in a narrow right
  sidebar. Exact typography, spacing and chart proportions remain to be matched.

## Evidence

The presentation build passed the actual Wayland monitor Qt test (4/4), covering
live fixture activity, grouping, stable selection/sorting, search, filters, copy,
process exit and observer reconnect. Its screenshot was inspected:

- `.workspace/design-monitor.log`
- `.workspace/monitor-ui-1076703/host-monitor.png`

These evidence paths are in the main repository workspace. The design binary was
built in the separate presentation worktree; that worktree was subsequently moved
from `netlimiter5` to `netlimiter-design` during coordination. Reconfigure CMake
before rebuilding it, since its generated cache contains the original path.

Root integration owns the final button-to-API lab regression. The design stream
has not rerun the accepted native/Wine enforcement matrices.

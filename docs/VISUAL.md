# Desktop presentation

The Qt interface presents an application, process and socket tree, a details pane, and a non-modal permission prompt.

## Truthful differences and remaining visual work

The initial layout has the following limits.

- Actual socket fields replace unavailable transfer-rate and priority columns.
  No rates, totals, domains, geographical flags or application icons are invented.
- The chart region explains TCP table metrics and unavailable UDP/chart history; it has no fake axes or
  plotted values. Read-only Rules explains that no rule is applied, with no inert
  imitation editor controls.
- FlowGate exposes only implemented Activity and pending/recent-decision tabs.
  It does not reproduce unsupported rules, quotas, priorities or scheduler tabs.
- The prompt now uses structured selectable fields and actual Once/one-hour/
  persistent scopes. Create/Edit opens a functional compact Qt rule editor with
  authoritative scope preview; it does not reproduce every reference control.
- The backend socket selector is visible. The main menu has only working local
  actions. Linux window decorations and fonts may differ from the reference.
- Narrow displays require horizontal tree scrolling for endpoint/state columns.
  PID width accommodates seven digits, and socket counts appear beside PID;
  logical column indices and sorting semantics are preserved.
- The sidebar scope selector sits above Allow/Block to fit narrow windows.
  Exact typography and the main Info plain-text detail layout still differ.

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

## Refinement verification (session 01a1465b)

Started from verified, clean handoff `77286d286faa169a81f455426dac933ee13a8b81`
on `frontend/netlimiter-design`. Rebuilt with CMake in the worktree's
`.workspace/build-netlimiter-design`. No API, backend, test source or scripts
changed. Existing Qt object names, column indices, scope values and actions are
preserved. There are no new backend integration dependencies.

FlowGate uses an explicit dark content palette.

Evidence below is relative to the **main repository**, not this worktree:

- `.workspace/design-refine-monitor.log`: Wayland monitor suite, 4/4 passed.
- `.workspace/monitor-ui-1084117/host-monitor.png`: main window at 1040×740,
  showing real loopback fixture processes through the actual read-only observer.
  Seven-digit PIDs, counts, IPv6 rows, focus and selection are visible. This is
  controlled live fixture traffic, not invented rates or process identities.
- `.workspace/design-refine-desktop-final.log`: Wayland decision suite, 8/8
  passed, including actual isolated UDP Allow, keyboard Block, remember, expiry,
  stale rejection, read-only mode, reconnect, and metadata/error coverage.
- `.workspace/design-refine-prompt.log`: final prompt-height adjustment smoke,
  3/3 passed (init, close/disconnect, cleanup).
- `.workspace/desktop-test-1086564/prompt.png`: final 600×650 prompt, actual
  pending isolated-lab UDP request with visible expiry and decision controls.
- `.workspace/design-refine-small.log`: focused presentation checks, 3/3 passed.
- `.workspace/desktop-test-1085999/long-ipv6.png`: 860×600 **synthetic metadata
  fixture**, explicitly covering long executable paths and IPv6, not real
  attribution or IPv6 enforcement evidence.
- `.workspace/design-real-launch-joqsq61s/launch.log`: actual standalone desktop
  executable launched on Wayland with a private read-only observer; both stayed
  running until orderly cleanup.

All
controls remain accessible at the checked sizes; long tables scroll horizontally
and long details scroll vertically. No host firewall/network configuration was
changed. Rates, chart series, persistent rules, quotas, priorities, geo/domain
metadata and unsupported reference editor features remain unavailable and are not
simulated. The integration agent owns final merge and backend validation.

## Integration verification

Both complete design commits were cherry-picked into milestone/backend without conflicts after backend hardening. Rebuilt native program passed one focused actual Wayland Activity smoke (3/3) and isolated prompt Allow-to-receiver smoke (3/3). Evidence: `.workspace/monitor-integration-build.log`, `.workspace/monitor-integration-smoke.log`, and `.workspace/host-monitor.png`. The integrated screenshot was inspected. Broader design suites above were reused, with no Wine retest or host enforcement.

## Structured prompt/editor increment

Actual Wayland real-traffic captures: `.workspace/outgoing-ui-1188339/`
(`outgoing-real-prompt.png`, `outgoing-real-editor.png`, `incoming-real-prompt.png`).
`synthetic-ipv6-long-path.png` is a presentation fixture, not IPv6 receiver evidence
(the isolated receiver suite separately covers IPv6). Values are selectable,
elided with full tooltips/copy; narrow editor content scrolls. Main Info remains
plain text, icons generic, typography/proportions approximate. No pixel identity
is claimed. The layout remains the integrated NetLimiter-style desktop.

## Traffic column increment

Activity preserves the dense tree/right Info layout. Four functional TCP traffic
columns now appear beside identity/socket count; endpoint columns remain reachable
by horizontal scrolling at narrow widths. Numeric units and `*` partial coverage
replace unavailable values truthfully; UDP remains `—`. No chart history or rates
are fabricated. One collapsible Unidentified group is presentation only.

Actual Wayland captures for this increment: `.workspace/traffic-ui-1485300/real-traffic.png`
(1500×850) and `real-traffic-narrow.png` (860×600), real unprivileged loopback
traffic, not fabricated presentation rates. The Qt regrouping fixture is separately
labelled synthetic in `.workspace/traffic-ui-final.log`.

## UDP experiment

Activity adds explicit extended-monitoring Enable/Stop controls without changing
the tree layout. UDP source health is independent of enforcement. UDP API bytes
are labelled separately; incompatible aggregates show Mixed sources. The earlier
Wayland capture (directory in `.workspace/udp-wayland-final.log`) shows real UDP
datagrams with counters unavailable before authenticated BPF validation. That
capture is not measured-rate evidence; the mixed-source UI fixture is synthetic.
The measured capture below supersedes this historical limitation.

## Verified measured UDP capture

`.workspace/udp-verified-o2oghdyo/udp-measured-wayland.png` and
`udp-measured-narrow.png` show real kernel-backed IPv4/IPv6 UDP fixture rates and
observed totals in an actual unprivileged Wayland window (3/3). Shared sockets
remain once under Unidentified. Partial markers reflect the deliberate
pre-registration miss; registered steady transfers had zero additional misses.
These replace the earlier unavailable-state capture as UDP-rate evidence.

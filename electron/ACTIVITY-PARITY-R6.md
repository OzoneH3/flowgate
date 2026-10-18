# Activity panes and chart navigation, round 6

Base: `7760c3568895eec25ceb36222ebcbdfc00ec09fe`. Real isolated backend:
`6c68f8cd0627bce69f15f4e995a3cf68fa161215`, binary SHA256
`7b8fbbe065001c78641eb2157b747d085a93359eab045fdffe478eb70ab83893`.

## Delivered

Info View and Traffic Chart genuinely undock into separate sandboxed windows. One main
backend connection, selection, units, accounting source and bounded history feed all panes.
At most one window exists per pane. Dock returns it to Activity; closing hides it; Window
reopens it. Main hide/show includes detached panes. Quit closes GUI windows only. Saved
geometry is clamped into available displays. Pane preload has no mutation operations:
rule entry focuses the existing main editor/setter, preserving its draft and safeguards.

Chart supports retained-history pan, wheel/right-drag/button zoom, series visibility,
previous/next actual observations, keyboard navigation and Return live. Pause freezes
presentation, never collection. Observation spacing is not a claim of an exact one-second
measurement. Source/generation/missing-data gaps remain gaps. Small positive fixed-unit
values no longer round to a false zero.

Double-click expands/collapses parent rows; a connection opens Info View. A green dot
means an observed connected TCP/UDP peer, not a rule, protection or successful delivery.
Listeners, unconnected UDP and unknown states are neutral.

## Evidence and checks

Evidence is local, deliberately uncommitted media:

- `.workspace/panes-real-brlu3b/`: real isolated process-rule creation from detached Info,
  authoritative update, exact conditional Delete, restored zero rules, main Quit and unchanged
  daemon generation. Normal/narrow and dock/close/reopen checked.
- `.workspace/panes-synthetic-iyVWfo/`: labelled deterministic history, disconnect/reconnect,
  shared selection/units/source, pause/navigation, keyboard/double-click, hide/reopen;
  zero mutation calls. These synthetic samples are not kernel evidence.
- `.workspace/gr-bIO32u/`: bounded real TCP traffic, table/graph agreement, shared sockets
  counted once, actual detached Info/chart and normal/narrow rendering.

Build/typecheck and focused panes, assets, model, units and history tests pass. Existing
receiver/process-rule/UDP acceptance is reused. No host lifecycle or rules were changed.

## Pinned network rows

Internet and Local Network stay first beneath All applications, unaffected by sorting.
They are non-policy overview selections. Measurements are explicitly unavailable, never
zero or a bucket for unknown sockets. Backend coordination rejected public/private-IP
guessing: genuine zone totals need explicit configured zone membership, freshness and
TCP/UDP baseline attribution (UDP counters may span peers). That is a separate agreed
proposal, not an implemented capability. Final synthetic pane/navigation run:
`.workspace/panes-synthetic-2O3JKN/` (zero mutations, no renderer errors).

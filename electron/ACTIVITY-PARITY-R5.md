# Activity display units and chart controls

Base **4422cfad7da87127bfb56838b68fe3e43a752b3f**, including the font-serving correction
652dab3 and accepted 01e3 review fixes. Compatible backend **6c68f8cd0627bce69f15f4e995a3cf68fa161215**
(any-protocol/process rules), unchanged API; no new backend capability was required.

## Evidence and focused verification

Local images in main `.workspace/netlimiter-reference/rule-status-r5/`:

- `05-process-popup.png`: real process rule, application fallback and open setter.
- `06-real-tcp-chart.png`: real bounded TCP fixture, Mbit display, source-separated totals/rates.
- `07-narrow.png`:860×600, horizontal scrolling preserves columns and policy access.

Original FlowGate before: UI `.workspace/round5/before-{normal,narrow}.png`; after no-rule comparison:
UI `.workspace/round5-journey-qjNaon/`. Real rule journey: `.workspace/round5-journey-yNI5mm/`.
Its original fixture-label metadata was stale; `metadata-correction.txt` explains the two actual
isolated mutations (not host data). Raw screenshots and original result remain preserved.

- Build/typecheck and18focused asset/unit/history/model checks pass, including fractional rates,
  missing≠zero, raw numeric sorting, source separation, restart gaps, timestamp jumps and memory bounds.
- Sandboxed Wayland real isolated rsf-c780 journey passed: File/Tools/Window/Help; all font weights;
  Units persisted without source change; rate first click descending; Rate/Total;10min menu;
  pause→process selection→resume; popup keyboard dismissal; sample keyboard details; normal/narrow;
  no page errors. Two UI rules (app In Allow, process Out Block) acknowledged, shown together, then
  exact conditional Delete restored authoritative0rules. Backend owner cleaned fixture after DONE.
- Real TCP graph presentation `.workspace/gr-RBo9Jd/`: socket and application plots agree with
  backend rates/unique-socket sums; shared sockets once. All owned TCP fixture/observer/UI processes
  cleaned. Reuses prior receiver/process/expiry/UDP evidence; no enforcement matrix rerun.
- Preferences restored byte-for-byte after fixtures. WinBoat autoByte/Rate/root selection restored;
  no theme/rule/global setting changed; viewer closed. Host daemon absent after reboot: no host
  launch, restore, collection, rule, networking or enforcement operation.

## Remaining exact work

- **Frontend:** real Undock remains absent. It needs typed pane open/dock IPC, one main-owned
  selection/source/unit state, shared existing Backend/TrafficHistory, one editor/mutation owner,
  bounded on-screen placement and close/re-dock tests. Reusing the full renderer would create
  independent selections/editors; this increment deliberately adds no inert Undock menu.
- **Frontend:** reference drag pan/zoom, stream visibility toggles and previous/next1s app-detail
  navigation remain different. Current sample detail reports observed backend rates with timestamp,
  not NetLimiter's one-second per-application byte inventory. No fabricated historical membership.
- **Backend:** stored Ask remains explicitly deferred by owner; no new capability. Limiter, priority,
  quota, persistent stats and reusable filters remain separate scoped proposals, not active controls.
- **Platform/data:** Windows service/version/product metadata and icon inventory differ. Actual Linux
  installed icons and neutral fallbacks retained. Selawik/Linux rasterization is not Segoe/ClearType.
- Monitoring/firewall status is text plus explicit review, rather than an interception checkbox.
  Unknown counters stay unavailable; no visual zero substitution.

## Minimal integration

```sh
npm --prefix electron run build
node --test electron/test/{assets,display-units,history,model}.test.cjs
# Optional fresh, disposable held fixture owned exclusively by this runner:
FLOWGATE_TEST_READY=/absolute/project/.workspace/FIXTURE/ready.json \
FLOWGATE_TEST_MUTATIONS=1 node electron/test/activity-round5.mjs
```

The mutation flag requires an initially empty disposable fixture and deletes only the two acknowledged
rules using their exact versions. No new fixture/matrix is needed just to integrate this release.
Ordinary launch: `scripts/run-electron.sh --daemon /run/flowgate-api/daemon.sock` **when an independently
running endpoint exists**; this task does not restore one. Isolated equivalent:
`scripts/run-electron.sh --observer /absolute/FIXTURE/api/control.sock.monitor --control /absolute/FIXTURE/api/control.sock`.

A deliberate default remains60s (a new client has no ten-minute backfill);10min is selectable and
unobserved intervals stay empty. Reference multi-application1s detail and service-retained history
would need a separately scoped backend history proposal before imitation.

Concurrent crash monitoring stayed read-only: one Firefox/libxul fault at18:42:29CEST during the
WinBoat viewer session, no recorded OOM/GPU reset. Prior zero-Electron baseline also had faults;
causation remains unresolved. No Firefox restart/profile/tab changes. Local timeline:
UI `.workspace/round5/monitor-summary.json`; Electron journeys had no renderer page errors.

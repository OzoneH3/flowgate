# Permission window placement — real-launch follow-up

Base: master `04c51590ff18086031f61abd9a1b0a7439c09538`. This increment changes only
permission-window startup placement and its tests. No policy or host operations.

## Demonstrated problem

The user confirmed **wrong monitor, followed by a visible jump**. Normal launch
showed/focused the permission window using Electron's primary display, then installed
a delayed KDE script. Wayland ignores requested global coordinates. The old script
logged `frameGeometry` immediately after requesting an asynchronous configure, so
“PLACED” did not establish settled geometry. The retained real-host journal includes
an initial1280×848 frame and a later520×460 frame; there is no retained final screenshot
proving the initial frame persisted. KDE's window-position restoration script is
installed and restores other FlowGate windows; its configuration was not changed.

Current inspected KDE configuration: DP-2 priority1, DP-3 priority2, both scale1,
2560×1440. DP-2 usable logical area `(2560,30,2560,1410)`. These names/coordinates
are evidence, **not application constants**. No Electron was running when inspection
began. Actual reported launch used normal `scripts/run-electron.sh --daemon ...`,
not a special test placement path; no persisted permission bounds or zoom are read.

## Fix

Install an owned, temporary compositor hook **before mapping** the prompt. Match
this Electron PID plus the fixed numeric permission-window caption, then bind its
native internal ID. Hold it invisible during initial output/geometry settlement;
use current KDE priority and compositor usable area, request520×460 logical pixels
(clamped to the area), and reveal/focus only after three matching native samples.
One bounded correction handles late initial restoration/configure. There is no
poll-driven placement or recurring focus activation. Prompt minimum constraints
allow fitting smaller work areas; long content remains scrollable.

The startup handshake times out rather than retaining a hidden window indefinitely.
If KDE discovery is unavailable, the first compositor output is the deterministic
fallback; if compositor scripting is unavailable, Electron's work area is used and
the limitation is logged. No renderer receives command execution. Declarative
scripts are explicitly stopped **and** unloaded, with owned files removed: unloading
alone left a DBus object which could intercept a later reused script ID during the
repeated-arrival diagnostic. No user compositor script/rule was removed.

## Verification and evidence

Build/typecheck,14 focused placement/queue/observed-rule checks and syntax/diff checks
pass. Native Wayland and sandboxing remain enabled.

- **Normal launcher**, labelled synthetic pending requests, no decisions:
  main-repository `.workspace/placement-host/normal.log`,
  `compositor-confirmed.log`, `outputs.json`, `normal-after.png`.
  Current compositor confirms DP-2 `(4600,980,520,460)`, not merely requested bounds.
- **Controlled actual compositor journey**, synthetic pending requests:
  UI-worktree `.workspace/connection-compact-GqVQiY/placement-result.json`,
  `compositor.log`, `hidden-main-detached-info.png`, `second-arrival.png`, `small400.png`.
  Activity moved to secondary output, detached Info open, Activity hidden; two
  successive independent prompts target KDE primary with zoom1, no parent, stable
  geometry across polls. First native mapping on secondary was held at opacity0;
  confirmed primary frame has opacity1.400×400 test keeps Allow visible. Zero mutation
  requests. Native monitor scaling was1; no global scale/monitor layout was changed.
- `.workspace/connection-compact-XV7B1m/`: existing focus/expiry/disconnect/Enter
  presentation check passed. Small-area geometry is also covered deterministically.
- Early diagnostic attempts are not passing journeys: the QML import was corrected;
  a native-query script collision exposed the stop/unload cleanup issue above.

Own test windows/processes/sockets and temporary compositor scripts were closed;
only the original compositor Script0/1/2 remain. Final journey restores its preference
file; main-checkout user preferences and host firewall state were untouched. Actual
receiver/decision semantics are unchanged and their accepted evidence is reused.

## Reported systemd-labelled Allow failure

Main `.workspace/electron-run-1un1gbv7/electron.log` identifies **Activity
`rule:preview` → `stale_target: process generation, executable, principal or namespace
changed/unsupported`**, not a pending Decide or saved-rule acknowledgement failure.
Existing quick-setter error presentation retains that exact backend error and
“Nothing was saved”; no retry or identity/scope widening was added. Backend owner
received the evidence and separately fixed private-mount namespace verification.
The exact historical process/PID remains unconfirmed pending privileged read-only
export; this document does not identify a particular system service by guess.

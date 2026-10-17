# FlowGate Electron milestone

An additional unprivileged frontend; Qt and `scripts/run-desktop.sh` remain intact.
Vanilla TypeScript, CSS and Electron, built by esbuild. No web development server,
remote assets, frontend rule matching or packaging. Explicit controls delegate privileged work to the existing terminal bridges.

## Run

From the repository/worktree root:

```sh
scripts/run-electron.sh
scripts/run-electron.sh --control /absolute/private/control.sock
scripts/run-electron.sh --observer /absolute/private/observer.sock --control /absolute/private/control.sock
scripts/run-electron.sh --width 860 --height 600
```

The launcher installs **repository-local locked npm dependencies**, downloads the
pinned Electron binary with its package checksums, builds production assets and the
Go observer, then launches Electron. Requires Node >=22.12, npm, Python 3, the
repository's Go toolchain and existing desktop libraries. No system installation
is performed. Node 26.11.1/npm 12.2.0/Electron 44.9.0 were used here. Electron's
sandbox must work; there is no `--no-sandbox` fallback.

Default startup creates a private mode-0700 `.workspace/electron-run-*` directory
and starts only its own read-only observer. Its observer stops when Electron quits
or the launcher receives Ctrl+C. `--observer` reuses an existing observer and leaves
it running. `--control` attaches to an existing authenticated Go API. Merely launching or closing Electron never starts, stops, or recovers its controller. Evaluation buttons require an explicit user action. Independent controllers/collectors
survive client exit. Each launcher owns only its own children and socket. Logs and
Electron profile/cache directories remain under `.workspace` for inspection.

For already-built **production** assets without rebuilding:

```sh
scripts/build-electron.sh
XDG_CACHE_HOME="$PWD/.workspace/cache" TMPDIR="$PWD/.workspace/tmp" python3 electron/launch.py
```

`--interval 1s` configures an owned observer; accepted backend range is 500ms–30s.
No startup enables host enforcement or privileged UDP collection. Fullscreen or
inactive applications receive no automatic permission window: pending requests appear in the
main window and bounded native notifications request review. **Open permission window**
and notification activation are explicit user actions. Closing
that window or choosing **Decide later** sends no verdict.

## Boundaries and backend semantics

- `main.ts` owns the Unix sockets indirectly through `backend.ts`. A separate
  serial poll loop serves Activity and control. Losing one does not stop the other.
- The renderer is sandboxed with context isolation, no Node integration and no
  webview. `preload.ts` exposes snapshot/subscription, decisions, rule drafts/previews/mutations, bounded preferences, and fixed evaluation/extended-monitoring operations. Sender WebContents, main frame and local origin
  are validated for every invoke; decision payloads have exact allowed keys and
  enum values. No generic filesystem, shell, socket or IPC capability is exposed.
- Only three local assets are served by the custom `flowgate://app` protocol.
  Production CSP blocks connections, frames, objects, inline scripts and remote
  assets. Navigation, new windows and permissions are denied. Diagnostic names,
  paths, addresses and metadata are inserted using text nodes/textContent.
- Authenticated API v1 `list`, `decide`, `rule-preview`, `rule-save` and capability-gated `rule-delete` are used. Go peer credentials and
  socket permissions are unchanged. Snapshots are bounded to 4 MiB, validated and
  projected into typed fields before reaching the renderer.
- Backend generations, deadlines and read-only authorization gate every decision.
  Deadline countdowns advance from backend time using a monotonic clock. Only
  backend-offered `once`, `application` and `persistent` scopes are shown, with
  the **exact supplied preview**, including memory/disk and expiry semantics.
- Repeated clicks cannot send multiple operations. A submitted request stays
  locked for that event, with acknowledgement or rejection shown; ambiguous
  results stay locked as well. Reconnect only polls authoritative state and never replays decisions.
  Resolution by another client disables the request on the next poll. A backend
  acknowledgement confirms permission, not delivery through other firewalls.
- Activity uses backend socket IDs, application key/revision and PID/start IDs.
  Selection and expansion survive refresh and real owner reassociation. One
  initially collapsed Unidentified group contains unresolved/mixed-application shared sockets, each
  counted once. Groups aggregate only their visible unique sockets; no ownership
  attribution is inferred from names, ports or labels.
- Rates/totals follow [TRAFFIC.md](../docs/TRAFFIC.md) and [UDP.md](../docs/UDP.md).
  Unavailable is `—`, partial is `*`, and incompatible byte definitions show
  **Mixed sources** rather than a sum. Totals are observed intervals, not lifetime
  traffic or historical process ownership. Observer loss clears all stale rates.
  UDP availability is consumed from the actual backend; this frontend does not
  claim any new UDP kernel verification or activate a collector.

Security design follows the [Electron security guidance](https://www.electronjs.org/docs/latest/tutorial/security).
FlowGate uses installed application icons when attribution is available and neutral fallbacks otherwise.

## Focused verification

```sh
scripts/check-electron.sh
```

This builds native fixtures, runs focused synthetic model/transport checks,
then launches actual sandboxed Electron on the existing KDE/Wayland session.
It uses the read-only observer with real TCP loopback fixtures, and the existing
`scripts/lab.sh`/`desktop-lab.py` disposable namespace for firewall checks. Its supervisor receives an explicit quit, with an owned process-group fallback
for failed startup; test-owned processes exit before completion. It does
not run host enforcement, UDP collector or Wine/Proton matrices. Test-only CDP
binds to loopback and is supplied by the external test runner; the production
launcher enables no debugger or TCP control service.

Verified on base `86ce7e4163ef31afae15889babb475f1a110ae4f`:

- Real TCP grouping/endpoints, 262144 uploaded / 131072 downloaded bytes on a
  socket, positive measured rates, numeric sorting, search/filter and selection.
- Real non-dumpable fixture enters Unidentified; restoring visibility retains
  selected socket ID and moves it beneath its process. Observer loss clears rows
  and reconnect resets the observed baseline without stale rates.
- Electron prompt Allow delivers a retained UDP datagram to the actual receiver;
  Block prevents delivery. One-hour remembered scope admits a new source-port
  attempt using the backend's existing scope. Expiry/stale calls, read-only API,
  external-client resolution and controller disconnect cannot grant accidentally.
- Real controller loss leaves Activity connected. Unchanged details retain text selection through polling. No renderer exceptions. Normal
  1280×820 and narrow 860×600 windows captured and visually inspected. Horizontal
  scrolling exposes the endpoint/state columns; prompt fields wrap.
- Separate production-launcher checks passed both owned-observer cleanup and
  independently owned observer survival after the real GUI exits.
- Synthetic-only tests cover mixed-source/shared duplicate aggregation, numeric
  sorting and partial measurements, ambiguous acknowledgements, opposing repeated
  decisions and changed-generation acknowledgements. These are **not enforcement
  evidence**. Actual graphical Qt-to-Electron cross-client clicking and live host
  control were not tested; the external-client test uses the same authenticated API.

Evidence (relative to this worktree, all uncommitted runtime artifacts):

- `.workspace/electron-acceptance-final.log` — complete passing real-backend run.
- `.workspace/el-check-DrlXgE/electron-activity.png` — real controlled TCP traffic.
- `.workspace/el-check-DrlXgE/electron-prompt.png` — real isolated UDP request.
- `.workspace/el-check-DrlXgE/electron-main.png` — Activity after controller loss.
- `.workspace/el-check-DrlXgE/electron-narrow.png` — actual 860×600 Electron window.
- `.workspace/el-check-DrlXgE/resources.json` — idle Electron process tree sample:
  **986200 KiB summed RSS (~963 MiB)**; **0.05 CPU seconds over 2.5 seconds**
  (~2.0% of one CPU), eight processes. Summed RSS double-counts shared mappings;
  this includes the Electron GPU/utility/renderer processes, excludes the observer
  and test driver, and is a brief sample with the test debugger attached.
- `.workspace/electron-launch-check.log` and `.workspace/el-launch-4lo5jko4/` —
  production launcher cleanup evidence.

## Rules, evaluation and extended monitoring increment

Based on integration `a48ee2be1a54d0fa2d5304dab668f11e61d3d128`, rebased from
frontend starting snapshot `8cd82a08bf04ba76a3e3e5b0baf97538068ed7bc`.
Backend/Qt/collector/shared bridge implementations are unchanged.

### Workflows

- **Rules** lists backend-saved policies. Select **Edit**, **Enable / Disable…**,
  or **Delete…**. **Create rule…** is available on an attributable pending request
  in the main window. Go must support durable editing (host-enforcement mode).
- The modeless editor preserves application/revision/UID/direction and absolute
  expiry. Resetting expiry to one hour or removing it is explicit; enabling an
  expired rule leaves it expired. Legacy exact endpoints are converted without
  broadening their scope. All matching, validation and precedence remain in Go.
- **Preview** gets the exact backend scope. Any field change invalidates the
  preview. Save uses a single-use main-process receipt tied to the generation,
  original version and immutable identity. Failed saves retain fields. A conflict
  requires **Reload version, keep fields**, review and a fresh preview. Ambiguous
  acknowledgements lock the editor; inspect the authoritative Rules list before
  opening another draft. No mutation is automatically replayed after reconnect.
- Enable/Disable uses versioned preview/save. Delete uses atomic `rule-delete`
  with the generation, rule ID and version frozen in the displayed confirmation.
  Backend capability `conditional-rule-delete-v1` is required; without it Delete
  is disabled with a compatibility explanation. There is no unconditional fallback.
  Changing rules may leave already-approved TCP sessions alive.
- **Minimize / Resume editor** retains unfinished input while requests are handled.
  Ctrl+1/2/3 selects Activity/requests/Rules; Ctrl+E opens the selected (or first)
  rule; Ctrl+P opens the selected request. Escape minimizes the editor.
- **Start 5-minute evaluation…** explains the effect before opening Konsole and
  the unchanged `scripts/desktop-control.py`. Choose incoming-only or both
  directions. Only the terminal handles sudo; Electron remains unprivileged.
  Readiness must match the authenticated backend generation. Countdown uses backend
  time. **Stop**, **Cancel authentication**, **Status** and **Recovery…** reuse the
  same lifecycle. Controller loss is unknown, and only an acknowledged cleanup
  is described as stopped. Detached controllers retain their original deadline
  across frontend exit; Activity polling continues independently.
- **Enable extended monitoring…** is separately opt-in and invokes only the
  unchanged `scripts/traffic-control.py`. Build its optional helper first with
  `scripts/build-udp.sh` (existing build prerequisites required). **Stop extended
  monitoring** invokes fixed `.workspace/flowgate udp-stop`; Go authenticates the
  privileged collector and its acknowledgement. Neither operation starts/stops
  firewall evaluation. Closing Electron leaves independently owned collectors alone.
  Authentication cancellation/refusal is inspected in the held terminal; observer
  availability remains authoritative. Missing helpers produce a clear error.
- UDP status/missed-operation indicators come from the observer. Socket totals
  cover all peers; API-reported UDP bytes remain separate from TCP transport bytes.
  Partial coverage never becomes fabricated missing-byte estimates. See the updated
  [UDP](../docs/UDP.md) and [traffic](../docs/TRAFFIC.md) documentation.
- Drag the information-panel divider or use its left/right arrow keys. Drag Activity
  column edges to resize. Widths and main-window size persist in the local
  `.workspace/electron-preferences.json`; Wayland controls screen placement.
  Editor/detail DOM remains stable during unchanged polling.

### Focused verification

```sh
scripts/check-electron-workflows.sh
```

Actual sandboxed Electron on KDE/Wayland, real Go host-session API and disposable
user/network namespaces; **terminal authentication is simulated**, not real sudo.
The private harness uses a 120-second deadline to bound tests; production bridge
arguments remain five minutes. No host enforcement or privileged UDP collection.

Passing real-backend checks: create Allow releases retained UDP to the receiver;
edit Block prevents a new delivery; Enable/Disable preserve expiry; Delete removes
policy; stale save rejects without losing fields; invalid preview retains input;
read-only and disconnected clients cannot mutate; selected both profile reaches
Go; Stop confirms cleanup while Activity continues; refusal/cancellation preserves
monitoring; controller loss reports unknown; closing Electron preserves the
controller and its exact original deadline. Prior Activity/prompt evidence above
is reused; no UDP kernel or Wine/Proton matrix was rerun.

Nine synthetic unit checks include ambiguous-save single-use receipts, unchanged
expired-rule expiry/identity, fixed extended-monitoring subprocess arguments,
failed Stop acknowledgement, mixed-source sums and partial metrics. An explicitly
labelled **synthetic UDP UI fixture** checks active/partial/disconnected states.
These are not kernel or enforcement evidence. Existing real UDP evidence remains
integration `.workspace/udp-verified-o2oghdyo` and docs/UDP.md at a48ee2b.

Artifacts relative to this worktree:

- `.workspace/workflows-final.log`, `.workspace/unit-final.log`.
- `.workspace/er-JqNtV8/rules.png`, `rule-editor.png`, `editor-narrow.png`,
  `evaluation.png`: actual namespace-backed Electron UI, normal and 860×600.
- `.workspace/er-JqNtV8/synthetic-udp-partial.png`: synthetic status only.

### Bounded production memory diagnostic

No debugger, CDP or test runner attached. Production `electron/launch.py` reused a
real isolated Go observer/controller with approximately 20 sockets. `/proc` PSS
and private memory were accessible for all eight Electron processes (main,
renderer, GPU, utility, zygotes and broker); Go observer reported separately.
CPU is a five-second interval, percent of one CPU. The editor was opened/closed
using normal keyboard controls. This diagnostic predates the extra UDP toolbar.

| Sample | Electron PSS | Private | Summed RSS | CPU | Go observer PSS / private / RSS / CPU |
|---|---:|---:|---:|---:|---|
| Idle | 313.6 MiB | 149.3 MiB | 819.1 MiB | 0.8% | 16.2 / 16.2 / 17.7 MiB / 0.8% |
| After editor cycle | 379.1 MiB | 207.2 MiB | 896.7 MiB | 1.0% | 17.9 / 17.9 / 19.4 MiB / 0.6% |

Raw samples: `.workspace/mm/idle.json`, `.workspace/mm/after-editor.json`;
production editor capture `.workspace/mm/editor2.png`. Eight processes remained
in both samples. The increase in this short sample does not establish a leak;
there is no history buffer, duplicate backend poller or retained native editor
window (the editor is bounded DOM). Permission-window open/close **was not measured
in this debugger-free pass**: desktop focus could not be controlled reliably.
No extended benchmarking or sandbox/GPU changes were made. The earlier ~963 MiB
figure was summed RSS with the test debugger, not private memory or PSS.

## Integration and remaining migration gaps

Stay on `frontend/electron`, worktree `.workspace/worktrees/electron`. Integrate
`electron/`, `scripts/build-electron.sh`, `scripts/run-electron.sh`,
`scripts/check-electron.sh`, and `scripts/check-electron-workflows.sh`. No API or
shared bridge change is required. Qt remains available. This branch was rebased onto
`dbe651f9cb6f2fd51ec416113faaf7f4d9ebf55d` to incorporate the additive attribution backend.
Also integrate `scripts/check-electron-background.sh`.

Remaining gaps: real system sudo authentication and privileged extended-monitoring
Enable/Stop through Electron are unverified; their frontend boundary/status checks
are simulated and existing Go kernel evidence is reused. Permission-window PSS
cycle remains unmeasured. No packaging or application artwork beyond the original tray glyph.
The dense dark presentation follows NetLimiter proportions without claiming a
pixel-identical match; required identity/scope text makes the editor taller and
scrollable, and endpoint columns scroll horizontally at narrow widths.

## Tray, background requests and attribution increment

Enable **Keep running in the tray when the window closes** in the **Options** menu of the
main window. It is off by default. Closing then hides the existing window and
preserves selection, layout and unfinished rule input. The tray offers Open,
current pending count/list, independent enforcement/extended-monitoring status,
and Quit. Quit confirms that only Electron and its owned observer exit; independent
controllers/collectors retain their lifetime, including the original evaluation
deadline. Unknown/disconnected status is never described as stopped.

The original cyan/white/black tray glyph targets light and dark panels. Linux tray
availability is checked against the StatusNotifier host through fixed `dbus-send`
operations. Missing support prevents invisible close-to-tray; losing the host
restores a visible window without activating it. No services/autostart are installed.

Native notifications request review only while inactive/minimized/hidden. They
contain plain application/direction/endpoint text, no verdict buttons. Clicking
checks generation, identity and current pending state again. Expired/resolved
notifications cannot substitute a different request; the current pending list is
still accessible. New notifications never replace unfinished rule input. Notification
suppression/failure leaves the authoritative count/list usable; no Do Not Disturb
setting is overridden and no window automatically takes focus.

Main-process control polling continues while hidden. Hidden renderers receive no
snapshot stream; showing refreshes the latest bounded snapshot without resetting
traffic baselines. Notification state is bounded to 512 seen identities, 256 queued
identities and three live notifications, at most one delivery per three seconds.
Bursts become a summary. Repeated polls/reconnect do not automatically replay
notifications or decisions. Generation changes distinguish reused request IDs.

Attribution uses the backend's `ownership_category` explanation, distinguishes a
recovered worker TID from `thread_group_pid`, and groups shared sockets only when
Go explicitly provides `display_application`. Each socket is counted once. This
association is **observation-only, never a permission target**. Unresolved sockets
remain in one Unidentified group; inode-zero rows explicitly have no userspace
inode. Creation UID/global visibility limitations alone do not prove permission
denial. Socket selection and parent expansion follow the stable ID during regrouping.
UDP API-byte/partial-coverage semantics and separate TCP aggregates are unchanged.

### Focused evidence

Run `scripts/check-electron-background.sh` on the existing KDE/Wayland session.
This builds and runs 13 synthetic unit checks, the isolated real-controller
background test and an explicitly synthetic attribution presentation fixture.
No UDP kernel matrix, real sudo authentication or live-host enforcement is run.
Existing backend ownership and UDP evidence is reused.

Actual sandboxed Electron + real disposable controller passed:

- Tray pending count, retained UDP delivery after explicit Allow, Block preventing
  delivery, expiry and resolution by another client granting nothing.
- Actual KDE notification `Notify` delivery and notification-daemon `InvokeAction`
  activation opening the matching request without a verdict. This is **daemon API
  activation, not a physical mouse click**; notification popup appearance and DND
  behavior were not verified.
- Twelve actual requests produced bounded summary notifications; repeated polling
  did not continuously renotify. Four hide/reopen cycles retained editor input and
  one native main window.
- Explicit tray Quit exited Electron and its launcher-owned observer; independent
  controller retained its exact deadline. The confirmation response was simulated.
- Synthetic notification failure/unsupported tests preserve pending access. A
  synthetic tray-host probe failure restored the visible recovery window.
- Synthetic attribution checks cover same-app shared totals, unresolved/inode-zero
  explanations, worker TID, and selection/expansion during regrouping. These are
  presentation evidence, not new kernel ownership evidence.

Artifacts (relative to this worktree): `.workspace/background-test.log`,
`.workspace/background-unit.log`, `.workspace/attribution-ui.log`, and
`.workspace/bg-Yp60r4/desktop-notifications.json`. Real UI screenshots:
`.workspace/bg-Yp60r4/notification-prompt.png` and
`.workspace/bg-Yp60r4/tray-preference-editor.png`. The attribution log identifies
its separately labelled synthetic screenshot. Test-owned processes were cleaned up.

### Production visible/background sample

Unmodified production launcher, no debugger or test runner, real read-only host
observer, no controller/privileged collector. All eight Electron processes had
readable PSS/private memory. CPU is percent of one CPU over five seconds; this
brief sample is not a benchmark or leak claim. Hidden Activity rendering was idle.

| State | Electron PSS | Private | Summed RSS | CPU | Observer PSS / private / RSS / CPU |
|---|---:|---:|---:|---:|---|
| Visible | 360.5 MiB | 193.3 MiB | 871.2 MiB | 1.0% | 16.9 / 16.9 / 18.9 MiB / 1.4% |
| Tray | 367.4 MiB | 200.3 MiB | 879.1 MiB | 0.0% | 17.3 / 17.3 / 19.1 MiB / 1.6% |

Raw samples `.workspace/tray-measure/visible.json` and `tray.json`. Both contained
eight Electron processes and one observer. Reopen-cycle/window-count evidence is
from the isolated test above, not this debugger-free sample. No sandbox or GPU
settings were weakened. Production launcher termination cleaned its observer.

## Atomic conditional Delete integration

Frontend history was rebased onto required backend
`1729c292e29e5feef73b286864aa44bf4d551fcb`, preserving the earlier Electron increments.
Qt/backend/shared authentication files were not modified by this frontend migration.

Delete sends exactly one `rule-delete` request with the snapshot shown in its
confirmation: generation, rule ID and `expected_version` (numeric 0 when omitted
from an older stored rule). Polling never replaces those tokens while confirmation
is open. The backend atomically checks and deletes. Version/generation conflicts
refresh authoritative state and require a newly displayed snapshot/confirmation;
`not_found` is already absent, not this client's successful deletion. Other
structured failures retain their backend code and message.

Success requires an acknowledgement matching the submitted generation, ID and
version. Lost/malformed/mismatched responses remain unresolved even if a refreshed
list shows absence; no automatic retry occurs. Protocol capability is independent
of authorization and health. Read-only/disconnected clients remain unable to mutate.

This client supports rule versions through JavaScript's exact integer range
(0–9007199254740991). A larger uint64, negative, fractional or malformed version is
rejected explicitly at protocol projection, before display or submission; mutations
are unavailable until a valid authoritative snapshot is available. It never silently
rounds a version into a mutation. Use a uint64-capable client for larger versions.
A missing stored version is 0; a missing acknowledgement version is invalid.
No backend wire change is required, and this limitation was coordinated with its owner.

Run `scripts/check-electron-delete.sh` with existing repository-local dependencies.
It builds and runs only focused delete/rule-save checks and sandboxed Wayland
Electron against the disposable real controller. No package installation, host
enforcement, privileged collection or broad UDP/tray matrices.

Passed real-backend/UI checks:

- Electron Delete succeeds with matching conditional acknowledgement.
- Deterministic concurrent edit: confirmation is displayed first, another client
  saves and receives acknowledgement, then Electron submits its frozen version.
  Delete conflicts and the newer rule survives.
- Actual controller restart before confirmation submission rejects the original
  generation; the persisted rule survives.
- Real deletion with **synthetic proxy response loss** refreshes to authoritative
  absence, retains unresolved outcome and sends no replay. Activity remains usable.

Synthetic compatibility stripping disables Delete and direct bridge submission.
Synthetic protocol/transport checks cover version 0, unsafe uint64 rejection,
all structured failure codes, missing/mismatched acknowledgements and no replay.
Existing rule-save identity/expiry/single-use receipt regression passes. Completed
backend concurrency and prior tray/UDP evidence are reused, not rerun.

Evidence: `.workspace/delete-ui.log`, `.workspace/delete-unit.log` and
`.workspace/del-kCUuoE/conditional-delete.png` (actual isolated-controller UI).
Test-owned Electron and namespace supervisor processes exited. No real sudo
workflow was exercised. Integration files for this increment: four frontend
modules (`backend`, `protocol`, `rules`, `workflows`), two focused delete tests,
this README and `scripts/check-electron-delete.sh`.

## Live traffic graphs

Based on exact integrated checkout `ffa5c45f99c393853e73e28af2b2be7c6e948371`.
The lower Info View contains a lightweight canvas chart for the selected socket,
process, application or Unidentified group. Choose **60 s / 5 min** and **TCP
transport payload / UDP API-reported bytes**. Download is green/solid; upload is
orange/dashed so equal rates remain distinguishable. Axes show B/s and elapsed
time. Labels remain text; no remote assets or chart framework are loaded.

Group charts include **all observed member sockets**, independent of table search
and filters. Thus a filtered table can show a smaller subtotal than its graph;
the chart states this scope. Membership is recorded at each sample, not calculated
retroactively from current owners. Shared sockets are counted once. Discovery of a
new owner keeps socket history, while earlier unidentified traffic stays in the
historical Unidentified group. Display attribution remains observation-only.

TCP/UDP definitions never share a sum or rate axis simultaneously: use the source
selector to inspect each independently. Unsupported UDP has an explanatory empty
graph, not fake zeroes. Collector availability, partial measurement coverage and
census visibility limitations remain distinct. Partial sums use known measurements
with `*`; missing components are not imputed. Rates come directly from Go (which
uses monotonic intervals); Electron does not differentiate counters or infer bytes.

Backend generation/sequence/collection time identify a sample. Duplicate/older
poll deliveries add nothing. Collection times are anchored onto the frontend's
monotonic timeline; wall-clock discontinuities break and re-anchor the trace.
The first observation/reconnect warms up without a rate; known baseline/source
changes and counter decreases produce gaps. Missing rates, absent sockets,
collector loss and observer loss never become zero or connected line segments.
Measured zero is plotted as zero. Sequence skips break the line rather than
inventing the missing samples. New backend generations start a fresh history so
reused IDs cannot inherit a previous observer's socket history.

### Bounds and background operation

One main-process in-memory store samples the **existing observer callback**. No
new observer, timer or endpoint. No disk history, export or historical analytics.
History begins when this frontend observes the socket/group; empty time before
that is left blank. On-demand typed graph IPC returns only the selected history.

- Up to five minutes and 1,202 source-points per entity (TCP/UDP points count
  separately); 120,000 points across the entire store.
- Up to 2,048 current socket measurements, matching the backend census; at most
  8,192 total socket/process/application/group records.
- At most 256 inactive records, including closed sockets/groups, for 60 seconds.
- A proportional per-record budget shortens history under heavy socket counts;
  **History shortened by memory bound** is explicit. Five minutes is a maximum,
  not a guarantee. Evicted records return empty; identities never share buffers.

Hidden/tray windows continue bounded sampling without canvas rendering or graph
IPC polling. Showing them queries retained data. Rendering occurs only for fresh
samples, selection/window/source changes or resizing; no animation timer. Existing
selection, table filters/sorting/widths, sidebar sizing, rules, conditional Delete,
authentication, tray notifications and firewall behavior are unchanged.

### Focused verification

`scripts/check-electron-graphs.sh` uses existing dependencies, builds the ordinary
read-only observer/native loopback fixture, and runs only graph/model checks and
actual sandboxed Electron on KDE/Wayland. No controller, live-host enforcement,
privileged collection or UDP kernel suite. Existing UDP evidence is reused.

Real TCP shared-FD fixture: correct upload/download series, exact agreement with
socket table rates, idle measured zero, application graph agreement with unique
socket sums, and three hide/reopen cycles retaining history with no duplicate
sample times or windows. Normal 1280×820 and narrow 860×600 screenshots inspected.
A process/application includes both ends of its own loopback exchange; that is
not an interface-wide total. All fixture/observer/Electron processes clean up.

Synthetic unit samples cover mixed sources, shared deduplication, partial coverage,
unavailable samples, disconnect/reconnect, reset/source change, bounded eviction,
new socket identities/reused endpoints, ownership reassociation, duplicate/older
sample delivery, and backend wall-clock jumps. These are **not UDP/kernel evidence**.
The focused model regression is reused in the same run. No synthetic screenshot is
presented as real measured traffic.

Evidence: `.workspace/graph-real.log`, `.workspace/graph-unit.log`; the real log
identifies the capture directory containing `real-tcp-socket.png`,
`real-tcp-application.png`, `real-tcp-narrow.png`, and `graphs.json`.

The short visible/hidden resource comparison in that directory (`visible.json`,
`hidden.json`) sums the Electron tree's PSS/private memory and RSS, with the Go
observer separate; CPU is percent of one CPU over five seconds. **The external
Playwright debugger is attached in both samples**, so these are comparable UI-test
measurements, not production memory figures. No resource gate or extended benchmark.

Latest graph run: `.workspace/gr-Vhk0fS/` (nine synthetic/model checks passed).

| State | Electron PSS | Private | Summed RSS | CPU | Observer PSS / private / RSS / CPU |
|---|---:|---:|---:|---:|---|
| Graph visible | 430.6 MiB | 257.6 MiB | 961.5 MiB | 2.8% | 17.1 / 17.1 / 18.6 MiB / 1.4% |
| Hidden | 431.2 MiB | 258.1 MiB | 962.1 MiB | 1.0% | 17.1 / 17.1 / 18.5 MiB / 1.4% |

Eight Electron processes in both samples; same retained history and idle fixture.
This bounded comparison does not establish a leak or a production resource budget.
Integration adds `electron/src/{history,graph}.ts`, their typed bridge/render hooks,
focused tests and `scripts/check-electron-graphs.sh`; no backend/Qt changes required.

## Desktop controls and layout (2026-10-17)

**Control** contains the existing evaluation profile/Start/Stop/status/recovery
and independent extended-monitoring controls. **Options** contains the opt-in
close-to-tray preference and Quit. Activity, enforcement status and pending-request
access remain visible. Neither menu starts privileged work automatically.

The sidebar defaults to 38% of the window; saved widths still take precedence.
Drag its separator or use its arrow keys. Technical identity details expand in
place. The live graph remains available, with TCP/UDP sources separated and gaps
preserved. Upload/download headers now sort descending on their first selection,
then toggle; unavailable measurements remain below measured values in either order.

Prompt From/To follows incoming/outgoing direction. Full executable identity,
attribution and exact backend deadline are selectable in the expandable details;
endpoint, deadline, scope and decision controls remain visible. The modeless editor
keeps its draft and offers pending-request access through Minimize/resume.

See [VISUAL-REVIEW.md](VISUAL-REVIEW.md) for the desktop verification scope.
Focused reproduction with already-installed dependencies: `scripts/check-electron-visual.sh`.
It uses real unprivileged host TCP observation and the existing disposable namespace
controller, never host enforcement or privileged host UDP collection.

### Targeted palette, table, rule inventory and installed icons

See [VISUAL-TARGET.md](VISUAL-TARGET.md) for rule indicators and installed icons. Activity uses installed Open Sans when available (Noto Sans
fallback); no proprietary fonts are downloaded. Actual Linux application icons are
resolved from matching desktop-entry executables and the installed theme in main,
with a neutral fallback; icon association has no policy authority.

**In Blocker / Out Blocker** follow the rate columns and explicitly describe
**configured policy**, never an effective connection verdict. Cells distinguish
application-wide, protocol/scoped, mixed, disabled/expired, no explicit rule and
unavailable policy. Click either cell (or the sidebar direction count) for the
relevant scopes and existing versioned editor. Shared observation-only identities
never become permission targets. An empty inventory does not imply Allow or Ask.

### Existing machine daemon

```sh
./scripts/run-electron.sh --daemon /run/flowgate-api/daemon.sock
```

This reuses the primary policy endpoint and its `.monitor` Activity companion;
no additional observer starts. Electron remains unprivileged and closing it leaves
the independent daemon running. The explicit backend permissions independently
gate stored-rule editing and pending decisions. A non-enforcing daemon can permit
rule editing while the toolbar correctly says **Enforcement stopped**. A read-only
companion allows viewing policy but exposes no mutation controls. Invalid advertised
permission metadata fails closed. Prototype evaluation controls are disabled for
this independently managed non-enforcing daemon; this UI does not transition it.

Creating the first rule from Activity requires `observed-rule-create-v1` on the
primary endpoint. Older daemons retain pending-request creation only. Existing configured
rules open the existing authoritative preview/versioned-save workflow; conditional
deletion protections remain unchanged. Changing policy need not disconnect existing
approved TCP sessions.

See [ACTIVITY-POLICY.md](ACTIVITY-POLICY.md) for current root-monitor captures,
measured dimensions, real versus seeded/synthetic evidence and focused checks.

Focused checks with existing local dependencies:
`cd electron && npm run build && node --test test/model.test.cjs test/presentation.test.cjs`.
`node electron/test/presentation.mjs` from the worktree root exercises labelled
synthetic UI edge states, without enforcement. `VISUAL_STAGE=target-final node
electron/test/visual.mjs` uses the existing disposable controller for the actual
inventory check, preserving independent host controllers and collectors.

### Authoritative Activity policy batches

A primary daemon advertising `policy-explanations-v1` supplies Activity's In/Out
summaries through one bounded `policy-view` batch, driven by the existing main-process
control loop (at most once per second; no per-row requests or new timer). Columns say
**Backend policy**. Clicking shows the backend's configured class, exact rule refs,
configured/runtime defaults and direction-specific enforcement coverage. Stored Block
while stopped is not protection; incoming-only coverage does not imply outgoing
protection. Initiation direction differs from upload/download byte flow. These are
current policy explanations, never evidence of a past connection outcome.

Older daemons—including the independently running root monitor—show **Listed · legacy**
and an explicitly labelled compatibility inventory. New metadata failures never fall
back silently. Generation changes, disconnect, policy expiry, mismatched observation
identity and out-of-order replies clear authoritative results. Decimal response sequences
and rule-ref versions stay exact strings; sequence ordering uses BigInt. Existing
numeric mutation APIs still refuse unsafe uint64 values instead of rounding them.

Policy details offer Edit and conditional Delete using existing preview/version and
frozen-confirmation safeguards. Unfinished editor fields survive metadata refreshes.
The read-only policy API supplies **no creation authority**. Activity creation uses
the separate `observed-rule-create-v1` preview/save contract described below; a
summary association is never used as a creation token.
The existing pending-request creation workflow is unchanged. No stored Ask action,
new precedence, filter semantics or accounting exclusion is introduced.

`--daemon /run/flowgate-api/daemon.sock` continues to reuse primary/companion endpoints
without owning the daemon. For an independently started evaluation controller use
`--daemon /run/flowgate-api/control.sock`. The toolbar reports actual profile/state;
new evaluation selection offers incoming-only, with both directions disabled because
support is not advertised by the present contract. No daemon transition starts on launch.

Focused reproduction with already-installed dependencies:
`npm --prefix electron run build && node --test electron/test/policy.test.cjs`.
For a compatible released backend binary, the isolated seeded-rule workflow is
`FLOWGATE_TEST_POLICY=1 FLOWGATE_TEST_DAEMON=/absolute/path/to/flowgate node electron/test/policy-workflow.mjs`.
It checks the authoritative batch, Activity→details→editor→save, exact expiry/version,
read-only denial, narrow layout and preserved editor focus. It never activates enforcement.

Current icon audit: 4/15 distinct live executables had reliable installed desktop/icon
associations and all four resolved (Firefox, KDE Connect, KRDC, KRDP). The remaining
nine services and two CLI/runtime executables had no matching application metadata;
related settings/discovery utilities are not substitutes. No demonstrated resolver
failure justified weakening executable matching. The actual UI capture also contains
transient test/CLI processes and Unidentified; its visible-row denominator is separate.
Neutral fallbacks, bounded caches and the existing narrow asset protocol remain intact.

Verification for this increment: backend **0aca36145adc857bdb59d52f1862a420bbdac9cf**,
`.workspace/flowgate-policy` SHA256
`556e49b5747b012b3882e93bd633cc55569885c6673b0b74045d593ca7b55ca2`.
No backend commits were merged into the UI branch. Build and 22 focused checks passed;
synthetic generation/order/expiry cases are not enforcement evidence. Actual sandboxed
Wayland + real isolated daemon/seeded rule passed in `.workspace/policy-ui-upGpIo`
(policy list, editor/save, narrow and companion read-only screenshots). That earlier policy-summary increment did not include first-rule creation; see the
subsequent creation evidence below.

Real host fallback screenshot with installed icons and policy details:
`.workspace/policy-authoritative/root-fallback.png`; narrow: `after-narrow.png` in the
same directory. That final capture has 18 visible rows including Unidentified and transient
frontend/test processes, with four resolved installed icons. `icon-audit.json` records
the separate 15-executable pre-launch audit. `tests.log`, `isolated.log`, `root.log`,
`synthetic.log` and `final-lifecycle.json` distinguish evidence and confirm fixture
cleanup plus unchanged root peer PID/generation/stopped state/zero rules. No host
mutation, activation, collection, daemon restart or unrelated suite was performed.

## First rule from Activity (observed-rule-create-v1)

Click an application's **In Blocker / Out Blocker** cell → **New incoming/outgoing
rule…**. Direction means connection initiation, not download/upload. The primary
must advertise `observed-rule-create-v1` and grant `can_manage_rules`; it need not
grant `can_decide`. Older daemons show an update explanation, and read-only or
unsupported selections cannot create. No pending connection is required.

Choose an explicit address/port scope or **All addresses / ports for this protocol**,
TCP or UDP, Allow or Block, enabled state and expiry. All-endpoint scope covers only
the selected protocol. The initial expiry is one hour; preserving expiry retains
that absolute time. Priority is backend-fixed at 100. Preview verifies the live native
single-holder socket/process/executable/UID/namespaces and displays the backend scope.
Shared/runtime/unsupported identities cannot use this operation. Policy-summary display
associations alone never confer creation authority.

Preview lasts 30 seconds. Changing fields invalidates Save; expiry, permissions or
session changes require review again. Save sends the exact frozen draft and token,
never invented identity or pending IDs. No automatic retry occurs. Lost/mismatched
acknowledgements freeze the editor and offer **Check save result**, which only reads
authoritative rules and compares the reserved rule ID and full reviewed contents.
Absence is unresolved, not proof of failure; closing warns to inspect saved rules
before creating again. Acknowledged/reconciled success selects the rule in Rules.
Saving stored policy never activates enforcement or releases a pending packet.

Verification backend: **8ef90cde66c73c69bf8fd8b686e82d2298b98536**; no backend
commit merged here. Build and nine focused creation/rules/delete/policy tests passed.
Synthetic tests cover generation/identity changes, capability denial, expiry and
persistence failure. Actual sandboxed Wayland with a real non-enforcing isolated Go
daemon, native Python listener and initially empty policy passed first incoming and
outgoing creation with no pending events, authoritative policy appearance, edit,
conditional delete, real 30-second expiry, focus preservation and read-only denial.
A labelled proxy fault dropped one real save acknowledgement: reconciliation found
the committed rule without a second save. This is not host enforcement evidence.

Reproduce with installed dependencies:

```sh
npm --prefix electron run build
node --test electron/test/observed-rules.test.cjs electron/test/rules.test.cjs electron/test/delete.test.cjs electron/test/policy.test.cjs
FLOWGATE_TEST_DAEMON=/absolute/path/to/released/flowgate node electron/test/creation-workflow.mjs
./scripts/run-electron.sh --daemon /run/flowgate-api/daemon.sock
```

Inspected captures (relative to this worktree):
`.workspace/creation-ui-5tNt4G/first-rule-preview.png` (1280×896),
`first-rule-preview-narrow.png` (860×600), and `created-rules.png` in that directory.
They show a labelled real isolated fixture, not host rules. Older root-daemon fallback
and descending-first rates passed with no host mutations; captures/logs are in
`.workspace/observed-creation/`. Existing root daemon stayed running with enforcement
stopped; adoption of the new API needs a separately authorized backend update.
Test-owned namespace daemon/Electron processes exited. Existing accounting, icons,
tray and receiver-enforcement evidence was reused, not rerun.

## Activity/editor polish after integration c448cf1

Base: `c448cf15c6e2c30621649f6d877f6f34b1bce567`, fast-forwarded only after
integration released ownership. Backend/API/authentication/launcher are unchanged.

Policy cells say Allow/Block only for backend uniform configured policy, otherwise
Scoped, Mixed, Inactive rules, No explicit rule or Unavailable. Coverage and defaults
remain in the policy view/tooltip; no default or historical verdict is inferred.
New incoming/outgoing rule is near the top of the panel. Longer default/permission
explanations are expandable. Overall enforcement remains visible in the toolbar;
redundant per-direction sidebar status and idle footer warnings are removed.

The editor exposes Any address/Any port checkboxes instead of requiring `*`/0.
Unchecked fields require an explicit valid value; empty ports cannot silently become
wildcards. Protocol-wide scope is still an explicit selection and covers only TCP
or UDP, not all traffic. Expiry choices distinguish keeping the existing absolute
expiry, one hour from preview, and persistent. Application/direction/UID remain visible.
A readable summary uses the **structured reviewed backend rule**; full unmodified
backend scope text is expandable. It is display formatting, not another evaluator.

The existing polling update displays remaining preview seconds beside Save; no new
timer or renewal loop was added. Expiry/session invalidation preserves fields and
shows Refresh preview. Refresh obtains a new receipt for review, never saves. Stale
identity errors explain reselection. Existing acknowledgement/reconciliation and
conditional deletion safeguards remain unchanged.

Focused evidence: build and 12 presentation/creation/policy/rules/delete tests;
real sandboxed Wayland isolated first-rule runner against released backend
`8ef90cde66c73c69bf8fd8b686e82d2298b98536`, including real preview expiry, preserved
fields/focus, incoming/outgoing save, edit/delete, read-only denial and a labelled
lost-ACK transport fault with no duplicate creation. Root monitor inspection was
read-only and verified descending-first rate sorting, keyboard focus, policy details,
real icons and normal/narrow layout. No host rule saves or daemon lifecycle changes.

Creation captures: `.workspace/creation-ui-ZLz0Ct/first-rule-preview.png` and
`first-rule-preview-narrow.png` (real isolated listener/database, explicitly labelled).
Logs: `.workspace/activity-polish/{build,tests,after,isolated-final}.log`.
Remaining differences: Linux font rasterization, supported policy instead of NetLimiter's
limiter/priority controls, and sparse sidebar/table content for the actual host inventory.
No overall similarity percentage is assigned.
One intermediate repeat closed its Electron process unexpectedly; its screenshot-error
handler obscured the original failure. The runner now logs the original exception
before attempting a failure capture. The subsequent complete run passed; no cause
for that intermediate closure was established.

## Daemon-owned extended UDP monitoring

The `daemon-udp-monitor-v1` capability selects the connected daemon's
`traffic_monitor` status and fixed `traffic-start` / `traffic-stop` operations.
Electron reuses its existing Activity/control connections and polling; it launches
no helper/observer/second daemon and requests no sudo for this capability.
The compact **UDP · state** Activity button opens the existing Control menu's
Extended monitoring Enable/Stop controls. Enable is explicit and disabled by default.

`can_view_measurements` and `can_control_traffic` are consumed separately from
`can_manage_rules` and `can_decide`. A primary administrator needs the backend's
explicit collector-control grant; writable rule storage alone is insufficient.
Companion/read-only connections can display authorized data but cannot control it.
Static `available` is not proof of attachment: starting remains starting until Go
reports active. Failed/unsupported states retain their actual reason in details.
TCP Activity, rules and enforcement status remain independent.

Each lifecycle operation freezes daemon and collector generations. No duplicate
operation is sent while a response is pending. Lost/mismatched responses remain
uncertain until a **list request begun after the operation finished** returns;
an earlier in-flight poll cannot unlock another Start. Reconciliation only reads
status, never retries Start/Stop. Generation changes discard stale responses. After
recognizing daemon ownership, metadata failure, disconnect or capability loss never
falls back to the legacy privileged launcher. Invalid optional collector metadata
disables lifecycle controls without dropping the ordinary TCP/rules API.

Older daemons retain the clearly labelled **legacy monitoring** authentication path.
The frontend never combines a legacy measurement stream with daemon-owned samples.
Enable on the consolidated path requires Activity from the same daemon generation.
No setting restores collection automatically after reconnect. Hiding/quitting Electron
leaves independent collection running; explicit Stop only stops UDP collection,
not the daemon or firewall. The tray displays the observer's collector status.

Activity continues using existing UDP socket API-byte fields, counted once across
peers/shared holders, independently from TCP transport payload. Partial coverage is
`*` with detail, missing data is not zero, and mixed definitions are not summed.
The bounded main-process graph store now explicitly breaks UDP traces on collector
generation/state changes, suppressing the transition sample while retaining historical
points; TCP samples continue. No new history timer, collector, or baseline calculation
was introduced. These are application/socket observations, not deduplicated internet
usage or VPN transport accounting.

Focused reproduction (installed dependencies):

```sh
npm --prefix electron run build
node --test electron/test/daemon-monitoring.test.cjs electron/test/history.test.cjs electron/test/extended.test.cjs electron/test/backend.test.cjs
# Attach only to an externally owned, disposable fixture, initially disabled:
FLOWGATE_UDP_UI_ENDPOINT=/absolute/project/.workspace/fixture/api/daemon.sock \
FLOWGATE_UDP_UI_EXPECT=failed node electron/test/daemon-udp-workflow.mjs
# Explicitly synthetic active rates/lifecycle; no Go daemon/BPF:
node electron/test/daemon-udp-display.mjs
# Ordinary launch remains non-enforcing; no collection starts automatically:
./scripts/run-electron.sh --daemon /run/flowgate-api/daemon.sock
```

The Wayland runner refuses host `/run` endpoints. With `EXPECT=active`, the fixture
owner must supply actual measured UDP transfers and independently clean up after
GUI exit; it tests Stop then restart and leaves the collector active for that owner.
With `EXPECT=failed`, it records the actual attachment error and tests Stop/TCP
continuity. The runner logs Electron stderr, closure and renderer crashes; no
unexplained window closure recurred in this increment.

Evidence: 18 focused tests passed (synthetic lifecycle/fault replies and graph samples).
Actual sandboxed Wayland against the production Go daemon in a disposable user/net
namespace passed Enable→failed→Stop, TCP availability, read-only denial and daemon
survival after frontend exit. `.workspace/daemon-udp-ui-JBH2BD/attachment-blocker.json`
records `bpf_load_failed`: `collector_inspection_denied: cannot exclude an older
tracing collector: Operation not permitted`. The backend owner's isolated initial-
user-namespace attempt was refused with `sudo: a password is required`; it was not
retried at that stage (superseded by the kernel-backed check below).

### Kernel-backed consolidated UDP check

Backend `15d6e1a9762092c86fdb3201ffb7d71c77303eb0` (`daemon-udp-monitor-v1`; fixture
artifacts reported bit-exact to that source) with this UI. The user ran
`scripts/check-daemon-udp.sh --kernel --reuse-build --hold --traffic`, a disposable
initial-user-namespace net/pid/mount namespace with continuous native UDP4/6 + TCP.
No host collector, rule, firewall or route change. Sandboxed Wayland Electron attached:

```sh
R=/absolute/project/.workspace/daemon-udp-<run>
FLOWGATE_UDP_UI_ENDPOINT=$R/api/daemon.sock FLOWGATE_UDP_UI_RECEIVER=$R/receiver.json \
FLOWGATE_UDP_UI_EXPECT=active node electron/test/daemon-udp-workflow.mjs
```

- **Real measurements** (`.workspace/daemon-udp-ui-bVpoWV/`): six fixture sockets
  (UDP4/UDP6, connected/unconnected) shown as `udp-api-reported`; displayed bytes advanced
  exactly with the fixture's receiver counts across a traffic tick (constant per-socket
  offset, since receiver counts start at fixture creation and the collector at Enable).
  `consolidated-udp.png` is labelled REAL ISOLATED UDP. Stop rendered `—` (not zero),
  ended the UDP graph and kept TCP updating.
- **Restart and GUI exit** (`.workspace/daemon-udp-ui-KKXSTR/`, separate fixture run):
  each socket's UDP graph shows a two-sample break ("new baseline") and restarted rates
  equal to prior rates (e.g. 1421.0 vs 1421.2 B/s; no spike). After Electron exit the
  daemon generation, collector generation and active state were unchanged; enforcement
  stopped. Read-only connection: view permitted, control denied.

Two earlier fixture runs ended mid-check after an interrupt-like signal to the harness
(backend verified graceful shutdown and clean namespaces); the signal's origin is
unconfirmed. The runner sends no signals; in the second case the socket disappeared
before Electron closed, and the final fixture survived two Electron exits.
Shared-socket deduplication was not separately verified in this check.

Actual failure normal/narrow captures and result are in `.workspace/daemon-udp-ui-JBH2BD/`.
Explicitly **synthetic** active/partial UDP display, restart, Stop and read-only checks
passed in `.workspace/daemon-udp-ui-xmH6ua/`; screenshots label synthetic data in the
window. Unit graph tests also prove UDP generation gaps without losing TCP samples.
Old-capability host fallback was inspected read-only in `.workspace/daemon-udp-evidence/`:
real Activity/icons, sorting and normal/narrow layout, no host mutation or restart.
Logs: `.workspace/daemon-udp-{build,tests,wayland,display}.log`. Backend fixture owner
handles its namespace/helper cleanup; Electron owns neither.

## Decision Log (`decision-log-v1`)

The **Decision log** tab (Ctrl+4) presents the daemon's persistent firewall decision
log: what tried to connect, what FlowGate decided, and why. The backend owns capture,
persistence, authorization and history (`docs/DECISION-LOG.md`); Electron only presents
it (`src/decision-log.ts` parsing/paging, `src/decision-log-client.ts` main-process
queries, `src/decision-log-view.ts` tab). It uses the existing connection: the
primary controller when it advertises the capability, otherwise the read-only companion.

- Newest-first cursor paging (100/page, ≤1000 retained rows with an explicit limit),
  `log_id`-scoped cursors (`invalid_cursor` or a new `log_id` restarts at newest),
  stable-ID deduplication, one request in flight, stale filter responses dropped.
- Server-side filters only: time range, direction, outcome, source, and "Only this
  application" from a selected record (key matches all revisions).
- Live follow / Pause. Inserts keep the selection and scroll position; "↑ N new" or
  "New records — show" indicates arrivals. Polling runs only while the tab is visible.
- Details show decision-time evidence only: outcome, source, scope, recorded reason,
  deciding UID, kernel verdict, recorded application identity and attribution, rule
  snapshot (ID/version/filter). **Allow is a policy decision plus verdict submission;
  delivery is always "Not observed by FlowGate".** A pending record links only to a
  loaded final record with the same request ID, otherwise "Outcome not loaded" (a page/filter is not the complete history).
- The current rule is shown separately (same version / changed since / no longer
  exists, plus "View current rule…" through the versioned editor). Deletion is only
  claimed on a rule-managing connection; elsewhere current state is "not available".
- Explicit states: disconnected, capability missing, permission denied, loading, no
  matching records, no decisions yet (with enforcement-stopped note), health
  (degraded/dropped/write losses/retention removed), gap rows, self/machine scope.

### Verification

Backend `028ca809386d8d4ee616dd4dce1b0b9190d88f82` (test binary
`.workspace/decisionlog-build/flowgate-decisionlog`, `vcs.revision` = that commit,
`vcs.modified=false`), integrated `142da8d28b8589f36b47fc4ecd23a314763ddc64`.

Real isolated enforcement (no sudo; own `decisions.db`; never the host daemon):

```sh
R=$PWD/.workspace/decision-log-ui-fixture-<n>; mkdir -m 700 "$R"
scripts/lab.sh python3 scripts/decision-log-isolated.py \
  --binary .workspace/decisionlog-build/flowgate-decisionlog --run "$R" --hold </dev/null &
FLOWGATE_LOG_UI_RUN=$R node electron/test/decision-log-workflow.mjs
echo quit > "$R/command"
```

Two sandboxed Wayland runs passed (`.workspace/decision-log-ui-X31d4e/`,
`.workspace/decision-log-ui-leVPx2/` in this worktree), each compared with the same
daemon's API: newest page equality; real user (scope application) and rule decisions
with recorded source/reason and verdict/delivery separation; live arrivals
(`decide-allow`) without losing the selection; `rule-traffic 130` then full paging of
145 / 285 records equal to daemon paging without duplicates; server-side direction,
action and source filters equal to daemon queries; `restart` (same database, new
generation) keeps all earlier rows and appends new ones. Screenshots `log-details.png`
(normal) and `log-narrow.png`. The burst included one real `capacity` block among
rule allows. The lab's `list` carries no rule inventory, which exposed and fixed a
false "rule no longer exists" claim.

Stored-rule edit/delete is not available in the lab (memory rules): snapshot
immutability is covered by the backend's unit tests; the UI's "changed since" and
"no longer exists" presentation is covered by the **synthetic** display check
`node electron/test/decision-log-display.mjs` (also unsupported, forbidden, empty,
filtered-empty, degraded health with a gap row). Store logic: 9 synthetic unit tests
in `test/decision-log.test.cjs`.

Backend limitations (corrected at integration): one second is a nominal flush
interval, not a crash-loss bound. Records become durable after a successful SQLite
transaction commit; storage stalls/failures can extend loss indefinitely. The bounded
queue drops new records when full. Known overflow/failed-batch counts are volatile;
a later committed gap persists known loss, but cannot reconstruct abrupt-crash loss.
`buffered` excludes the writer batch and engine capacity aggregates.

Deduplication follows the engine admission attempt/lease: retransmissions and UDP
datagrams within that lease share a decision; a new source port/TCP initial sequence
or fresh evaluation after expiry is recorded separately, even with identical policy.
UDP is not logged per datagram. Capacity refusals are explicit counted five-second
observation aggregates (not unique connections); the reason includes the count and
`aggregation` carries the time range. The current UI displays that backend reason.
Such a Block can override a matched Allow when the existing admission limits are
full; it is not a Block-rule result. Details: [Decision Log](../docs/DECISION-LOG.md).

Fragments, IPv6 extension headers and non-SYN TCP are not individually logged;
held-packet verdicts after a decision are not individually logged; delivery is never
observed. Monitoring-only daemons invent no decisions. Historical-versus-current
edited/deleted rule presentation remains synthetic UI coverage; backend snapshot
immutability is unit-tested. The real isolated fixture covers actual decisions,
lookup, filtering, paging and restart, not durable rule-editor operations.

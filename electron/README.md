# FlowGate Electron milestone

An additional unprivileged frontend; Qt and `scripts/run-desktop.sh` remain intact.
Vanilla TypeScript, CSS and Electron, built by esbuild. No web development server,
remote assets, frontend rule matching, packaging or charts. Explicit controls delegate privileged work to the existing terminal bridges.

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
- Authenticated API v1 `list`, `decide`, `rule-preview`, `rule-save` and `rule` are used. Go peer credentials and
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
- Enable/Disable uses versioned preview/save. Delete checks the current listed
  generation/version before using the existing backend Delete API; that API has
  **no atomic expected-version parameter**, so deletion cannot promise atomic
  conflict detection. Changing rules may leave already-approved TCP sessions alive.
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
cycle remains unmeasured. No charts, packaging or application artwork beyond the original tray glyph.
The dense dark presentation follows NetLimiter proportions without claiming a
pixel-identical match; required identity/scope text makes the editor taller and
scrollable, and endpoint columns scroll horizontally at narrow widths.

## Tray, background requests and attribution increment

Enable **Keep running in the tray when the window closes** at the bottom of the
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

A later backend atomic conditional-delete API is under development separately;
this branch still documents the existing non-atomic Delete limitation above.

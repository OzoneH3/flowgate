# FlowGate Electron milestone

An additional unprivileged frontend; Qt and `scripts/run-desktop.sh` remain intact.
Vanilla TypeScript, CSS and Electron, built by esbuild. No web development server,
remote assets, rule matching, privileged activation, packaging or charts.

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
and starts only its own read-only observer. Its observer stops when Electron closes
or the launcher receives Ctrl+C. `--observer` reuses an existing observer and leaves
it running. `--control` attaches to an existing authenticated Go API and never
starts, stops, or recovers its controller. Independent controllers/collectors
survive client exit. Each launcher owns only its own children and socket. Logs and
Electron profile/cache directories remain under `.workspace` for inspection.

For already-built **production** assets without rebuilding:

```sh
scripts/build-electron.sh
XDG_CACHE_HOME="$PWD/.workspace/cache" TMPDIR="$PWD/.workspace/tmp" python3 electron/launch.py
```

`--interval 1s` configures an owned observer; accepted backend range is 500ms–30s.
No startup enables host enforcement or privileged UDP collection. Fullscreen or
inactive applications receive no automatic popup: pending requests appear in the
main window, and **Open permission window** is an explicit user action. Closing
that window or choosing **Decide later** sends no verdict.

## Boundaries and backend semantics

- `main.ts` owns the Unix sockets indirectly through `backend.ts`. A separate
  serial poll loop serves Activity and control. Losing one does not stop the other.
- The renderer is sandboxed with context isolation, no Node integration and no
  webview. `preload.ts` exposes only snapshot/subscription, decision and explicit
  permission-window operations. Sender WebContents, main frame and local origin
  are validated for every invoke; decision payloads have exact allowed keys and
  enum values. No generic filesystem, shell, socket or IPC capability is exposed.
- Only three local assets are served by the custom `flowgate://app` protocol.
  Production CSP blocks connections, frames, objects, inline scripts and remote
  assets. Navigation, new windows and permissions are denied. Diagnostic names,
  paths, addresses and metadata are inserted using text nodes/textContent.
- Only authenticated API v1 `list` and `decide` are used. Go peer credentials and
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
  initially collapsed Unidentified group contains shared/unknown sockets, each
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

This builds native fixtures, runs seven small synthetic model/transport checks,
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

## Integration and remaining migration gaps

Branch `frontend/electron`, worktree `.workspace/worktrees/electron`, based on
current integration HEAD above (not the older supplied c631a70 snapshot). Integrate
`electron/` plus `scripts/build-electron.sh`, `scripts/check-electron.sh` and
`scripts/run-electron.sh`. No backend, API, UDP, Qt, existing scripts or dependency
contracts were changed. No new backend dependency is required.

This is a working first frontend, not pixel-identical completion. It has no rule
editor, Start/Stop authentication workflow, traffic charts, packaging, desktop
notifications or application artwork. The extra authoritative scope/attribution
fields make the prompt taller than the reference. The fixed-width dense tree uses
horizontal scrolling at narrow sizes; the information panel is not yet resizable.
Qt remains the fuller control frontend during migration. UDP expanded privileged
verification remains with the backend owner/user-authenticated workflow.

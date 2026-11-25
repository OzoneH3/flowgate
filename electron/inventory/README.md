# FlowGate GUI inventory

The inventory records displayed text and control state from a packaged FlowGate GUI. Run the same command in a local Linux desktop or as the logged-in desktop user inside a guest. Use **1920×1080 at 100% scaling**. The driver checks the display and the renderer language once per launch. It sends keyboard input to exact controls. Electron windows are identified by their document and, for permission windows and detached panes, their request/generation or pane identity.

## Capture

Extract a verified distribution archive or use its installed GUI directory. Use the packaged Electron runtime and its normal sandbox setup. On distributions that require a setuid sandbox helper, use the installed GUI from a disposable machine prepared by the release installer.

```sh
node electron/inventory/capture.mjs \
  --package /absolute/path/to/gui \
  --work "$PWD/.workspace/gui-inventory-run" \
  --out "$PWD/.workspace/gui-inventory-captures"
```

The package directory contains `matched-manifest.json`, `runtime/electron`, and `electron/dist/main.cjs`. Use Node 22.12 or later. A packaged runtime with Electron's Node mode enabled can run the driver without a separately installed Node:

```sh
ELECTRON_RUN_AS_NODE=1 /absolute/path/to/gui/runtime/electron \
  electron/inventory/capture.mjs \
  --package /absolute/path/to/gui \
  --work "$PWD/.workspace/gui-inventory-run" \
  --out "$PWD/.workspace/gui-inventory-captures"
```

Native entries require the desktop's AT-SPI services, Python GObject bindings with the Atspi 2.0 typelib, and libxkbcommon. Run in the active desktop session with its D-Bus and display environment. Each renderer capture requires a visible document and its PID-bound AT-SPI top-level with SHOWING state. Detached panes additionally require their distinct native accessible heading. Native dialogs and tray menu accessibility depend on the desktop implementation. Every unsuccessful native state produces a JSON file with an issue. The driver never reads tray menu labels from the StatusNotifier menu protocol as a replacement for accessible presentation.

Use a new output directory for each run and keep the work path short enough for Unix sockets. Per-journey profiles, Electron logs and fixture operation logs are retained under work. The process uses the packaged sandbox configuration, the debugger listens on an ephemeral loopback port, and the driver supplies its own Unix sockets instead of connecting to the host daemon. `--show` opens the normal main window at startup. Each journey starts from a fresh isolated profile. The fixture reports the package revision/version as its daemon build for the positive About case. The disconnected recipe verifies the separate unavailable case. These are display checks against the simulated API.

Steps with `tabTo` use real Tab events and check the exact focused control and document focus. The per-journey `verification.json` records the actual focus sequence and native showing checks. Other `focus` and `press` steps place focus directly to inventory controls. They provide no keyboard reachability claim. Seed timestamps used as historical data are fixed. Runtime deadlines and visible countdowns are relative to the launch and are captured as displayed.

`node electron/inventory/capture.mjs --list` lists expected filenames. `--only rules-edit` runs just that journey and is useful for debugging. For a full capture, omit `--only`. A failed postcondition, missing surface, or unreadable native control is recorded and makes the run exit nonzero. A blocked capture may include the controls still on screen. Its status distinguishes it from a verified capture.

## Files

- [Expected inventory](expected.json) defines window identities, per-state keyboard steps and visible postconditions.
- [Schema](window-state.schema.json) and [illustrative sample](sample.json) define one file per expected window/state.
- [Seed recipes](seeds.mjs) serve the private API, with fixed application, request, rule and record identities, and scenario-specific state transitions.
- [Source map](surfaces.md) identifies the source for each family and remaining unverified states.

Electron display strings come from the rendered DOM. Chromium's accessibility tree supplies computed names and roles. The serializer prefers an HTML ID, then a semantic data key, then a role ordinal scoped to the parent panel. The latter is a structural fallback, so reordering equivalent anonymous siblings can change their IDs. The native adapter uses accessible IDs when provided and scoped role ordinals otherwise. Whitespace is collapsed. Captures exclude geometry, fonts, styling, pixel data and line wrapping.

Use the integrated package and a fresh full capture for the definitive baseline. The seed is a GUI presentation fixture. It does not establish daemon behavior, firewall outcomes, or delivery.


The capture launches Electron with the process-scoped `ACCESSIBILITY_ENABLED=1`. On Plasma the activity-empty evidence records KWin's client identity and AT-SPI registration together, including the PID, title, role and native visibility flags. Desktop-wide accessibility settings stay untouched. Native visibility failures are retained as blocked captures.

The comparison replaces the independently measured desktop account token only in the Activity overview's seven known fields and records each original display value alongside the measured account. Measurement uses the OS account, the hostname, and the graphical session UID when available. The activity-empty state requires all seven fields. The rest of each field and its control identity remain exact.

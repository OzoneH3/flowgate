# Native Wayland launch investigation

2026-10-18, Electron44.9.0 on actual KDE/Wayland host; base7020db0.

The original main `.workspace/electron-run-xsggk83v` retained only an empty observer.log (expected with an external daemon). It did not retain GUI output, a screenshot or exit status. Its original rendering/exit outcome cannot be reconstructed from that directory. No original FlowGate process remained at inspection; this alone does not establish a crash.

Ordinary launcher reproduction **did render actual Activity** with native Wayland, DPR1/zoom1, sandboxed renderer, and an accelerated GPU process despite both warnings. No renderer/GPU failure was observed. Diagnostic-only main-process instrumentation captured windows/GPU information and requested resize/quit without Playwright's default Chromium flags. Final GUI exit0 and launcher exit0 were confirmed; no test-owned FlowGate Electron process remained. Host daemon/collector lifecycle was not changed.

## Wayland/Vulkan

The GPU feature report showed Vulkan compositing disabled while `webgpu_on_vk_via_gl_interop` remained enabled. Chromium's GPU initialization can initialize Vulkan for that separate interop feature. Its Wayland surface factory emits the reported ERROR when asked for native Vulkan. Disabling only Vulkan compositing did not remove the warning.

For explicitly selected Wayland, main now preserves existing disabled-feature flags, disables Vulkan compositing, selects ANGLE OpenGL and the WebGPU `opengles` adapter. This avoids the unsupported Vulkan interop path. Final ordinary-launch log contains no Wayland/Vulkan warning. OpenGL, GPU compositing, rasterization, canvas and WebGL remain enabled; WebGL reports `ANGLE (NVIDIA Corporation, NVIDIA GeForce RTX 4080 SUPER/PCIe/SSE2, OpenGL ES 3.2)`. Native Wayland and sandboxing remain enabled; no no-sandbox, X11 fallback or disable-gpu flag is added. Non-Wayland launch does not receive these settings.

Source evidence: Chromium [Wayland surface factory](https://github.com/chromium/chromium/blob/main/ui/ozone/platform/wayland/gpu/wayland_surface_factory.cc), [GPU initialization](https://github.com/chromium/chromium/blob/main/gpu/ipc/service/gpu_init.cc), [interop feature selection](https://github.com/chromium/chromium/blob/main/gpu/config/gpu_util.cc). The local verified runtime, not the evolving upstream source alone, establishes the result.

## Fontconfig

Electron emits cache-content revision `current0x2012001` versus cache`0x2012003`. Host `fc-cache --version` and the system library's `FcGetVersion()` report2.18.3. The warning format is also embedded in the Electron binary. File tracing confirms Electron loads `/usr/lib/libfontconfig.so.1` and reads `/var/cache/fontconfig/*-le64.cache-12`, the worktree `.workspace/cache/fontconfig/`, and `~/.fontconfig/`; older-suffix cache symlinks already existed in the workspace. No FONTCONFIG_* override was set. The trace does not by itself identify the emitting internal Fontconfig call.

The warning says cache regeneration is skipped. Actual text/icon layout rendered, installed Liberation Sans regular/bold files were opened, and resizing/quit worked. No demonstrated font-rendering failure required a cache fix. System/user/workspace caches were left intact. Do not blindly delete/regenerate system caches or treat the warning as proof that the window failed.

### Private-cache fix (2026-10-22)

The source launcher and prepared `launch-ui` now derive a configuration from the
system fonts.conf with the same font directories and rendering rules, replacing
its cache directories with a FlowGate-owned cache separated by Electron runtime
version. Relative system includes are made absolute. System and user font caches
are left intact; explicit FONTCONFIG_FILE/FONTCONFIG_PATH overrides are respected.
Included custom configurations that add their own cache directories are diagnosed
and preserved, so those custom configurations can still require separate cache
configuration. Failure to prepare the private configuration falls back visibly to
the system configuration.

Cold and warm native Wayland launches rendered without the Fontconfig version
warning. A system-versus-private font probe returned identical measurements for
all sampled families. The first termination runs were interrupted during cleanup;
they establish rendering and warning removal, not clean launcher shutdown.
Configuration and release-packaging tests pass, including the helper's inclusion
in the matched manifest. Full repository checks pass. Evidence is retained in
`.workspace/fc-launch-{cold,warm}.log`, `.workspace/fc-probe/` and
`.workspace/warning-fixes-full-check.log`.

## Retained diagnostics and build ownership

Each normal run now retains `launch.json`, `electron.log` and `exit.json` alongside observer.log under `.workspace/electron-run-*`, while continuing to echo output. Main logs successful rendering and unexpected renderer/child exits. No remote debugging endpoint is enabled by this change.

Frontend builds produce `.workspace/electron-observer` and `.workspace/electron-backend`, preserving `.workspace/flowgate` for separately approved backend builds/deployment. Legacy terminal bridges receive the fixed `--backend electron-backend` enum; non-start controller operations still prefer the pinned runtime executable.

Local evidence is under worktree `.workspace/launch-review/`: before/final runtime JSON, file-access trace, ordinary screenshots, launch logs, host-before/after summaries and clean exit markers. No private host inventory is committed.

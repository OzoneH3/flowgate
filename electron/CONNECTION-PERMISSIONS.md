# Compact connection permissions

Base: `e2f045a172e3af63f6b8ef2209f5eca70c322900`. Isolated backend pairing:
`5c85f1334eb1791151539a1b345f16f1b93ac3fa` (fixture support only; policy unchanged).

## Presentation and behavior

- Activity's immediately rendered setter adds friendly identity/icon and explicit
  Incoming/Outgoing header. Existing frozen target, async authority refresh,
  process/application distinction, immutable rule scope, multi-rule selection,
  conditional Delete and unknown-ACK protections remain in the shared rule service.
- Pending decisions open automatically in one independent, sandboxed window.
  Primary-monitor bottom-right **work area**, not Activity's corner; 520×460 logical
  pixels, clamped on smaller displays. Foreground activation is requested once.
  New arrivals queue without replacing the displayed request. Closing/Escape/Decide
  later sends no decision; that same request does not automatically reopen.
- Compact blue heading and green connection strip follow the supplied official
  [Blocker image](https://netlimiter.com/img/galleries/nl5/nl-fw-ask.png).
  Real icons are used only where installed metadata reliably matches; the native
  test executable has no installed icon and correctly uses the neutral fallback.
  No domain, location, process-only Remember or unsupported Ask control is fabricated.
- Request endpoint, direction, protocol, configured network classification and
  decision scope are visible. Full identity, exact deadline and authoritative
  `scope_previews` text are in Details. Incoming describes peer → program;
  outgoing describes program → peer. Unknown remains unknown.
- Network classification is context, **not permission scope**. Remember creates
  application+peer/service policy for Any network, for one hour or persistent,
  only when offered by the backend. Once means a TCP connection admission lease,
  or fixed 30s exact UDP tuple lease. Subsequent UDP datagrams can match that lease.
- Polling attempt/state changes update controls/results without replacing the
  scope input or open Details. Initial Enter/second Enter cannot decide.
  Expiry/disconnect disables decisions while retaining details; no blind retry.

### Native Wayland placement

Electron `setBounds` requested coordinates but KDE/Wayland kept reporting (16,10).
The bounded KDE adapter executes one temporary compositor script matching **only
this Electron PID + fixed permission-window caption**, assigns numeric geometry,
then unloads/removes its own script. No installed KWin rule, preference, shortcut,
window hook, renderer operation or general command bridge is added. See official
[KWin API](https://develop.kde.org/docs/plasma/kwin/api/). On other compositors,
normal native placement/activation policy may override the requested position.
Actual KDE 6.7.5 compositor report confirmed `(2040,980,520,460)` for the primary
`2560×1440` usable area. Electron still reports virtual coordinates after that
move; its `getBounds` result is not placement proof.

## Focused evidence

Paths below are relative to the Electron worktree; images are local evidence,
not product assets. Comparison preserves native pixels, with labels/padding only.

- `.workspace/decision-compact/comparison.png`: before / official illustrated
  reference (DPI unspecified) / real isolated incoming and outgoing after.
- `.workspace/connection-real-dQva7j/`: real native UDP4 incoming Allow delivery1,
  UDP6 incoming Deny delivery0, UDP4 outgoing Remember Allow1, sibling remembered
  delivery1, TCP4 nonmatching outgoing Deny0. `evidence.json` includes exact event,
  classification and saved rule. Remember has neither process nor zone binding.
  Conditional deletion returned to0 rules; owner independently checked and cleaned.
- Same run: `local-setter.png`, `internet-setter.png`, `detached-setter.png`,
  `incoming-narrow.png`, `activity-narrow.png`. Real private configured zones;
  “Internet” is a fixture policy label, not public connectivity evidence.
- `.workspace/connection-compact-GeXLOP/`: explicitly synthetic automatic-window,
  two-request queue, two Enter presses/no mutation, scope focus and Details survive
  polling, expiry, disconnect, Escape. Native primary-placement followup uses
  compositor journal `FLOWGATE_PROMPT_PLACED_1370910` (geometry above).
- `.workspace/connection-compact-ADvMHX/incoming.png`: original released UI baseline.
- Build/typecheck and18 focused checks passed. Existing receiver/process/UDP
  suites reused; no host lifecycle or firewall operations in this UI increment.

Minimal integration checks:

```sh
npm --prefix electron run build
node --test electron/test/automatic-prompts.test.cjs electron/test/prompt-placement.test.cjs electron/test/connection-presentation.test.cjs electron/test/backend.test.cjs electron/test/notifications.test.cjs electron/test/popup-position.test.cjs
```

Remaining differences: no verified real NetLimiter prompt interaction parity;
FlowGate uses a scope selector rather than unsupported “For a while”; no domain/
location enrichment; compact logical size differs from the illustration; non-KDE
Wayland placement remains compositor-controlled. TCP event helper privileged proof
is still pending; this work never upgrades missing Activity direction evidence.

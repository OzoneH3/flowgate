# Targeted Activity correction — 2026-10-17

Base: `b8678fa1d306e652fb56bf582b07dd856099f1cc`. Frontend ownership was
confirmed before edits. No backend, policy, authentication or accounting changes.
The earlier overall similarity estimate is withdrawn; this review uses measurements
and close-ups, with no replacement score.

## Rule Status: inventory, not effective verdict

A compact **Rule Status / Scoped inventory** column now follows DL and UL rate,
as in the reference. In and Out have separate indicator strips:

- Green check: one or more enabled, unexpired Allow rules.
- Red cross: one or more enabled, unexpired Block rules.
- Gray open circle: disabled rules; clock: expired rules (including disabled ones
  whose expiry has elapsed). The tooltip preserves both action and expired state.
- Dot: no listed rule for that direction; it does **not** mean allowed or blocked.
- Dash: inventory unavailable (disconnect, missing snapshot or unambiguous identity,
  or an observation-only display association). Stale cached rules are not displayed.

Each glyph's accessible label/tooltip gives the exact count and full listed scopes.
The sidebar gives all four counts per direction; expanded identity details show
protocol, remote address, ports, expiry and rule ID. Multiple scoped rules retain
separate Allow/Block indicators, not a blanket verdict. Glyphs have fixed widths so
large counts cannot hide other states; exact counts live in labels and the sidebar.

Association requires the observed application's exact key, revision and UID. No
TypeScript endpoint matching, precedence, traffic-based inference or permission
mutation is introduced. `display_application` is never used for rule authority.
Expiry uses backend-aligned time and respects Go's zero-time permanent sentinel.
Control-only inventory changes update the table even without a new Activity sample.

## Installed icons and security

Main asynchronously indexes desktop entries in XDG application directories and
resolves each entry's literal Exec executable token to a canonical executable path.
The observed executable must match that path. It never executes Exec/TryExec/actions,
uses a shell, or guesses from a display name. Ambiguous associations, wrappers,
missing entries and unresolved binaries get the same neutral fallback. Unidentified
keeps a distinct question-mark icon; socket connectors stay neutral. Wine/Proton
extraction remains deferred.

Icons resolve through the configured KDE icon theme, inherited themes and hicolor,
with 16px directories preferred, then installed pixmaps. PNG and bounded static SVG
are supported. Active/external SVG constructs are rejected; images render in image
context under the existing restrictive CSP. No remote/data/file image permission
was added. Theme icons are read from the installation, not copied into the repository.

The typed `applicationIcons` operation accepts only a bounded list of identity keys
already observed by main. It cannot accept filesystem paths. Responses contain only
opaque, content-hashed `flowgate://app/icons/…` URLs. The protocol serves cached image
bytes, never arbitrary files. Sender/frame validation is unchanged. Cache limits:
4096 current identities, 2048 resolution results, 256 images / 16MiB total,
256KiB per file; PNG dimensions are limited to 1024×1024. Failed image decode restores the neutral fallback. Desktop indexing is once per process; lookups are asynchronous and
cached off the renderer's render path. Restart refreshes changed desktop/theme entries.

## Focused evidence and artifacts

Paths are relative to this **frontend worktree**:

- Prior captures: `.workspace/visual-review/after/` (b8678fa).
- Actual final Wayland: `.workspace/visual-review/target-final/`:
  `main.png`, `installed-icons.png`, `main-narrow.png`, `prompt.png`,
  `rules-{allow,block,disabled}-real.png`, plus metrics and run identity.
- Requested close-ups: `.workspace/visual-target/comparisons/`:
  `header-first-ten.png`, `selected-rule-status.png`, `sidebar.png`.
  `full-main.png` provides context. Each contains reference / before / after.
- `.workspace/visual-target/test.log`: build and 11 focused model/icon/status tests.
- `.workspace/visual-target/wayland-final.log`: actual sandboxed Wayland, real host
  Activity/icons/graph, descending-first sorting, resizing, normal/narrow, preserved
  IPv6 editor input, and isolated API-backed Allow→Block→Disabled inventory changes.
  The existing focused visual harness also passed its Allow/Block/save receiver smoke;
  no broad enforcement/UDP suites were run.
- `.workspace/visual-target/synthetic.log`: explicitly synthetic presentation checks:
  multiple scoped/disabled/expired/permanent rules, control-only updates preserving
  selection, installed prompt icon with disabled read-only actions, controller loss
  clearing stale indicators. No mutation was sent by this fixture. Its screenshot
  paths are printed in the log and identify synthetic content in the application.

The original table/status check above used its disposable namespace controller.
The subsequent permission-aware daemon migration and separate actionable In/Out
columns are recorded in [ACTIVITY-POLICY.md](ACTIVITY-POLICY.md). That increment
also captures the independent root monitor without changing its stored rules.

# Continuation handoff

Continue in `/home/flowgate-user/Apps/flowgate`, branch `milestone/backend`. Verify HEAD and
preserve unrelated work. Read applicable AGENTS.md, README.md, PLAN.md, STATUS.md,
SEMANTICS.md and this handoff; check `.workspace/coordination`. Source
`scripts/go-env.sh` before Go commands. The final report names the commit; this
file avoids a self-referential commit update.

## Current priority and runnable result

**Desktop first; game detection later.** Run `scripts/demo-desktop.sh` in a terminal
in the graphical session. It builds the Qt Widgets client and Go backend, launches
a disposable native UDP lab and opens the GUI outside the namespace. An initial
one-shot datagram prompts automatically. Enter sends another; 2–8 selects another
service port; q/Ctrl+C tears down only this lab. Closing the GUI alone leaves
traffic controlled. Logs remain in the printed `.workspace/desktop-demo-*` folder.

The client can also connect with `.workspace/desktop/flowgate-desktop --socket PATH`.
Use the `.monitor` endpoint for read-only mode. No host enforcement or service
installation is implemented. Recent history is bounded, client-observed and
session-local. Once is default; remembered permission is one hour in memory.

## Reusable evidence and commands

`QT_QPA_PLATFORM=wayland WAYLAND_DISPLAY=wayland-0 scripts/check-desktop.sh`
builds and runs the focused Qt UI-to-real-receiver tests, daemon/policy race tests
and vet. Without graphical access use `QT_QPA_PLATFORM=offscreen`, explicitly
reporting that limitation. The recorded Wayland run tested actual prompt Allow,
keyboard Block, remembered new-source-port delivery, expiry/stale denial, monitor
permissions, client closure and backend loss. Synthetic tests cover long paths,
IPv6 presentation, plain text, error acknowledgement, dedup and reconnect without
replay. See `.workspace/desktop-wayland.log`, `.workspace/desktop-go.log` and the
run directory named in the Qt log for receiver evidence and screenshots.

Sources: `desktop/` (C++ Widgets/QLocalSocket), `scripts/{build,check,demo}-desktop.sh`,
`demo-desktop.py` (outer supervisor), `desktop-lab.py` (namespace fixtures). Backend
changes are additive response metadata and scope descriptions only; no queue,
identity, policy-match or Wine adapter changes. Desktop name is a CMake cache
variable `FLOWGATE_PRODUCT_NAME`; Go CLI uses its existing ldflags name variable.

Historical backend/runtime evidence is preserved in HISTORY.md and WINE.md.
Do not rerun the full Wine/native matrix for presentation-only changes. Existing
Wine 11.19/direct Proton tests are not full Steam/UMU or real-game validation.

## Next smallest useful work

Get user feedback on the running prompt/list workflow. A small next increment is
optional tray/desktop notification access and remembered socket preference, while
preserving the authoritative persistent pending list. More game detection, full
application tree, persistence, bandwidth, packaging and production host enforcement
remain deferred. No missing dependency or additional authorization blocks the
current demo.

Authorization: local edits/builds/focused tests/commits and unprivileged GUI/native
fixtures in disposable namespaces. No host firewall/network/VPN/security/service
changes, package installs, runtime/launcher/existing-prefix edits, real games,
publishing/pushing or additional agents. All generated files stay in `.workspace`.

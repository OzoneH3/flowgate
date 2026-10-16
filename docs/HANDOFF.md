# Continuation handoff

Continue in /home/flowgate-user/Apps/flowgate, branch milestone/backend. Verify HEAD and
preserve unrelated work. Read applicable AGENTS.md, README, PLAN, STATUS, SEMANTICS
and VISUAL. Source scripts/go-env.sh before Go commands. Scratch outputs belong
under .workspace; check its coordination notes.

## Running program

Normal command: `scripts/run-desktop.sh`. This starts a private unprivileged host
observer and the existing native Qt Activity view. No synthetic traffic, firewall
hooks, Wine helpers, service installation or host protection. Close the window or
press Ctrl+C in its terminal to stop its observer. Duplicate launches are independent.
A separately managed `flowgate observe --socket PATH` survives client closure.

The user accepted the original prompt demo. Keep `scripts/demo-desktop.sh` separate:
it enforces the original isolated native test traffic. The new host-control tests
exercise a separate incoming-first profile in disposable veth namespaces. Its GUI can close while enforcement
continues; q/Ctrl+C in its terminal tears down that lab.

## Sources and verification

The bounded collector/cache/state evidence lives in internal/identity/activity*.go;
internal/monitor owns one serial worker and latest snapshot. Host list API returns
activity and always rejects decisions. Existing enforcement matching is preserved.
The Activity widget is part of the existing frontend, not another application.
Shared sockets appear once; Unknown initiation is never inferred from ports.

Focused runner: `QT_QPA_PLATFORM=wayland WAYLAND_DISPLAY=wayland-0 scripts/check-monitor.sh`.
It checks host loopback TCP/UDP v4/v6, SYN-sent/established/listening states, shared
holders, path identities, exit, API mutation denial, Qt interaction and one lab
Allow smoke. Reuse existing accepted desktop and Wine evidence; no full matrix
unless changed behavior warrants it. Offscreen runs must be labelled as such.

STATUS.md indexes host/go/launcher logs; VISUAL.md indexes design captures and
Wayland evidence. Screenshots filter to workspace fixtures, avoiding unrelated
host metadata. No rates, history completeness, real-game or host-protection claims.

## Design coordination and integration

Runnable checkpoint before concurrent design:
883db80dd457591e0fa12af49f4d9ab1e9332020.
Design branch frontend/netlimiter-design at .workspace/worktrees/netlimiter-design.
Complete design consists of 77286d286faa169a81f455426dac933ee13a8b81 followed by
2f375035cb43b2210d8c64d9411d09085d0070d7; the tip alone is not the full design.
The internal designer stopped at the first commit; external session
01a1465b-dadc-7010-91ad-6230a47cda24 then exclusively refined and released ownership.
Root reviews/cherry-picks both and runs focused integration smoke. Final report
names the integrated SHA without a self-referential commit update.

Backend/API/scripts/tests/main docs belong to integration. During concurrent work,
desktop presentation and VISUAL.md belong to design. Coordinate functional changes
explicitly and use the Yacwu relay for the external session. No competing rewrites.

The desktop uses compact Activity and permission views.
Use own Qt components/assets and FlowGate branding: dense tree, compact menus,
toolbar/tabs, right Info/rules panel, lower chart region. Missing measurements and
controls stay explicitly unavailable. Plain-text details, generic icons and other
remaining differences are acknowledged in VISUAL.md; do not claim pixel identity.

## Current increment: host control ready for review

Read HOST-CONTROL.md before any activation. `scripts/evaluate-host.sh` is the exact
opt-in five-minute foreground command; it has NOT been run on the real host.
Normal `scripts/run-desktop.sh` remains read-only. Actual host-start receiver and
Wayland button evidence is indexed in STATUS. Reproduce with
`QT_QPA_PLATFORM=wayland WAYLAND_DISPLAY=wayland-0 scripts/check-host.sh`.
Use the documented host-status/host-stop/host-recover commands independently of Qt.

Remaining work: user-reviewed real-host evaluation, concrete coexistence issues,
then service/desktop authorization integration. Existing mark/queue/VPN setups may
be refused deliberately. No need to redo Wine or accepted native/lab matrices.
No host firewall/network/VPN/security settings, installed runtime/launcher/prefix,
services or system packages were changed. Do not activate host enforcement without
separate explicit authorization or the user's own execution of the reviewed command.

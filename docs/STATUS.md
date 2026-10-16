# Current status

## Current: optional outgoing control and editable saved rules

Normal launch remains `scripts/run-desktop.sh` (read-only). Before starting an
explicit five-minute evaluation choose **Incoming connections** (default) or
**Incoming and outgoing connections**. The active profile is fixed for that run.
No live host enforcement was activated in development.

Prompts now use selectable structured application/executable/PID, direction,
protocol, remote/local address and port, attribution and lifetime fields.
**Create rule…** opens a real editor with backend scope preview. Saved rules support
**Edit**, Enable/Disable/Delete, absolute expiry and persistence. Edits use version
checks, backend validation and SQLite commit before policy publication. Exact
scope duplicates are rejected; overlapping rules use highest priority then
lexicographically smallest ID, without implicit Allow/Block preference.

Both profile queues new native outgoing TCP/UDP and retains initial packets;
unknown/ambiguous ownership fails closed. UDP senders must retain an observable
socket until approval. Approved replies and startup-preserved connections do not
prompt again. Incoming-only leaves outgoing traffic exempt, including saved
outgoing Block rules (shown inactive). See SEMANTICS.md and RULES.md.

Focused evidence: `.workspace/outgoing-check-final.log` (Go race/vet, isolated
receiver suite, actual Wayland Qt 5/5); `.workspace/outgoing-unified-smoke.log`
(existing unified UI 4/4). Receiver checks include TCP/UDP v4/v6 Allow/Block,
one-shot UDP, both-direction replies, startup preservation, remembered new source
ports, executable/destination separation, edit-to-Block, stale/failed edits,
restart and daemon death/recovery. Final receiver rerun: `.workspace/outgoing-receiver-final.log` (fresh per-attempt
reply logs). Additional final evidence: `.workspace/outgoing-last-ui.log` (5/5, corrected
narrow field labels), `.workspace/outgoing-last-editor.log` (expired editing and
read-only API), `.workspace/outgoing-last-bridge.log` (both-profile handoff with
simulated authentication), `.workspace/outgoing-normal-launch.log` (actual read-only
Wayland launch). Actual UI tests cover outgoing and default
incoming creation/editing. Reproduce with `QT_QPA_PLATFORM=wayland
WAYLAND_DISPLAY=wayland-0 scripts/check-outgoing.sh`.

Real-traffic captures: `.workspace/outgoing-ui-1188339/outgoing-real-prompt.png`,
`outgoing-real-editor.png`, `incoming-real-prompt.png`. The adjacent
`synthetic-ipv6-long-path.png` is explicitly a presentation fixture.
Wine/Proton was not changed or retested. Live sudo and host coexistence remain
unverified. No dependencies or SQLite table migration were added; rule documents
now contain an optional edit version (old documents load as version zero).

**Live host Activity monitoring is implemented and read-only.**

```sh
scripts/run-desktop.sh
```

The application shows real visible applications/processes/TCP/UDP sockets, without
synthetic traffic or host enforcement. Close its window or press Ctrl+C in the
launching terminal to stop that instance's observer. Independent launches have
separate private sockets. A separately managed observer stays running when a client
closes. Branch: `milestone/backend`; exact snapshot: `git rev-parse HEAD`.

## Current: one coherent desktop workflow

`scripts/run-desktop.sh` opens one native window with separate Activity and control
connections. Normal launch is read-only. Start 5-minute evaluation launches terminal
sudo, waits for matching-generation active health, and enables existing prompts
and rules in the same window. Stop/status/recovery use authenticated terminal
commands; selected-user policy permissions were not widened. Activity continues
when control fails, stops or times out. Closing Qt leaves the evaluation deadline
intact. No host activation was performed during this increment.

Saved rules now show application/action/direction/protocol/endpoints/absolute
expiry/state. Enable/Disable/Delete preserve selection, scope and expiry. Offline
rule rows are explicitly a last-received snapshot. Pending count, native tray and
bounded notifications support minimized use; notifications never Allow traffic.

The evaluator uses a private root-owned executable snapshot for controller and
watchdog, with safe existing-directory validation. The unprivileged terminal bridge
uses bounded private result files; it never collects credentials or adds sudoers.
See HOST-CONTROL.md for the user journey and independent commands.

Actual Wayland tests: `.workspace/unified-notification-final.log`; terminal bridge:
`.workspace/unified-bridge-final.log`; focused Go/race/vet:
`.workspace/unified-go-final.log`; host-monitor smoke:
`.workspace/unified-monitor-smoke.log`; normal launch: `.workspace/unified-launch.log`.
Inspected captures: `.workspace/unified-1160667/unified-activity.png` and
`.workspace/unified-1160667/unified-rules.png`. The UI logs print exact screenshot paths.
Authentication is simulated in a narrow seam; controller start/Stop, UDP receiver
Allow/Block, rule re-enable/unchanged expiry, real preflight refusal, timeout/loss,
and closure under the original deadline use the real namespace backend. Native tray
and message support were available; OS notification click dispatch is tested via Qt.
A final smoke caught stale-notification state interfering with the explicit tray
Open action; those paths are now separate and were rechecked.
Real sudo authentication and live-host coexistence remain untested intentionally.

## Previous host-control milestone (reusable evidence)

Incoming-first host-mode code, saved one-hour/persistent SQLite rules, Rules
Disable/Delete, enforcement health, scoped Stop/recovery and a detached five-minute
evaluation watchdog are implemented. **Real host enforcement has not been activated.**
Review `docs/HOST-CONTROL.md` before the explicit `scripts/evaluate-host.sh` command.
The normal monitor command above remains read-only.

Focused receiver checks use the actual host-start path on an isolated veth topology:
IPv4/IPv6 TCP Allow/Block; one-shot UDP Allow/Block; outbound TCP/UDP replies;
ICMP/ICMPv6; pre-existing TCP; persistence and absolute expiry across restart;
disable/delete; bounded no-listener attempts; duplicate/conflicting startup;
structural degradation; daemon SIGKILL; repeated recovery; scoped automatic stop,
including the independent watchdog after daemon death. Unrelated nft objects survive.

Actual Wayland Qt checks run as UID1000 outside that namespace: persistent Allow
releases the held datagram, a new source port matches, Disable restores Ask, Block
delivers nothing, Delete removes the rule, and disconnect disables mutations.
Focused Go race tests and vet cover the changed policy/API/storage/queue paths.
Evidence: `.workspace/host-verification-final.log`, `.workspace/host-suite-final.log`,
`.workspace/host-final-ui.log`, `.workspace/host-go-tests.log`,
`.workspace/host-bootstrap.log`, `.workspace/host-lab-regression.log`.
Inspected Wayland captures: `.workspace/host-ui-1113497/host-prompt.png` and
`.workspace/host-ui-1113497/host-rules.png`. Final test logs name their
own isolated run and capture directories. Historical startup failures (unmapped
namespace ancestors) were fixed without relaxing real-host privileged paths.

Limits: conservative VPN/mark/queue conflict refusals; snapshot cutover window;
queued extension headers/fragments unsupported; other-UID services can time out;
Full DHCP lease negotiation and real-host coexistence unverified. API control mode shows decisions;
Activity now shares the same window through an independent read-only connection. Game detection unchanged.

## Available now

- Existing Qt desktop with compact Activity tree, name/path/PID/endpoint search,
  sorting, active/listening filters, expand/collapse, copy actions and full details.
- Applications grouped by supported key/revision; PID/start process identities;
  shared sockets counted once, unknown sockets individually shown.
- TCP listening/connecting/established/closing states, bound versus connected UDP,
  bracketed IPv6 endpoints and diagnosed link-local interface scope. Initiation
  remains Unknown, not inferred from port numbers.
- Partial visibility, timestamps and collection cost; errors/overdue collection
  and disconnect never present a previous successful snapshot as live.
- Observation API always read-only, including direct mutation attempts. Policy
  controls require the separate authenticated controller. Observation creates no Allow/Block decision events.
- Serial periodic snapshots, default two-second delay after completion; bounded
  result/cache sizes, no GUI-triggered collection, Wine helpers or host hooks.
- Unprivileged launcher with private per-instance paths and scoped cleanup; no
  installed service, autostart or broad permission requirement.

The **user-accepted prompt demo** remains `scripts/demo-desktop.sh`. Enforcement is
only inside its disposable namespace. Closing that window does not stop the lab;
q/Ctrl+C in its terminal performs teardown. Existing native/Wine evidence is reused.

## Focused evidence

CachyOS x86-64, Qt 6.12.0, actual Wayland:

- Controlled IPv4/IPv6 listeners correctly identify executable/PID/local endpoint.
  Real TCP exchange appears Established; SYN-sent is observed using an unaccepted
  loopback backlog, without firewall changes. UDP bound/connected labels verified.
- Same basename at different paths yields distinct keys. An inherited listener
  reports both visible holders in one row. Process exit removes current ownership.
  All initiation directions remain Unknown. Direct API Allow is rejected.
- Qt checks passed search, filters, sorting, stable selection, copy, empty results,
  process exit, backend loss and fresh reconnect. One existing prompt Allow-to-
  receiver check passed after shared UI/API changes; no full matrix rerun.
- Focused race tests and vet passed. Two normal launchers had distinct sockets and
  generations; stopping one left the other live. GUI exit stopped its own observer.
- In a local 500 ms interval test: approximately 9–10 ms per collection, 0.05 CPU
  seconds over three wall seconds, 115 visible sockets in that sample. This is
  measured local behavior, not a throughput or zero-overhead claim.

Evidence: `.workspace/monitor-final.log`, `.workspace/monitor-host-final.log`,
`.workspace/monitor-go-final.log`, `.workspace/monitor-launcher.log`; fixture JSON
under the `.workspace/monitor-test-*` path printed by the runner. Qt captures under
`.workspace/monitor-ui-*/host-monitor.png` filter to owned fixtures to avoid unrelated
process metadata. Final design integration evidence is recorded separately;
VISUAL.md describes the desktop layout and its verification.

## Integrated visual checkpoint

Both design commits (77286d2 layout and 2f37503 refinement) were reviewed and
cherry-picked after the runnable host checkpoint and backend hardening, without
conflicts. The final rebuild passed an actual Wayland Activity smoke (3/3) and
isolated prompt Allow-to-receiver smoke (3/3). Broader recorded Wayland design,
monitor and decision suites were reused; no Wine tests were repeated.

Evidence: `.workspace/monitor-integration-build.log`,
`.workspace/monitor-integration-smoke.log`, `.workspace/host-monitor.png`.
The inspected capture uses real controlled fixture activity, not fabricated data.
See VISUAL.md for acknowledged plain-text details, generic icons, unavailable
measurements/rule editor and other differences from the NetLimiter 5 reference.

## Visibility and scope limits

About 340 process descriptor directories were inaccessible in the recorded run;
partial visibility is reported. Current network namespace, TCP/UDP and process-
leader descriptor directories only: no other namespace traversal, Unix sockets,
private per-thread FD census or packet history. Short-lived activity can be missed.
Snapshots are non-atomic; visible holders do not prove exclusive ownership or
identify a remote program. Useful partial monitoring requires no root request.

No measured rates/totals, persistent event history or production service. Normal
monitoring provides no host protection; explicit bounded control is described above. NetLimiter 5 is the authoritative visual target; remaining differences
are documented rather than claimed exact. Game detection remains deferred and its
existing optional adapter preserved. Other distributions, arm64, real games,
full launcher/container integration and VPN coexistence remain unverified.
No host firewall/network/VPN/security/service configuration, installed runtime,
launcher or existing-prefix changes were made.

## Checkpoints and next step

Runnable pre-design checkpoint: `883db80dd457591e0fa12af49f4d9ab1e9332020`.
Design worktree: `.workspace/worktrees/netlimiter-design`, branch
`frontend/netlimiter-design`. Integration owns backend/API/scripts/tests; design
owns presentation. The final report names the integrated commit.

Next: user review/execution of the desktop evaluation workflow; then address
observed coexistence issues before service integration. No hidden activation action.
Continue game detection later.

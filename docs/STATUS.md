# Current status

**Live host Activity monitoring is implemented and read-only.**

```sh
scripts/run-desktop.sh
```

The application shows real visible applications/processes/TCP/UDP sockets, without
synthetic traffic or host enforcement. Close its window or press Ctrl+C in the
launching terminal to stop that instance's observer. Independent launches have
separate private sockets. A separately managed observer stays running when a client
closes. Branch: `milestone/backend`; exact snapshot: `git rev-parse HEAD`.

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
- Host API always read-only, including direct mutation attempts. Host GUI omits
  policy controls. Observation creates no Allow/Block decision events.
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

No measured rates/totals, persistent rules/history, production service or host
protection. NetLimiter 5 is the authoritative visual target; remaining differences
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

Next: user feedback on real Activity and documented visual gaps. Host enforcement
needs a separately authorized coexistence/recovery/validation milestone. There is
no hidden enable-protection action. Continue game detection later.

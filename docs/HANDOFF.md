# Continuation handoff

Continue in `/home/flowgate-user/Apps/flowgate`, branch `milestone/backend`. Verify HEAD and
preserve unrelated work. Read applicable AGENTS.md, PLAN.md, STATUS.md, SEMANTICS.md,
WINE.md and README.md; check `.workspace/coordination`. Source `scripts/go-env.sh`
before Go commands. No additional agents without authorization. The final report
names the commit; this file avoids a self-referential SHA update.

## Completed increment

The existing public owner-table adapter now has read-only `runtime-discover` and
explicit `serve-lab --attach-prefixes` integration. It attaches to already-running
workspace prefixes using trusted runtime-bin selection, a broker-build allowlist,
caller UID checks, pinned process generations and verified helper Unix peers.
Server creation is disabled for attachment. Up to four separate observers are
supported. No automatic retry, privileged-root helper or weaker fallback.

Both Wine 11.19 and direct dwproton-11.0-4 / Wine 11.0 passed:

- Actual WSADuplicateSocket preparation/construction/close lifecycle. The recipient
  is visible already at preparation. Shared receivers get no data; stale retained
  approvals are rejected before recipient construction.
- Actual numeric handle reuse, with a changed kernel socket fingerprint.
- Late attachment to two prefixes, including same executable and reused service
  port not inheriting another prefix's permission.
- Server death/restart, stale denial and explicit reattachment/new generation.
- IPv6 ordinary TCP and one-shot UDP Allow/Block, reversed; dual-stack wildcard
  over both families; mapped IPv6 binds; separate IPv6-only/IPv4 listeners.
- Accepted TCP socket transfer continues the already-approved connection.

The product contract is **connection initiation**, not continuous TCP ownership
reauthorization. Existing rule deletion/replacement/expiry does not disconnect
established approved TCP. UDP retains ownership/flow checks. No revocation behavior
was weakened or silently added. Scoped link-local Wine policy remains unsupported.

Reproduce with `scripts/check-runtime.sh` and repeat with FLOWGATE_TEST_PROTON and
FLOWGATE_TEST_STEAM set as shown in WINE.md. The script builds and runs sequentially.
Evidence is indexed in STATUS.md: runtime-final logs, structured duplication/
attachment/IPv6 JSON, race/vet and native socket-matching regression. Reuse older
unchanged incoming-scope, queue-retention and outgoing evidence. Attached-helper exit is directly exercised; protocol mismatch paths have focused tests.

## Next smallest step toward native prompts

Implement a minimal unprivileged desktop notification/prompt client using the
existing peer-authenticated pending/decide Unix API, initially against the lab.
Show application, endpoints, initiation direction, attribution limits and exact
remembered scope; keep pending state/timeouts in the daemon. Preserve stale answer
rejection and separate monitor versus decision permissions. Do not combine this
with production host installation or broad rule editing.

Future integration work is explicit: dynamic session discovery/attachment outside
workspace test prefixes, validation of further runtime builds, link-local interface
mapping, full UMU/Steam/container integration and real games. `lwp` remains unchanged;
its original prefix override and dwproton selection were reread. Direct runtime
success is not full launcher integration. No need to restart attribution research
or make per-game isolation wrappers mandatory.

Authorization remains local edits/builds/tests/commits, read-only diagnostics and
source inspection, and installed runtimes with workspace-only fixtures/prefixes in
disposable namespaces. No host firewall/network/VPN/security/service/package
changes, runtime updates, existing-prefix/launcher edits, real games, pushes or
publishing. All generated output belongs under `.workspace`. No additional
privileged operation is currently required.

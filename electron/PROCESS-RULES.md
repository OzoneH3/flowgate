# Process-scoped Activity rules

This increment follows the actual NetLimiter5.3.28 process quick-set evidence in
[ACTIVITY-RULES.md](ACTIVITY-RULES.md). Setting Process11592 In Allow left its parent
application Not set. Saved captures are reused; no Windows settings or rules were
changed during this increment. Official [Info View](https://netlimiter.com/docs/user-gui-client/child-windows/info-view)
and [Rules](https://netlimiter.com/docs/basic-concepts/rules) place quick setters in
the selected-item context. FlowGate's matching and lifetime semantics remain its own.

## Selection and review

- Application: incoming/outgoing setters target all instances of the exact
  application/revision/UID. Application summaries exclude process rules.
- Process: **This process** is the default; **Application · all instances** is an
  explicit alternative. Own rules and application fallback are separate matrix
  rows and rule groups. Backend classification and precedence are displayed;
  Electron does not evaluate filters or select an effective winner.
- Connection: its uniquely associated holder has the same process/app context;
  initiation direction stays independent of byte flow. Protocol and endpoint scope
  are explicit before preview. Shared/unsupported contexts explain their limitation.
- Quick changes preserve one exact rule's immutable target, endpoints and absolute
  expiry. Advanced editing stays available in Activity. Process lifetime is **this
  daemon session**, optionally bounded by one hour; it ends on exit/session end,
  never a Persistent grant. All saves require the existing authoritative review.

## Contract and lifecycle

Backend capability `process-instance-rules-v1` extends existing observed preview/save,
versioned edit and conditional Delete. [Backend semantics](../docs/PROCESS-RULES.md)
cover identity, precedence and receipt behavior. The bridge retains schema3's entire
`filter.process`, including opaque instance ID, session/boot identity, PID/start ticks,
UID, namespaces and executable/revision. Decimal start ticks and rule-ref versions
remain exact strings. A provisional policy association with empty instance ID is
metadata only; full rule bindings require the canonical instance ID.

The main process freezes a canonical target from the observed preview, checks it on
later previews and acknowledgements/reconciliation, and refuses capability loss or
an unavailable observed instance. Edits echo the full target, never schema2 widening.
No PID/name match authorizes a mutation. Backend performs live native/pidfd checks.
Matching process rules precede application fallback; endpoint matching, priorities
and default evaluation stay entirely in Go. Stored Block is not active protection.

After exit, only the selected display context is retained (one bounded item, cleared
on selection/session change); no process inventory/history is invented. Backend
inactive reasons remain visible. Stale draft fields/focus are preserved, Preview/Save
are disabled and no target is rebound. Conditional Delete is still available.
Inactive disabling is supported by the backend but this UI deliberately offers
inspection/Delete only. Reused PIDs, a new daemon session or a sibling instance do
not inherit the prior process rule. Same-executable exec retaining native identity
is not treated as a new instance; no exec-epoch tracing is claimed.

Older daemons explicitly retain application-wide controls, without a process choice.
Once the new capability is recognized, failure cannot trigger an application fallback.
No new privileged launcher, observer, polling loop or enforcement operation is added.

## Verification and local evidence

Integrated starting base: `e2f3f29b826246aafe02703f1ac584834a9aabeb`.
Released backend pairing and real evidence are recorded below after verification.

Synthetic fixtures are explicitly labelled and have no measured traffic/verdicts:
process/app grouping, default scope, normal/narrow layout, PID/session mismatch,
shared identity refusal, exact binding, capability/exit save refusal and lost-ACK
reconciliation. Existing application-only presentation verifies older-daemon fallback.
Backend owns receiver enforcement evidence; the UI journey validates actual API
mutations and process-lifecycle presentation separately.

Focused runners:

```sh
npm --prefix electron run build
node --test electron/test/process-policy.test.cjs electron/test/activity-selection.test.cjs electron/test/policy.test.cjs electron/test/presentation.test.cjs electron/test/observed-rules.test.cjs electron/test/delete.test.cjs
node electron/test/process-presentation.mjs
node electron/test/presentation.mjs
```

Actual held fixture runner `electron/test/process-rules-workflow.mjs` requires an
externally owned disposable workspace endpoint and explicit owner-provided target ID
and exit command. It never starts/stops a daemon. Only the UI drives mutations while
attached; backend cleans up after DONE. Never point it at the host database.

Normal launch (old host backend retains labelled application-only behavior):

```sh
scripts/run-electron.sh --daemon /run/flowgate-api/daemon.sock
```

Remaining deliberate differences from NetLimiter: reviewed Preview/Save rather than
immediate action-on-click, session-bound native identity, no process-persistent grants,
and no unsupported Ask/Limit/Priority/Quota controls. These are not visual substitutes
for missing features.

### Completed exact-release results

UI worktree fast-forwarded to backend **60d35a366ae0104f9131f36916ff4172ef71ce71**
without touching local Electron edits. Released binary `.workspace/flowgate-process`
SHA256882556c5c977765b678c4dd09521bef6dc596e4532f6af223fcca073ea4ebd05.
Actual released fixture generation93be388df215b1740cb358a8c82d5563:

- Native same-executable alpha21/beta27. First process Allow did not appear on
  sibling or parent app. Explicit application Block then appeared independently
  as fallback. Exact process edit/disable/re-enable/delete preserved app identity
  and version; recreated process Allow stayed bound to alpha only.
- Exit alpha through the owner-provided command: authoritative rule state inactive,
  retained selected display/draft, input unchanged and Preview/Save disabled.
  Surviving beta showed only application fallback, no inherited alpha rule.
- Real sandboxed Wayland normal1280×656/narrow860×600 inspected. Polls preserved
  selected row, editor input and text range. GUI exit preserved the independently
  owned monitor generation/stopped state. Backend owner accepted DONE for cleanup.
- Backend owner separately verified actual receiver TCP/UDP IPv4/IPv6 in both
  initiation directions, override/sibling/fallback and lifecycle. This was reused,
  not claimed from UI screenshots; host enforcement never ran.
- Build/typecheck,23focused checks, new synthetic process normal/narrow/exit and
  older-backend presentation checks passed. Read-only and lost-response safeguards
  reused the focused bridge evidence. Actual PID reuse is not claimed; backend
  pidfd/session tests and labelled identity mismatch cases cover that boundary.

Evidence under UI worktree `.workspace/process-rules-real-rbmfwl/`:
`process-preview.png`, `process-with-application-normal.png`,
`process-exited-normal.png`, `process-exited-narrow.png`, `result.json`.
Additional real narrow surviving sibling: `.workspace/process-rules/real-sibling-fallback-narrow.png`.
Synthetic only: `.workspace/pp-nu6xJ9/` (filenames explicitly synthetic).
Logs `.workspace/process-rules/{real,focused,synthetic-final,compatibility}.log`.

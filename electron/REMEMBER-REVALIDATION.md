# Ended Remember requests — 2026-10-19

## Incident evidence and limits

Reported Claude PID542716/start2875534 UID1000, Out TCP
172.30.42.123:53130 →160.79.104.10:443, deadline20:04:02+02.
The preserved normal-launch log confirms **decision:preview**, not a successful
Save or lost acknowledgement. Its generic `identity_changed` message did not
record the failed field. UI offered Refresh and the original countdown afterward.

Evidence preserved in main `.workspace/remember-claude-incident/`: original log
and launch JSON/hash, user-supplied request labelled as such, targeted current
proc/socket evidence, and an earlier application observation/hash. At20:07 the
same PID/start/UID/executable and namespaces were present; executable device,
inode, size, mtime/ctime matched the18:20 observation. The original53130 socket
was then absent. This does **not** establish its state at the failed preview or
exclude a transient owner/visibility race. No historical failed recheck was
available to this unprivileged session. Do not claim an executable change or an
exact historical socket-cookie mismatch. Saved root Decision Log/export is still
needed to resolve that historical field; the old daemon did not log preview
revalidation differences.

## Demonstrated defects / changes

* Strict fingerprint bundled PID/start/UID/namespaces/executable revision and
  socket inode/cookie. Preview collapsed missing attribution and every mismatch
  into one error and did not finalize the event. Refresh therefore remained
  offered for a request that could not pass that binding again.
* New `Event.revalidation` and final Decision Log record carry exact changed
  fields, separate bounded diagnostic process rechecks, and timestamp. Socket
  absence/replacement is not called an executable change. Deadline expiration
  during revalidation is separately `stale_decision`. Existing strict ownership,
  fingerprint, principal and revision predicates remain required.
* Failed preview finalizes the original event; no rule or held-packet grant.
  Frontend fences explicit terminal refusals by generation/event even against an
  older daemon and stale polls. Paired Allow/Deny preview responses cannot erase
  a precise failure with a later generic stale response. Recoverable policy/zone
  review failures remain refreshable; Remember choices remain intact.
* A bounded five-minute/64-event display retains recorded details. No actionable
  old countdown or Refresh. Full backend reason is under Revalidation details.
  No submitted decision or success is invented.
* Explicit future-application action opens the **main** editor, never Decide.
  Main finds a fresh single-holder Activity association with the same immutable
  app key/revision/executable/UID, with current backend policy association. The
  existing observed preview/save independently validates it. New PID is allowed
  for application scope; replacement revision/UID/shared identity is not.
  Process selection requires an explicitly labelled switch to application scope.
  No suitable fresh identity => clear unavailable message, no filename/display
  authority workaround. Offline-file-only identity creation is not added.
  Save acknowledgement explicitly says future connections, original not allowed.
* Remember controls now visibly obey the popup's initial input-readiness guard.

## Focused evidence

* Build/typecheck,40 focused Electron tests; deterministic terminal/stale poll,
  paired response order, recoverable conflict, fresh sibling vs replacement
  revision/UID/shared identity, existing lost-ACK receipt guards.
* Targeted Go identity/Remember race tests and vet. Full daemon run exposed an
  existing long Unix test-socket path (`protection-readonly`) in this nested
  worktree; it is not reported as a full-package pass. Targeted relevant tests
  pass. No unrelated test-path/security workaround was made.
* Real private TCP/API/receiver run: worktree `.workspace/r2/result.json` and
  `verification.log`, final0rules+CLEANED. Native timeout closes original socket
  while process stays unchanged; diagnostic says socket inode/cookie. Old request
  cannot Once/Remember or release a stale packet. Explicit fresh app rule admits
  later retry; different executable does not inherit it. Real exec retains
  PID/start but reports executable revision change. Valid live application-only
  Any-zone Remember commits and delivers despite unavailable zone membership.
  Final Decision Log DB retains structured revalidation (export copied in main
  evidence folder). The fixture has no TLS layer; it reproduces held TCP connect,
  timeout and retry before application TLS could begin.
* Real sandboxed Wayland GUI: `.workspace/remember-ui-g5yvfR/result.json`, then
  compact-diagnostic/layout followup `.workspace/remember-ui-X8m3nu/result.json`.
  Ended card preserves identity/Remember, disables decisions/Refresh; Enter on
  container sends no decision. Explicit main future-rule editor previews/saves;
  old request not allowed, later retry receiver+1, conditional cleanup0.
  Subsequent text-only cleanup puts the same lifecycle summary on the visible
  expiry line and removes its repeated paragraph; no mutation logic changed.
  Failed first GUI attempt caught the Remember readiness affordance mismatch;
  no policy mutation occurred. All owned windows/fixtures cleaned.
* Earlier failed native harness used a112-byte Unix socket name; second attempt
  initially mistook an Activity sample not yet containing the new socket for
  closure. Corrected harness joins the native connect job and uses a short owned
  path; those failed attempts are not passed acceptance.

No Claude rule was changed. No host protection, daemon or collectors were
started/restarted/toggled. No host deployment. KWin remember-position script was
reported disabled by user during this work; placement acceptance is owned by
popup partner on released5a4ce96, not proof of historical interference.

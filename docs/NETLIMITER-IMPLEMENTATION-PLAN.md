# NetLimiter gap implementation plan

23 October 2026. Based on the [functionality audit](NETLIMITER-FUNCTIONAL-AUDIT.md).
Status: sequence and first accounting scope jointly reviewed with the FlowGate
backend session. The first slice is implemented and has passed source, isolated
backend and native UI integration checks; see [observed usage](OBSERVED-USAGE.md) for its API, limits and
evidence. It has not been deployed by this work.

## Delivery sequence

| Workstream | First useful outcome | Dependency / completion gate |
| --- | --- | --- |
| Observed accounting | Accumulated observed bytes remain visible after sockets close. | Backend owns deduplicated deltas, identity, epochs and coverage; separate TCP/UDP definitions. |
| Existing TCP control | A precisely targeted effective Deny can stop or terminate an established connection, with an explicit outcome. | Isolated kernel proof and identity/reuse/concurrency review before changing Deny semantics. |
| Directional defaults | Independently configured incoming/outgoing fallback for supported attributed traffic. | Versioned durable configuration; evaluator and explanations agree; existing behavior preserved on migration. |
| Custom Blocker weights | Explicit rule precedence controls with accurate previews. | Versioned rule schema and collision/migration policy; separate from bandwidth priority. |
| Reusable filters | Named, versioned combinations of already-supported predicates. | Preview affected rules and preserve existing identity/scopes; domain evidence is a later independent design. |
| Durable statistics/history | Usage queries survive daemon restart; separate connection lifecycle records. | Transactional accounting checkpoints, bounded retention, privacy and explicit gaps. |
| Bandwidth limits and QoS | Measured per-scope upload/download limits and allocation. | Separate enforcement design and throughput/latency tests; not implemented by verdict Priority. |
| Quotas and schedules | Usage thresholds and timed policy transitions. | Reliable accounting for quotas; atomic policy revisions, clock/restart semantics and recovery for automation. |

Accounting and established TCP control are separate workstreams. Their foundation
work can proceed concurrently after file ownership is assigned. Shaping does not
need to wait for a historical statistics UI, but quotas must not rely on the
current live-socket totals. No dates are promised until the backend design and
first experiments establish scope.

## Agreed first implementation slice: observed accounting

`internal/identity/traffic.go` currently forgets missing sockets. The renderer
aggregates currently visible observations. Simply retaining rows or summing UI
rates would not establish correct cumulative per-application usage.

The agreed bounded first slice is an in-memory backend accumulator and a
capability-gated read-only API. It preserves measured deltas across closure and
labels them **observed bytes since this observation interval began**. Restart
persistence follows once checkpoint and replay semantics are implemented. Reset,
persistence, quotas and TCP revocation are excluded from this initial slice.

Required contract:

- A complete observation has a source definition, observation epoch, collector
  and socket incarnations, and a per-source sequence. A backend snapshot reducer
  consumes observations independently of GUI polling. Repeated samples never add
  bytes twice. Backward counters, resets and coverage loss create explicit gaps
  or a new baseline.
- Keep observed bytes when a socket disappears. A missing final sample or an
  entirely missed short-lived socket remains incomplete coverage.
- Associate each delta with verified application/UID/runtime/prefix identity.
  Shared or changing ownership goes to an explicit unresolved/shared interval;
  it is not charged to every owner or transferred as lifetime usage to a new one.
  Two matching ownership snapshots do not prove continuous ownership between
  them; the API exposes sampled-attribution uncertainty.
- Keep TCP transport payload and UDP API-return bytes separate. Neither becomes
  a remote-delivery or billable wire-byte claim. Collector-disabled means
  unavailable, not zero.
- Bound state and query size. Define frozen-entry/overflow behavior without
  silently evicting known totals. Overflow and omitted records are visible.
  Exact byte counts use decimal strings to survive JavaScript integer limits.
- Project history by authenticated principal even after the original process
  exits. Global and unattributed totals are administrator-only; an ordinary user
  cannot infer foreign totals or reset machine history.
- In a later slice, define reset scope and an atomic epoch boundary before exposing Reset. A
  retry after unknown acknowledgement must not reset twice.
- Later persisted accounting must atomically checkpoint totals and consumption state,
  or otherwise prove no double counting on crash/replay. Data loss windows must
  remain visible. Storage failure must not silently alter firewall verdicts.

The UI shows live rate separately from accumulated observations, interval start,
source and incomplete coverage. Recorded usage remains queryable for inactive
programs. Older daemons retain their current UI; no frontend-generated substitute
is presented as backend accounting.

Acceptance combines deterministic closure/duplicate/reset/reuse/owner-change and
bounds tests with isolated two-application TCP/UDP IPv4/IPv6 fixtures. Verify
conservation against actual observed counter deltas, not equality with receiver
payload. Verify ordinary-user privacy, separate UIDs and synthetic Wine identity
prefixes. Wine runtime integration claims additionally require real supported
runtime tests. Native UI and persistence acceptance are separate stages.

The agreed v1 contract uses a random ledger epoch, exact decimal sequence and
counters, authenticated user/machine projection, 1,024 retained entries and 2,048
socket baselines. Capacity exhaustion freezes accumulation at an observation
boundary without evicting totals. See the [implemented contract](OBSERVED-USAGE.md).

## Established TCP control: prove the operation first

`internal/hostfirewall/firewall.go` accepts already-marked established TCP.
`conntrack.go` binds masked updates to connection tuple, kernel ID and zone and
preserves unrelated bits. Current policy explanations cover new admissions.

Before implementing a public control, the backend design must resolve:

1. How an admitted connection remains tied to verified executable/UID/prefix and
   process/connection generation, including descriptor sharing, NAT, tuple reuse,
   namespace differences and connections preserved during activation.
2. Whether the operation blocks further packets, terminates the local socket,
   or both. These are distinct outcomes. Removing a conntrack entry alone does
   not establish either claim without a tested enforcement path.
3. How current effective policy, rule revision and connection ownership are
   revalidated. A matching Deny that loses precedence must not revoke a permitted
   connection. Concurrent admissions cannot fall through a publication gap.
4. How partial failure, vanished targets, Stop/restart and retries are reported.
   Never use a global conntrack flush, foreign mark reset or process kill as an
   application-specific implementation shortcut.

The first proof uses two continuously transmitting synthetic applications in a
disposable namespace. Change the target's effective policy, establish the claimed
receiver/socket outcome, and show the unrelated application continues. Cover both
directions and IP families, identity/rule races, reconnection and partial failure.
Unsupported shared or runtime scopes remain explicit.

The UI reports **rule saved** separately from **connection operation completed**,
including partial, unsupported and unknown results. Existing Deny behavior remains
documented until the new capability has passed its acceptance gates.

## Policy and filter migration requirements

Directional fallback changes apply only after explicit rules and current safety
boundaries: unverifiable attribution does not become Allow, same-host behavior is
not silently changed, and an incoming-only protection profile does not acquire
outgoing enforcement merely because a setting exists. Configuration changes must
settle pending requests under one coherent policy revision and appear identically
in evaluation, preview and explanation.

This is a smaller independent implementation option, not an accounting
prerequisite. The backend identified a critical interaction: `engine.go` handles
cached Once decisions specially when the base verdict is Ask and applies a
separate temporary-lease overlay. Replacing the final `default-ask` return alone
would therefore be incorrect. Define existing grant precedence and pending/held
packet re-evaluation explicitly. Legacy installations start at Ask/Ask; malformed
settings fail visibly. Reviewed administrator changes persist before publication,
and backup, rollback and downgrade must preserve or explicitly refuse configured
non-default policy.

Custom weights require an explicit relationship with fixed target weights,
existing numeric Priority and newest exact-scope rules. Keep legacy behavior for
unmigrated records. Reusable filters need versioned references, impact previews
and deletion semantics before adding general expressions or domain predicates.

## Coordination and verification

Backend has accepted ownership of the accounting reducer, complete-observation
integration and read-only API. UI owns contract review and capability-gated
presentation. Current native verification and diagnostic tasks retain their
existing owners until explicitly reassigned. Accounting does not change policy
authority or grant permissions.

Each increment records source tests, isolated integration, native UI acceptance
where relevant, and installed-release verification separately. A source merge is
not installed verification. This planning round makes no deployment or host
instrumentation changes.

The scope-widening and expiry-wording defects from the audit were already fixed
in source (`fb92566`, `3da9427`); they are not new implementation tasks here.

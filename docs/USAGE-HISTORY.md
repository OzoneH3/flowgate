# Durable observed usage history

Electron's **Observed usage → Durable history** view reads an optional private
archive. The current observation interval remains a separate in-memory view.
History is disabled by default. An authenticated administrator on the writable
primary endpoint can enable recording and choose 1, 7 or 30 days of retention.
The consent control describes the machine-wide privacy scope before saving.
These settings never change firewall permissions or enable a traffic collector.

## Meaning and restart boundaries

The production daemon checkpoints its existing accounting ledger independently
of API polling, normally every 30 seconds. The first checkpoint after enabling
or restarting establishes a baseline. It does not backfill earlier observations,
restore live socket baselines or charge traffic from a disabled interval.
Previously committed records remain readable across daemon restarts. Each ledger
incarnation and daemon generation remains a distinct recording interval.

Positive cumulative deltas and their watermark commit in one SQLite transaction.
Duplicate or out-of-order samples add nothing. Regressed counters are refused
without lowering the watermark. Failed commits do not advance it. A crash may
lose uncommitted observations; there is no fixed loss-time guarantee. A bucket
records the checkpoint end time, not the exact time of every byte in its delta.

All history is partial. Short connections, closure tails, missing collector
samples and ownership gaps remain unmeasured. Blank bins do not mean zero
traffic. TCP transport payload includes upload retransmissions; UDP uses the
optional collector's API-return definition. Sources remain separate. Neither is
remote delivery, interface billing, current speed, quota enforcement or bandwidth
shaping. Historical names and identities confer no permission authority.

Storage uses five-minute buckets. Queries rebin with exact integer addition:
five minutes for 1 hour/24 hours, 30 minutes for 7 days, and 2 hours for 30 days.
The response reports its resolution and recording intervals. Missing bins stay
absent. Saturation is explicit, and counters use decimal strings without floating
point rounding. The graph includes inactive recorded identities rather than
joining them to a newly observed owner.

## Privacy, retention and capacity

The production `serve` command uses `usage-history.db` beside `rules.db`. The
parent directory must already be private, owned and secure; the database is
mode 0600 with one writer. It stores application names, keys, revisions, kinds,
user IDs, source, recording intervals and sampled totals. It stores no executable
paths, command lines, socket endpoints or packet contents. Opt-in is machine-wide,
so administrators should consider other users before enabling it.

Authenticated ordinary users receive only their own identities and aggregates;
filtering occurs before aggregation. Administrator-only unattributed observations
are a separate explicit selection. Global storage diagnostics and last-commit
time are omitted from ordinary-user replies. Read-only companions can query but
cannot change settings. Developer observer entry points do not persist history.

Limits are 1,024 application/source identities plus two unattributed source
entries, 128 recording intervals, and 50,000 bucket rows. The database is bounded
to 32 MiB, with a bounded rollback journal of at most 34 MiB including headers
(66 MiB combined working-file ceiling); WAL is not used. Checkpoint identity state
is separately bounded to 1,026 entries and 2 MiB. Queries return at most 512 points.
Capacity or database failure pauses recording with a diagnostic; protection and
the in-memory ledger continue. There is no silent eviction or reassignment.
Expired rows and unreferenced catalog entries are pruned; recording can resume
when retention frees capacity. Shortening retention deletes older records.
Disabling recording retains existing history until it expires. There is no Reset
or export operation in this increment.

## API and settings acknowledgement

Capability `usage-history-v1` advertises:

- `usage-history`: requires the current `generation` and `history_query` with
  `range` (`1h`, `24h`, `7d`, `30d`) and a single supported `source`. Optional
  `entry_id` selects a recorded identity; `unattributed: true` is administrator-only.
  Callers cannot supply another user's UID.
- `usage-history-configure`: requires current generation and `history_options`
  containing `enabled`, `retention_days` and exact decimal `expected_revision`.
  Only the writable primary administrator can change machine-wide settings.
  A successful compare-and-swap advances the revision once.

Replies contain `usage_history` or `history_settings`. Historical snapshots carry
scope, partial/state/settings, source, time range, resolution, bounded entries,
sparse points and recording intervals. A missing or older capability leaves live
Activity and the current observation interval available.

If a settings acknowledgement is lost or mismatched, the client locks saving and
offers a fresh read to check the result. It never automatically resends the
mutation. A later authoritative revision can resolve the lock without claiming
the earlier save succeeded; the current settings must be reviewed before another
change. Connection, generation and permission changes fence old responses.
Unsaved settings edits retain their reviewed revision across periodic reads, so a
concurrent settings change refuses the stale draft. Changing identity context clears
the draft and consent. History lives separately from rule migration/rollback;
older binaries do not consume it. Preserve the private history file when doing
manual backup or recovery; the existing installer rule backup is not a history
backup.

## Verification scope

`internal/accounting/history_test.go` covers opt-in baselines, replay, counter
regression, transactional failure, SQLite capacity rollback/recovery, retention,
catalog/epoch bounds, exact large values, saturation, UID projection and reopening
committed history after an actual child-process exit with an uncommitted write.
This is process-crash recovery, not a power-loss guarantee.
`internal/daemon/usage_history_test.go` exercises authenticated primary/companion
reads, administrator settings, generation/revision refusals and diagnostic-only
unavailability. Electron parser/client tests cover bounded projection, exact
integers, context changes and lost-acknowledgement reconciliation without replay.
Sandboxed native Electron checks against a synthetic API verified the sparse
graph and exact large-number tooltips at 800/1280 pixels, separate source controls,
ordinary-user restrictions, retained unsaved drafts, refusal after a concurrent
settings change, and one-write/read-only reconciliation after a committed save
lost its acknowledgement. These UI checks do not establish real traffic
collection or daemon persistence by themselves. Guest tests and synthetic UI
checks are separate evidence; no host-scale performance or power-loss claim is
made.

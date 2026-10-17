# Persistent firewall decision log (`decision-log-v1`)

Answers "what tried to connect, what did FlowGate decide, and why?" after a prompt
disappears or the daemon restarts. This is the **Connection Log** foundation only:
no connection history aggregation and no traffic statistics. Evidence is captured at
decision time; nothing is reconstructed later from current rules (unlike
`policy-explain`) and Activity rows are never backfilled.

## What is recorded

Only daemons that evaluate new connections record: `host-enforcement` and
`isolated-lab` (`serve-lab --decision-log PATH`). The non-enforcing `serve` monitor
opens the same file **read-only for history** (`health.recording:false`) and never
produces allow/block records. Stored-rule edits in monitor mode are not decisions.

| kind | meaning |
|---|---|
| `pending` | an initiation with no matching rule, now awaiting a user answer (`source:default_ask`; verdict `held`, or `drop_submitted` when retention bounds were full) |
| `final` | the disposition FlowGate applied |
| `gap` | records were lost (buffer overflow, oversize, storage failure); history is incomplete there |

Final `source`: `rule` (stored/remembered rule), `attribution` (unresolved/unsafe
ownership → block), `capacity` (pending capacity/prompt rate → block), `user`
(scope `once`, `application` or `persistent`; `decided_by_uid`), `timeout`,
`identity_changed`, `policy_change` (rule replace/edit/delete discarded the pending
request), `rule_edit` (a committed editor rule decided the pending request),
`shutdown` (daemon stopped while pending). A `pending` record is normally followed
by a final with the same `request_id`; after a crash (not a clean stop) a pending
record can remain without a final — present it as "outcome not recorded".

One record per evaluated initiation: a TCP SYN or a UDP flow lease. Retransmitted
SYNs hit the cached decision; identical re-decisions of the same flow/token after the
cache lease expires (same source/action/rule/version) collapse to one per minute;
repeated capacity refusals of a flow collapse per 5 s. Datagrams are not logged.

`verdict.state`: `accept_submitted`/`drop_submitted` (kernel verdict call succeeded),
`submission_failed` (+detail), `held`, `deferred` (user/timeout/edit outcomes apply to
held packets at the next 20 ms queue flush and to later packets of the lease; a held-
packet submission failure stops the queue and is reported by enforcement health).
`delivery` is always `not_observed`: **Allow is a policy decision plus verdict
submission, not proof of delivery**; other firewall chains may still drop.

Captured fields: record ID, time, daemon generation, mode, direction (from the
netfilter hook, never inferred from ports), protocol, family, endpoints, interface,
application key/name/kind/executable/revision, principal UID, attribution status/
reason, action/source/scope/reason, matching rule IDs, the **decision-time rule
snapshot** (ID, exact version as a decimal string, action, priority, created,
expiry, filter), deciding UID. Not collected: payloads, environments, command lines,
PIDs. Unknown values stay absent/`null`.

## Storage, durability, retention

Separate private file `decisions.db` beside `rules.db` (same validated 0700 root
directory; `serve-lab` takes an explicit private path). The rule database is
untouched (still schema 1), so a rollback executable keeps working and a later host
rollout needs no rule-database migration; log growth never approaches the rule
store's 16 MiB open limit. Schema v1: `meta(log_id, removed, removed_through)` and
`decisions(seq AUTOINCREMENT, id, at, kind, owner_uid, direction, action, source,
application, document ≤8 KiB)` with indexes on `at` and `(owner_uid, seq)`. Version 0
(new, empty) migrates to 1; unknown versions, unversioned nonempty files, public or
oversized (>256 MiB) files and a second owner (flock) are refused.

The packet path only does a non-blocking enqueue into a 1024-record buffer; a writer
goroutine commits batches (≤256 records or every 1 s, `synchronous=FULL`).
**Durability window: up to ~1 s of records** (or one batch) is lost if the daemon
crashes; clean shutdown records pending→`shutdown` and flushes. Overflow/oversize/
write failure never blocks packets or changes policy: they are counted
(`dropped`, `write_failures`, `lost_in_failures`), health becomes `degraded`, and the
next successful write inserts a `gap` record. If the file cannot be opened the daemon
still starts; health reports `unavailable`.

Retention: at most **20,000 records** and **30 days**, pruned inside each write
transaction in steps of ≤1000; `retention.removed`/`removed_through` report pruning.
Expected size is a few tens of MiB at the cap.

## API (additive; primary and read-only companion)

Capability `decision-log-v1`. Reads only — no deletion, export or administration.

```json
{"version":1,"operation":"decision-log","decision_query":{"limit":50,"before":"<seq>","after":"<seq>","since":"RFC3339","until":"RFC3339","direction":"incoming|outgoing","action":"allow|block|pending","source":"<source>","application":"<application key>","log_id":"<from health>"}}
{"version":1,"operation":"decision-log-get","decision_id":"<record id>"}
```

`decision_query` is strictly decoded (unknown fields rejected). `limit` 0..100
(default 50; 0 = health only). Default/`before` pages newest-first (`next_before` set
when `has_more`); `after` pages oldest-first from that sequence (`after:"0"` = oldest
retained; `next_after` is the last returned). Sequences are decimal strings, strictly
increasing and never reused, so pages stay stable while records arrive. All filters
are server-side for both directions; `application` matches all revisions (keys omit
the revision). `since` inclusive, `until` exclusive. Scans are bounded by retention.

Response `decision_log`: `records`, `has_more`, `next_before`, `next_after`, `order`,
`scope` (`machine`|`self`), `health`, `limitations`. `decision-log-get` returns
`decision_record`. Errors: `invalid_request`, `invalid_cursor` (malformed cursor or
`log_id` mismatch → restart at newest), `not_found` (unknown, pruned **or not
visible** — existence is not disclosed), `unavailable`.

Health: `log_id` (changes only when the file is recreated), `state`
(`ok|degraded|unavailable`), `recording`, `buffered`, `dropped`, `write_failures`,
`lost_in_failures`, `last_error`, `last_write`, `durability_window_ms`,
`retention{max_records,max_age_days,removed,removed_through}`, `oldest`, `newest`
(unfiltered). Reconnect: recheck capability and `log_id`; generations differ per
daemon run and appear per record.

Visibility: administrators see all records. Ordinary peers see records whose
principal UID is theirs plus `gap` records with the dropped count withheld; health
counts are withheld (`counts_withheld:true`). Unknown-owner records are never shown
to ordinary peers.

## Real isolated example

`scripts/lab.sh python3 scripts/decision-log-isolated.py --binary <test build> --run <private .workspace dir> [--hold]`
runs real `serve-lab` NFQUEUE enforcement with native receivers in a disposable
namespace. Run `.workspace/decision-log-1792272647`:

- Ask → user Allow once → receiver RECEIVED: `pending`(held) + `final`(user, once, allow).
- Ask → user Block remembered; a fresh TCP connection → `final`(rule, block, rule
  `user:946e…` version "1", `drop_submitted`), receiver got nothing; SYN
  retransmissions produced no second record.
- Unanswered UDP request → `final`(timeout, block); nothing delivered.
- Restart → new generation reads all 7 records; same `log_id`.

Rule-block record (revision elided):

```json
{"id":"3d08928c8609cb3fd139ca4b39a0151d","sequence":"5","time":"2026-10-17T23:30:48.908943227+02:00","generation":"574169ef08d65cc43903f0f8639f3af8","mode":"isolated-lab","kind":"final","request_id":"56d9ddc6e5b51b28c2e563e9257ed87d","flow":{"direction":"incoming","protocol":"tcp","family":"ipv4","local":"127.0.0.1:24602","remote":"127.0.0.1:47442","interface_index":1},"application":{"key":"74940cab…751414","name":"python3.14","kind":"native","executable":"/usr/bin/python3.14","revision":"…"},"principal_uid":0,"attribution":{"status":"directly-associated","reason":"one visible socket and one current FD owner; observation is subject to races"},"decision":{"action":"block","source":"rule","reason":"blocked by rule or unresolved ownership","rule":{"id":"user:946e7b8dc5fd2a3ca72e6d58b477bc01","version":"1","action":"block","priority":100,"disabled":false,"created":"2026-10-17T23:30:48.589113439+02:00","expires":"2026-10-18T00:30:48.589113439+02:00","filter":{"application":"74940cab…751414","revision":"…","direction":"incoming","protocol":"tcp","remote_address":"127.0.0.1","local_port":24602,"uid":0}},"matching_rules":["user:946e7b8dc5fd2a3ca72e6d58b477bc01"]},"verdict":{"state":"drop_submitted"},"delivery":"not_observed"}
```

`--hold` keeps the lab daemon for UI attachment (`ready.json`; commands on stdin or
the `command` file: `decide-allow`, `decide-block`, `rule-traffic N`, `restart`,
`quit`). Lab rules are memory-only, so stored-rule edit/delete is covered by unit
tests, not the lab fixture.

## Verification and limits

Focused race/vet on decisionlog, daemon, queue, hostfirewall, cmd/flowgate
(`.workspace/decision-log-tests.log`): migration/refusals and rule-DB independence,
restart persistence, age/count retention, stable paging under arrivals, UID privacy/
administrator visibility, overflow and storage-failure gap reporting, rule snapshot
across disable+delete, no duplicate for retransmission/lease re-evaluation, user/
timeout/policy-change/identity/shutdown/capacity sources, monitor mode records
nothing, read-only API errors.

Not covered: host enforcement was not run (no host changes); unparseable or
non-initial queued packets (fragments, IPv6 extension headers, non-SYN TCP) are
dropped without a record; held-packet verdicts after a decision are not individually
logged; receiver delivery is never observed; log-on-crash loses the durability window.
The running host monitor is unchanged; a later deliberate rollout creates
`/var/lib/flowgate/decisions.db` (empty history, recording off in monitor mode).

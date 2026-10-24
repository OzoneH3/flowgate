# Accumulated observed usage

FlowGate now retains sampled traffic deltas after sockets close. Electron's
**Observed usage** tab displays those backend-owned records separately from live
Activity. The **Current observation interval** view is in memory: a
daemon/observer restart starts a new interval. Optional, administrator-enabled
[durable history](USAGE-HISTORY.md) separately archives sampled checkpoint deltas
across restarts with retention settings and historical graphs. Both views are
partial observations; neither provides Reset, quota enforcement or bandwidth
shaping. The live ledger semantics below remain independent of the archive.

## Meaning and limits

The observer feeds completed, runtime-annotated, size-bounded snapshots to the
accounting reducer. API polling only reads the result; opening the tab does not
start collection or change counters. First observations establish baselines;
later supported deltas accumulate once. Duplicate/out-of-order samples do not
add usage. Counter resets, generation changes, incomplete collections and
continuity gaps break baselines. Missing sockets lose their baseline while
previously accumulated totals remain.

Every value is partial. Short connections can escape sampling, final bytes can
be missed at closure, and matching owner samples do not prove uninterrupted
ownership between them. Changed/shared/unverified ownership is not credited to
an application. Accounting identity does not grant firewall permission.

- TCP counts observed transport payload; uploaded payload includes retransmits.
- UDP uses the optional collector's API-return byte definition. Without that
  collector, UDP is unavailable rather than zero. No BPF collector is enabled by
  this feature.
- TCP and UDP retain separate totals. Neither measures remote delivery or a
  billable interface-wide byte total. No VPN double-counting correction is claimed.
- Application identities include user, revision, runtime/prefix and source. Two
  executable paths or Wine prefixes do not inherit each other's observations.
- Ordinary users receive only their own entries. Global unattributed totals and
  coverage-break counts are administrator-only, including after owners exit.

The ledger retains at most 1,024 application/source records and 2,048 socket
baselines. If a new observation would exceed entry capacity, accumulation freezes
at the observation boundary until restart. Existing totals remain readable;
`capacity_limited` is explicit. Counters saturate at unsigned 64-bit maximum and
expose that condition. No silent eviction, wraparound or reassignment to another
application is allowed.

`gaps` counts coverage breaks **including ended socket baselines**. It is not an
error count, dropped-packet count, or lost-byte estimate. Retained observations
remain historical when collection becomes unavailable or overdue.

## Read-only API

Capability: `observed-usage-v1`. Operation: `observed-usage`. The normal v1 reply
contains `observed_usage`; the authenticated server chooses `scope: user|machine`.
The primary daemon and its read-only companion can serve this operation. Developer
observer entry points also publish the capability when their ledger is present.

The bounded snapshot contains:

| Field | Meaning |
| --- | --- |
| `version`, `epoch`, `sequence` | Schema 1, random ledger incarnation, last consumed observation sequence as an exact decimal string. |
| `started_at`, `sampled_at` | Interval start and last sample time; sample time omitted before the first observation. |
| `scope`, `partial`, `attribution` | Authenticated projection, always partial, `sampled-owner`. |
| `capacity_limited`, `saturated` | Explicit frozen accumulation and counter-bound states. |
| `sources` | Separate TCP/UDP source availability and explanatory reason. |
| `entries` | Stable ID, UID, bounded application key/revision/kind/name, source, exact decimal upload/download bytes, first/last observation times and partial flag. |
| `unattributed`, `gaps` | Administrator-only source totals for unassigned intervals and coverage-break count. |

All byte counters are decimal strings. Names are display metadata. The response
does not expose executable paths, permit caller-selected foreign principals,
offer pagination or accept a reset operation.

## Electron behavior

The tab queries only an advertised connected endpoint, preferring the primary
daemon and otherwise its companion. Overlapping refreshes share one request.
Generation, endpoint or permission changes discard an in-flight response; older
sequences within the same interval are refused. Errors clear displayed totals
rather than presenting a previous principal or interval as current.

Source and application filters operate on returned records, including inactive
programs. The global display unit applies; integer formatting preserves counters
beyond JavaScript's safe numeric range, with exact bytes in the cell tooltip.
There is no combined TCP/UDP grand total. Source availability, interval start,
sample time, sampled ownership, capacity and saturation remain visible. Daemons
without the capability show an unavailable explanation while live Activity
continues normally.

## Verification

UI checks are in `electron/test/observed-usage.test.cjs`: strict bounded parsing,
exact counters, independent entries, projection boundaries, real client calls
over a synthetic Unix API, concurrent refreshes, generation/permission changes,
sequence regression, new intervals and legacy/companion compatibility.

Fresh evidence for this increment is under `.workspace/usage-ui/`:

- `unit.log` and `full-electron.log`: 10 new tests and the isolated Electron suite
  (354 tests at that checkpoint).
- `j-ef38ed/evidence.json`: sandboxed native Wayland Electron against a synthetic
  Unix API; retained entries with empty Activity, exact large values, filters,
  visible capacity/saturation, restart clearing and unavailable-capability state.
  A screenshot was captured; controls were checked at 900px and 1280px.
- `real-run-path.txt` identifies an actual-daemon fixture in a private
  user/network/PID namespace. Two separate compiled executable paths send
  IPv4/IPv6 TCP to isolated receivers. Observations remain after sender exit and
  three further collection cycles with no sender-owned Activity sockets. Later
  primary/companion reads retain the same totals. Receiver delivery is checked
  separately; byte totals are not claimed equal to delivered payload.

Backend reducer, observer integration and authenticated API verification are
recorded in `.workspace/accounting-full-packages.log` (accounting, monitor and
daemon race packages), `.workspace/accounting-api-root.log` (private-namespace
administrator API), and `.workspace/accounting-collector-final.log` (TCP4/TCP6
real counters; UDP4/UDP6 injected-counter providers over real sockets).

Final end-to-end evidence: `.workspace/usage-ui/real-4mKZ4j/evidence.json` and
`ui-evidence.json`. A sandboxed native Wayland GUI read the actual isolated daemon
after both synthetic senders exited; displayed exact retained values matched the
backend records. Scope, coverage text, unavailable UDP and search/refresh passed,
with a captured screenshot. The tested daemon SHA-256 is
`0666f75d4f093b6842fa72477d89fd6ec6985527e40014492696a19941543082`.
The final UI build and focused tests are recorded in `build-final.log` and
`unit-final.log`; `full-electron-final.log` records the 354-test suite before the
last small-positive-value formatting correction, which the final focused run covers.

Synthetic UDP counter fixtures do not prove real
BPF attachment, and synthetic Wine identities do not constitute runtime acceptance.
No host firewall, installed daemon, installed GUI or protection settings were
changed by this increment's checks.

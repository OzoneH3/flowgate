# Daemon-owned incoming evaluation (`daemon-evaluation-v1`)

Implemented for the existing root `serve` daemon; **not deployed or activated on
the host in this increment**. One Go daemon continues to own Activity, rules.db,
Decision Log and optional UDP accounting. Evaluation adds an NFQUEUE session, not
a second controller/API/database owner. Electron remains unprivileged.

## Configuration and authority

`serve` advertises the capability. Selected-user activation requires an explicit
root configuration grant `--administrator --allow-evaluation`; rule management,
collector control and deciding requests do not imply this grant. Root peers may
control evaluation. `permissions.can_control_evaluation` is false on the read-only
companion. The companion may request bounded read-only readiness inspection.

`--evaluation-state` defaults to `/run/flowgate-evaluation`. Only Start prepares
its root-owned0700 directory and pins a private copy of the running executable for
the independent watchdog. No startup interception, automatic renewal or service
installation. All runtime paths come from privileged configuration, never API data.

## API

Use version1 on the existing authenticated primary. Every operation requires the
current daemon `generation`; Start/Stop additionally require explicit authority.
Only `profile:"incoming"` is accepted. Readiness and Start return immediately;
poll `list` (no extra process/stream) for completion.

```json
{"version":1,"operation":"evaluation-readiness","generation":"<daemon generation>","profile":"incoming"}
{"version":1,"operation":"evaluation-start","generation":"<daemon generation>","evaluation_id":"<last evaluation.id, initially empty>","request_id":"aabbccddeeff00112233445566778899","profile":"incoming"}
{"version":1,"operation":"evaluation-stop","generation":"<daemon generation>","evaluation_id":"<current evaluation.id>"}
```

Both endpoints' `list` and operation replies contain:

```json
{"evaluation":{"id":"<server allocated session id>","request_id":"aabbccddeeff00112233445566778899","state":"active","profile":"incoming","stops_at":"<absolute RFC3339 deadline>","duration_seconds":300,"cleanup":"pending","reason_code":"active","reason":"Incoming interception verified; independent deadline armed","review":"<backend confirmation text>","unsupported_outgoing":"Only incoming is supported by this daemon lifecycle, including the bounded Tailscale client profile; combined outgoing evaluation is unavailable.","readiness":{"state":"ready","checked_at":"<RFC3339>","checks":[{"id":"firewall.queue_census","status":"not_checked","code":"permission_required","detail":"Queue census unavailable; startup must still perform an exclusive bind","next":"<diagnostic action>"}]}}}
```

The example uses illustrative tokens/timestamps; shapes are exercised against the
real isolated API. Initial status is `stopped`, empty id/request_id, incoming,
300seconds, zero deadline, cleanup`not_needed`, readiness`not_checked`.

- Evaluation states: `stopped`, `starting`, `active`, `stopping`, `failed`,
  `degraded`. `cleanup`: `not_needed`, `pending`, `confirmed`, `unconfirmed`.
- Readiness states: `not_checked`, `checking`, `ready`, `blocked`. Checks reuse
  existing doctor `{id,status,code,detail,next}`. At most one read-only probe runs,
  with a15s context. Exclusive queue binding and startup conntrack checks are NOT
  established by readiness. Start always repeats actual preflight.
- Existing `enforcement` reports the same state/profile/deadline. Backend mode
  remains `daemon-monitor`; clients must inspect enforcement, not infer protection
  from API connectivity/mode. `can_decide` is true only on the primary while active.
  Policy summaries correctly distinguish active incoming from bypassed outgoing.
- Start uses compare-and-swap against the latest `evaluation.id`; the server creates
  a new session id and a deadline **300seconds from acceptance**, including startup.
  The client supplies a fresh32-lowercase-hex `request_id`. Duplicate Start with the
  current start nonce returns that session even after Stop/expiry; it never renews.
  A stale expected id or another concurrent start conflicts; an in-flight readiness
  or evaluation can return `busy`. A later deliberate Start needs the latest id and
  a fresh nonce. Do not reuse request nonces for different user intentions.
- Stop is idempotent for the current id, never for an old session. Cleanup errors
  remain `degraded`/`unconfirmed`; another explicit same-id Stop retries only owned
  cleanup. New Start is refused until cleanup is confirmed. A lost response is
  ambiguous: read `list`, reconcile session id/request_id and never automatically
  replay/fall back to an unconditional operation.
- `error_code`: `forbidden`, `generation_conflict`, `evaluation_conflict`, `busy`,
  `invalid_request`, `unavailable`. Asynchronous refusal/failure appears in
  `evaluation.reason_code`/`reason` and readiness checks; startup inherits specific
  existing codes where available. Failure is not readiness success or protection.

## Policy, cleanup and independence

Stored rules decide supported new incoming TCP/UDP; unmatched supported native
applications prompt, unknown/ambiguous attribution blocks, timeout blocks. Existing
bounded initial-packet retention remains unchanged; excess packets may drop. New
outgoing traffic remains allowed; marked replies do not prompt in reverse. Startup
connections are preserved with the existing conntrack bootstrap. Existing bootstrap
exceptions and TCP initiation (not continuous ownership) semantics are unchanged.

The watchdog acknowledges readiness before interception. Queue binding precedes
the existing atomic owned-table transaction; Active is published only after queue,
bootstrap, table digest and durable instance record succeed. Partial startup rolls
back only owned table/mark bits. Conntrack bootstrap checks its cancellation/deadline
between updates; individual netlink/dump calls retain their bounds. Mask cleanup has
a10s budget. Stop first removes interception, then clears owned marks; failed residual
cleanup is explicit, not presented as confirmed. Operations can complete after the
exact deadline while bounded kernel/cleanup calls finish; the deadline never extends.

The pinned independent watchdog removes only this token's table/marks at the original
deadline, even if the GUI disconnects or the daemon dies. It **does not SIGTERM the
root daemon**. Cleanup is serialized with activation using a private lock. An
unexpected queue failure retains fail-closed interception until explicit Stop or the
original deadline. The queue drains/drops held packets before ephemeral admissions
are reset; rules and observer remain. Owned-table changes/loss are checked about
once/second and trigger cleanup (external command bounds add latency).

Foreign rules, routing and Tailscale state are checked at readiness/activation,
**not continuously during evaluation**. Existing incoming-only1.104.1 iptables-nft
client compatibility remains narrow; both/outgoing is refused. No tunnel/root/LAN
blanket exemption. Component evidence is not encrypted live-tailnet verification.

UDP helper ownership and root observation contexts are independent of the evaluation
context. Start/Stop/expiry never call collector Start/Stop/Close. No UDP baseline
reset is intended. Real BPF/active-collector continuity was not re-exercised here:
user-namespace fixtures keep collector disabled/unavailable; an active collector
model verifies no lifecycle calls and existing kernel accounting evidence is reused.

Decision Log opens once in the daemon. Recording health toggles with evaluation;
records use mode`host-enforcement` and additive `evaluation_id`. Stop finalizes pending
as policy-change dispositions, does not erase history, then health returns to
`recording:false`. Verdict submission remains separate from receiver delivery.

## Reproducible focused checks

Build separately, leaving the host executable untouched:

```sh
. scripts/go-env.sh
go build -o .workspace/flowgate-evaluation-test ./cmd/flowgate
go test -race ./internal/daemon ./internal/hostfirewall ./internal/decisionlog ./internal/queue ./cmd/flowgate
go vet ./internal/daemon ./internal/hostfirewall ./internal/decisionlog ./internal/queue ./cmd/flowgate
scripts/lab.sh python3 scripts/daemon-evaluation-isolated.py \
  --binary "$PWD/.workspace/flowgate-evaluation-test" --run "$PWD/.workspace/evaluation-check-NEW" --suite
# Supported Tailscale-shaped component (real TUN/marks/routing, emulated TS metadata):
scripts/lab.sh python3 scripts/daemon-evaluation-isolated.py \
  --binary "$PWD/.workspace/flowgate-evaluation-test" --run "$PWD/.workspace/evaluation-ts-NEW" --suite --tailscale --skip-expiry
```

Use fresh run paths. Full suite intentionally waits the actual five-minute deadline
with no attached client. `--hold` instead publishes `ready.json`; a single UI owner
controls lifecycle and the `command` file (`send PORT [v6]`, `counts`, `quit`). Backend
owner cleans up only after explicit DONE. Odd ports44001/44003 are one-shot UDP;
44002 is TCP; IPv6 counterparts44101/44103/44102. Counts are receiver evidence.

In-package fault fixture (disposable namespace only):

```sh
go test -c -o .workspace/eval-hostfirewall.test ./internal/hostfirewall
FLOWGATE_EVALUATION_BINARY="$PWD/.workspace/flowgate-evaluation-test" \
  scripts/lab.sh sh -c 'cd internal/hostfirewall; exec ../../.workspace/eval-hostfirewall.test -test.run TestEmbeddedKernel -test.v'
```

It injects failure after the real atomic table install but before Active, modifies
an owned rule, and uses a private shortened duration to check cleanup races. It
asserts unrelated objects survive and a model active collector receives no lifecycle
calls. The production duration has no API override. Unit gates prove concurrent/
duplicate Start, stale Stop, lost-response reconciliation and read-only/ordinary
peer denial without timing-dependent ordering.

Recorded evidence: `.workspace/eval-suite2-output.log` real UDP4/6 retained Allow,
TCP4/6 Block, approved replies, pre-existing TCP, saved rules/daemon preserved on
Stop, Decision Log, stale/read-only denial, mark-conflict refusal, **actual300s
expiry without a client**. `.workspace/eval-ts-shaped2.log` passed supported shape
and conflicting full-write refusal; no encrypted tailnet. `.workspace/eval-release-
{race,vet,kernel}.log` focused tests. Fixture teardown closes only its namespace and
processes; no host firewall or collector actions.

## Future host procedure — NOT executed

The current host daemon is deliberately unchanged and lacks this capability.
A separately authorized controlled monitor rollout must deploy the released binary
with the same socket/database/UID1000/administrator/UDP configuration and the
explicit `--allow-evaluation` grant. For that future startup (never a second writer):

```sh
sudo -n /home/flowgate-user/Apps/flowgate/.workspace/flowgate serve \
 --socket /run/flowgate-api/daemon.sock --database /var/lib/flowgate/rules.db \
 --uid 1000 --administrator --allow-evaluation \
 --udp-helper /home/flowgate-user/Apps/flowgate/.workspace/udp-collector --allow-traffic-control
```

After that separate rollout, an authorized UI/client inspects list/generation,
requests readiness, displays `evaluation.review` and blockers, and only after an
explicit user Start submits the guarded incoming request. Poll for verified Active
and preserve the original deadline. Stop via the same primary/id; verify
`stopped`+`cleanup:confirmed`. Closing the GUI is not Stop. The independent monitor,
rules and UDP remain. If daemon loss prevents API Stop, inspect exact owned state
and use privileged `host-recover --state /run/flowgate-evaluation` only for that
recorded session; it refuses an active owner lock. **Do not use legacy host-stop
against embedded state: it is a whole-controller signal path.** No existing
terminal evaluator/second database owner is needed or automatically launched.

## Released backend and UI handoff

Backend release **bfa93b6a695fb1928b0f7d55b4aff5cd1d71f626**, clean source build
`.workspace/flowgate-evaluation-release`, SHA256
`3e717df8790683c5222dc47c9426f843825fd309c6224b483e6963193608eb77`.
Later evidence-only documentation commits do not change the running test source.
The root host executable `.workspace/flowgate` was never replaced.

Exact-release real component repeat `.workspace/eval-released-ts.log`: dropped Start
acknowledgement reconciled via status/nonce without replay, supported TUN/TS-shaped
preflight, actual veth UDP4/6 Allow+reply delivery, TCP4/6 Block, startup TCP
preservation, Stop keeps the same daemon/rules/collector generation, Decision Log,
read-only/stale denial and full-write conflict refusal. No encrypted Tailscale claim.
Exact-release kernel fault fixture `.workspace/eval-exact-release-kernel.log` passed
post-install rollback, owned-rule mutation cleanup and private shortened expiry
with a model active collector left untouched. Full **production300s** expiry ran
on the earlier candidate using the same fixed deadline/watchdog path
(`eval-suite2-output.log`); final expiry handling was additionally rechecked at the
private short-duration seam, not by repeating another five-minute wait.

UI-owned exact-release sandboxed Wayland journey passed against the held
`.workspace/eval-ui-released` instance: review/readiness, Start, UDP44001 AllowOnce
receiver1, UDP44003 BlockOnce receiver0, actual Decision Log, read-only Start denial,
**closing GUI while active preserves session/original deadline**, reconnect and
confirmed Stop, same daemon/rules/Activity afterwards. Screenshots/evidence in UI
worktree `.workspace/evaluation-ui-S42wAW/` (active-normal, active-narrow,
review-real, decisions-real). UI owner sent DONE; backend then sent quit and the
fixture confirmed CLEANED. Earlier candidate UI evidence `.workspace/evaluation-ui-
fNpKcs` is separate. The released UI81c0aaa was subsequently integrated; the new visual pass remains separate.

Host read-only final check: daemon generation **0840f7c256126f1708702f27c5b26551**,
collector **43a091abb81a09901be2c9b460080ee1** still active, enforcement stopped,
rules unchanged. It still lacks daemon-evaluation-v1. No host restart, collector
interruption or enforcement was performed.


## Integrated UI and focused real-BPF continuity follow-up

UI81c0aaa and referencebf3b79d are integrated at90cbac5. The settled API is unchanged.
`scripts/check-evaluation-udp.sh` adds one isolated initial-user-namespace BPF
continuity journey using the existing adapter/fixtures: continuous controlled UDP4/6
connected/unconnected transfers, TCP control, incoming evaluation Allow/Block and
explicit Stop. Same socket IDs, observed-since, helper PID and collector generation
are required, with final socket-API byte totals compared to fixture counts.
It checks actual Decision Log outcomes and foreign rules/routes preservation.
No claim of remote delivery is derived from accounting; separate receivers check
only the Allow/Block flows. This does not repeat five-minute expiry.

The concrete noninteractive launch was denied authentication before namespace or
BPF execution. **This new case has not passed against the kernel.** Run exactly
`scripts/check-evaluation-udp.sh` from the main checkout and authenticate if prompted;
see [INTEGRATION.md](INTEGRATION.md) for evidence paths and remaining deployment steps.
Host monitor and active collector were not restarted or interrupted.

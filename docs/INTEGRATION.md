# Integrated desktop and non-enforcing root monitor

## Current: remaining TCP kernel check uses explicit shared-hook observation

Zone-scoped Remember and released UI remain complete atf7b04c49; no receiver/UI
matrix is repeated. Initial-root fixture path fix40df1fb and diagnostic fix2ef62bb
preserve the earlier real failures. The user supplied effective sockops id109
bpftune_conn_tuner (sysctlid99 separate hook): default collector refusal is expected.
No foreign program, service, host daemon or UDP collector was changed.

The implementation now adds explicit root `--tcp-initiation-observe-shared` mode:
independent own link, no callback/tuning/reply writes in shared mode, evidence only
where lifecycle notifications already exist, foreign IDs checked at attach/every
sample and cleanup. Default refusal remains. Focused native build/race/vet pass;
real shared-kernel/overhead proof still pending. See TCP-INITIATION.md for bounds,
source audit and exact affected test (requires terminal authentication):

```sh
scripts/check-tcp-initiation.sh --observe-shared
```

Do not detach/disable bpftune or silently switch the running host. After the test,
inspect saved verifier/result/inventory/overhead evidence before any further edit or
rerun. A future separately authorized rollout on this machine would require this
explicit option in addition to the reviewed helper/cgroup flags, only after proof.

## Current: reviewed zone-scoped pending Remember integrated; kernel proof awaiting authentication

Backend API **ee7ba47**, receiver followup **05c341bf3336fa9c9bd328f493eea38c6fdf71ce**,
and explicit clean UI **7a210332976b3ed61d8aded29134d2ec73cc06ad** (including sender/
window safety checkpointeb8fa8b) merged at **d306a8cac3388037b8b40bb4da9da94595734a9b**.
No host deployment. `decision-zone-remember-v1` uses action-bound30-second previews,
exact zone/configuration revision and reserved rule binding, plus5-minute queryable
receipts. Once unchanged; no process-only Remember/stored Ask. Visible default
**Any network**; Local/Internet require current known matching classification.
Unknown named scope refuses rather than guessing. Legacy Any rules remain schema2;
named scope uses schema4. Exact contract/examples: `NETWORK-ZONES.md` pending section.

Preview/commit preserve application/revision/UID/protocol/peer/service and absolute
expiry. Identity, generation, definition, classification and pending deadline are
revalidated; mismatch never substitutes a different scope. Current admission is
separate from the future remembered rule. Lost ACK uses decision-status query;
pending/unknown never triggers blind resend. Same successful token acknowledges
its historical receipt only, not another rule, decision, packet verdict or log entry.
Decision Log stores the actual zone-constrained rule snapshot. Receipt memory is
bounded and volatile, not crash-proof reconciliation or proof of receiver delivery.

### Passed focused evidence

- `.workspace/remember-zone-receivers-2/remember-zone-evidence.json`: actual native
  receiver proof with SAME application/peer/protocol/service across explicit zone
  definition changes in the disposable daemon. Local Allow/subsequent delivery;
  that identical peer classified Internet no longer inherits Local Allow; Internet
  Deny/subsequent receiver0; restored Local again delivers; Any on another service
  continues across both definitions. Different executable at the identical original
  service/peer gets independent Ask/Deny0. Old generation, mismatch and lost ACK
  reconciliation/idempotence checked. Root configuration changes require daemon
  restart/new generation; fixture private addresses are policy labels, not public
  Internet reachability. Final rules0, namespace discarded.
- Actual UI on exact05c341b binary SHA256
  `363158d16af56f5d453798f92cabcec8173435455246ef60a73f4a445f528c41`:
  `.workspace/worktrees/electron/.workspace/connection-real-suf8ni/evidence.json`.
  LocalUDP4 Remember Allow+repeat delivery; InternetUDP6 Remember Deny+repeat0;
  outgoingUDP4 Any Allow+sibling delivery; nonmatchingTCP4 Once Deny0. Focus during
  polling, automatic prompt, detached/narrow checks passed. Backend independently
  checked generation48780e9525607c8c6b37bc84ecb9b202/rules0 after explicit UI DONE,
  then owned quit; `.workspace/remember-zone-ui-owner.log` confirms CLEANED.
- Main UI build/typecheck and **20 minimal integration tests** pass in
  `.workspace/remember-ui-integration-{build,tests}.log`. Changed Go daemon/policy/
  Decision Log race and command vet pass in `.workspace/remember-zone-release-*`.
  Tests cover concurrent/replayed commit, expiry during identity resolution,
  unauthorized/read-only access, malformed/mismatched scope, unknown Any, failed
  persistence, legacy behavior and immutable logged zone. UI exact-release wider
  focused checks reused; no unrelated accounting/firewall/process/watchdog matrix.
- UI sender identity/generation freezes per prompt. Temporary KDE placement targets
  own PID and numeric-window caption, cancels stale runs and removes its own script.
  Read-only KScreen priority fixes actual preferred output vs Electron enumeration:
  DP-2 priority1, actual compositor coordinates4600,980 /520x460. Evidence UI
  `.workspace/decision-compact/primary-monitor-proof.log`. No installed window rule,
  host policy mutation or generic renderer command bridge.

### Kernel direction check: NOT yet passed

Existing fast TCP4/6 sampling-miss reproduction and real EPERM fallback remain
preserved. The implemented event helper has not been rewritten simply for lack of
privilege. Initial-root noninteractive attempt required authentication. No real
active/passive kernel evidence or active-helper overhead is claimed. Exact command
requested from the user (fresh netns/cgroup-filtered fixture, no host daemon/API):

```sh
cd /home/flowgate-user/Apps/flowgate
scripts/check-tcp-initiation.sh
```

Inspect the resulting verifier/error/evidence before any edit or repeat. This
portion remains blocked until that authenticated result is supplied; protocol/model
checks are not a substitute. `TCP-INITIATION.md` lists intended cookie/namespace,
loopback, closure/restart/failure and bounded timing acceptance. The older host
retained-identity failure remains unresolved; its checks were not weakened.

### Host boundary and proposed later rollout (NOT executed)

Read-only `.workspace/remember-host-readonly.json` confirms unchanged PID1113279,
generation3e696c4462fb777d9be0bc350a56df2e, UDP active generation
 de1c7cda058de0f47be901dcdf92cfa3, enforcement stopped, rules0. Installed source
remains7ec89ad; it does not advertise decision-zone-remember-v1. No host restart,
collector/rule/firewall/network change. Outgoing receiver proof above is isolated;
host/Tailscale evaluation remains incoming-only. Reboot still needs manual startup.

For a later separately authorized rollout, first complete the kernel check and
review explicit Local/Internet prefixes against actual host routing/VPN intentions.
Do not infer private=Local/public=Internet. Then:

1. Read current generation/config/UDP state; refuse unexpected active enforcement.
2. Export the verified running executable with
   `sudo -n .workspace/flowgate monitor-backup --generation ACTUAL_GENERATION > .workspace/ROLLBACK_EXECUTABLE`.
   This command backs up the **executable only**, not SQLite.
3. Generation-check shutdown:
   `sudo -n .workspace/flowgate monitor-stop --generation ACTUAL_GENERATION`.
   Wait for helper/socket/database-writer release; never run competing writers.
4. Use SQLite backup API for the preserved database (handles WAL consistently),
   not a bare live-file copy. For example, in a reviewed private rollback directory:
   `sudo python3 -c 'import os,sqlite3; os.umask(0o077); s=sqlite3.connect("file:/var/lib/flowgate/rules.db?mode=ro",uri=True); d=sqlite3.connect("/home/flowgate-user/Apps/flowgate/.workspace/PRIVATE_ROLLBACK/rules-before.db"); s.backup(d); d.close(); s.close()'`.
5. Copy a separately built/hash-reviewed candidate to a new inode at the approved
   launch path; atomically rename only after Stop. Never truncate a live executable.
   Retain existing root-owned database, endpoints, selected UID/admin permissions.
6. Launch with retained arguments plus explicitly reviewed zone definitions and,
   only after its successful kernel proof, the optional event helper:

```sh
sudo -n /home/flowgate-user/Apps/flowgate/.workspace/flowgate serve \
  --socket /run/flowgate-api/daemon.sock \
  --database /var/lib/flowgate/rules.db --uid 1000 --administrator \
  --allow-evaluation --allow-traffic-control \
  --udp-helper /home/flowgate-user/Apps/flowgate/.workspace/udp-collector \
  --zone-local REVIEWED_LOCAL_CIDR --zone-internet REVIEWED_INTERNET_CIDR \
  --tcp-initiation-helper /home/flowgate-user/Apps/flowgate/.workspace/tcp-initiation-collector \
  --tcp-initiation-cgroup /sys/fs/cgroup
```

Prefix placeholders require an explicit reviewed policy definition; repeat flags as
needed. No host prefix choices or rollout are authorized by this proposal.
`--allow-evaluation` grants bounded control, **does not Start interception**. Restore
UDP only if previously enabled through generation-checked control; accept new
collector generation/baseline and an observation gap. Verify capabilities/rules/
permissions and monitoring mode before any separately reviewed evaluation.
Rollback preserves all schema4 documents: use a compatible executable (or the
complete consistent pre-upgrade data state only when explicitly authorized), never
strip new rules to satisfy an older reader. If event attachment fails, retain honest
failure/unknown monitoring and inspect error; do not make speculative restart loops.

Launch current UI: `scripts/run-electron.sh --daemon /run/flowgate-api/daemon.sock`.

## Current: automatic pending permission workflow integrated

Explicit clean UI release **575aca86f6ab013c474c46f4b7700420125471ab**,
basee2f045a, merged at **599984ae087c48b76dd00f753c2338c3bc81f294**,
preserving backend fixture release **5c85f1334eb1791151539a1b345f16f1b93ac3fa**.
Main-checkout build/typecheck and **18 focused checks** passed in
`.workspace/ui-prompt-integration-{build,tests}.log`. No host deployment or
interception. Detail: `electron/CONNECTION-PERMISSIONS.md`.

Pending requests now open an independent foreground permission window, one pinned
request at a time. Queued requests do not silently replace its target; dismissed
IDs do not automatically reopen. Opening/Enter/dismissal grants nothing; expired,
disconnected, read-only and submitted requests remain non-actionable. Compact scope
text distinguishes TCP connection admission from the fixed30-second UDP tuple
lease. Remember remains exact application/revision/UID/direction/protocol/peer/service,
Any network, not a process-only or zone grant. Backend scope previews remain
available. Contextual network classification is not permission scope.

Primary-monitor bottom-right placement uses normal Electron requests plus a narrow
KDE adapter: temporary script, own Electron PID and fixed prompt caption, numeric
geometry only; no renderer command bridge, installed rules or preferences. Reviewed
sender/permission/receipt boundaries remain in the main backend service. Actual KDE
journal verified2040,980 /520x460 on primary2560x1440; Electron getBounds did not
reflect native placement. Other Wayland compositors may override placement.

Actual sandboxed UI receiver journey on exact backend5c85f13 passed:
`.workspace/worktrees/electron/.workspace/connection-real-dQva7j/evidence.json`.
Incoming UDP4 Allow receiver+1, incoming UDP6 Deny+0; outgoing UDP4 Remember Allow+1,
sibling same-application remembered+1; nonmatching outgoing TCP4 prompt then Deny+0.
These are **isolated** results, not outgoing host/Tailscale support. Existing full
receiver/process/accounting evidence reused. Automatic-window queue/focus/two Enter/
expiry/disconnect/Escape and final geometry have separately labelled synthetic
coverage. Live NetLimiter Ask interaction remains unverified; supplied illustration
and official documentation are labelled accordingly, not passed off as live capture.

First real attempt passed incoming receivers but its runner selected an older event
before outgoing; it did not establish outgoing success. Corrected exact-direction/
protocol runner passed the complete final journey. Both fixtures returned explicit
DONE; backend independently verified exact generations and rules0 before owned quit:
`.workspace/prompt-ui-{live,final}/cleanup-before.json`. Both owner logs confirm
CLEANED and processes/sockets removed. No host endpoint, rule, collector or firewall
operation occurred. The installed host backend and UDP collector are unchanged.
Event-source authenticated kernel proof remains pending as described below.

Launch: `scripts/run-electron.sh --daemon /run/flowgate-api/daemon.sock`.

## Current: configured zone policy, metadata and optional TCP event source integrated

Backend release **b4d4f13238aedc18c52d30d12b6d42df682f6aec** includes zone
implementation **c0a9543**, optional initiation source **643b872**, metadata
**4789181**, and focused authorization/identity/restart followups. Explicit clean UI
release **6f5c5fb54465f4cdbf16934573c651da8d3d3077** merged at
**bc19358ee858ca5214052c92e235a5b9ba0f233a**, preserving all backend history.
The separately released presentation-only correction **0fb417db4606ba0c97647c345be4479492836e7c**
merged at **e0c5641db94e7b6cfa6e5774519a647af41c2226**; it removes a
hand glyph mistaken from the reference mouse cursor. Followup build/typecheck
passed (`.workspace/practical-ui-glyph-build.log`), no behavior changed.
No privileged deployment is included. Source checkout and installed capabilities
are different; normal GUI against the existing host must retain capability gating.

### Implemented contracts and actual evidence

- `network-zone-policy-v1`, schema4: explicit configured-prefix classification;
  loopback/link-local built-ins, other peers only via reviewed prefixes. Private
  routed, global, ULA and VPN addresses are not guessed. Unknown stays unknown;
  limited broadcast/multicast/unspecified are unclassified. Immutable generation/
  revision binds previews. Process > application > all-program zone precedence,
  existing ordering within a tier; exact selected/overridden rules remain visible.
  Machine mutations require existing administrator authority; ordinary self-UID
  scope remains available. No zone byte-total claim for multi-peer UDP. See
  [NETWORK-ZONES.md](NETWORK-ZONES.md).
- Actual isolated incoming **and outgoing TCP+UDP receiver checks** passed Local
  IPv4 Allow delivery vs configured Internet IPv6 Deny non-delivery, application/
  process overrides and same-executable sibling fallback. Explicit routed private
  unknown did not inherit Local Allow. Evidence `.workspace/zones-receiver-2.log`
  and `.workspace/zones-unknown-1.log`; namespace cleanup confirmed. Internet in
  this fixture is an explicit policy label, not physical Internet connectivity.
- Real isolated Electron zone journey reused: four global/application/process
  rules, edit/disable, immutable zone, narrow layout, conditional cleanup to0.
  UI `.workspace/panes-real-71aeVT`; backend independently checked generation
  197647bf3a4a3ca078c4437653c35d0d/rules0/stopped, then owned quit. Owner log
  `.workspace/zone-ui-owner.log` confirms CLEANED; both sockets removed.
- `application-display-metadata-v1`: clean display path/name and separate linked/
  deleted/unavailable status, without changing identity/revision. Actual Firefox
  /proc executable is unlinked (Nlink0) and differs from replacement disk inode:
  `.workspace/firefox-executable-status.json`. UI desktop lookup uses only reliable
  matching metadata, not new permission authority. Real unlink/replacement tests pass.
- `activity-initiation-events-v1`: optional cgroup sockops active/passive established
  events bound by kernel cookie, namespace and collector generation. Bounded map,
  explicit loss/failure status, stale evidence cleared; snapshot monitoring still
  works when disabled/failed. **Successful real event-backed arrows and active
  kernel overhead remain unverified**: userns load EPERM; one initial-root attempt
  required authentication. Actual fast TCP4/6 sampling misses were reproduced.
  Protocol/model tests are not kernel proof. See [TCP-INITIATION.md](TCP-INITIATION.md).

New main-checkout UI build/typecheck and **51 focused tests** passed:
`.workspace/practical-ui-{build,tests}.log`. Reused focused Go race/vet evidence
for changed identity/policy/daemon/logging/monitor/tcpinit/command paths and exact
real UI/receiver evidence; no unrelated UDP, firewall or watchdog matrix repeated.
The older retained identity-change failure remains unresolved and preserved in
`.workspace/host-practical/first-attempt-decisions.json`; no attribution checks
were weakened to conceal it.

### Remaining authenticated check; no host deployment

Run this one prepared disposable kernel check, then inspect its result before any
rerun (it records exact source/diff/artifact hashes):

```sh
cd /home/flowgate-user/Apps/flowgate
scripts/check-tcp-initiation.sh
```

Current host read-only inspection remains PID1113279, generation
3e696c4462fb777d9be0bc350a56df2e; installed source7ec89ad, SHA256
761c4991b8047d79680e6fc98f996bd328e401bf68a0ee9ac1b80cc75d5baf0e.
UDP active generationde1c7cda058de0f47be901dcdf92cfa3; enforcement stopped,
evaluation cleanup confirmed, no stored rules. `.workspace/practical-host-readonly.json`.
No daemon/collector restart, rule mutation or host network change in this increment.
Host incoming-only evaluation remains the supported activation profile; isolated
outgoing evidence does not grant outgoing host/Tailscale compatibility.

Future deployment is a separate authorized operation: preserve actual running
executable/configuration (`monitor-backup` exports the executable only), generation-
check Stop, wait for socket/database/helper release, then use SQLite backup API for
a consistent database copy before atomically
install a copy of reviewed candidate (never truncate a live inode), then reuse the
existing retained `serve` command below. Add reviewed `--zone-local CIDR` /
`--zone-internet CIDR` definitions explicitly; optional event startup additionally
requires reviewed `--tcp-initiation-helper ABSOLUTE_PATH --tcp-initiation-cgroup
/sys/fs/cgroup`. No guessed host prefix configuration is supplied here. Restore UDP
only if previously enabled, with a new baseline. `--allow-evaluation` grants bounded
permission; **does not Start enforcement**. Readiness and explicit Start remain
separate. Never run a competing database writer.

Rollback must preserve schema4 documents: after such rules exist, use a schema4-
compatible binary/data backup, not an older executable which rejects the inventory.
Do not strip/delete rules to downgrade. Preserve separate candidate and current
working executable; the earlier rollback artifacts below predate schema4 support.
No rollback or host stop is requested now. Launch the unprivileged UI normally:

```sh
scripts/run-electron.sh --daemon /run/flowgate-api/daemon.sock
```

## Current: Rule Status popup and chart-detail fixes integrated

Explicitly released clean UI **8ecd71b652353f4af6596e713112d6e2f036366f**,
base8e16061, is fast-forward integrated with its complete history. No backend/API
change or privileged deployment. Main build/typecheck and **39 focused tests** pass
(`.workspace/ui-rule-clicks-integration-{build,tests}.log`). Exact-release synthetic
click/placement/color/reconnect evidence and real isolated process Allow→Deny edit,
conditional Delete to rules0 and GUI-exit daemon survival are reused. No receiver,
UDP or evaluation matrix repeated. Detail: `electron/RULE-STATUS-FIXES.md`.

Table setters anchor to the clicked row; matrix icon/text/background behave alike.
Viewport flip/clamp/reposition, keyboard focus and frozen target survive polling.
Detached Info has a local setter; its reviewed main-process proxy accepts only
registered Info senders with current selection/generation, draft/receipt ownership,
full process-target comparison and the existing Rules service authorization,
preview/save/version/reconciliation safeguards. Advanced editors and Delete
confirmation remain in Activity. Bounded maps retain at most32 entries per kind;
receipts are consumed before save, not automatically replayed.

Chart traces were already download green/upload red; the reproduced inconsistency
was monochrome sample details, now using the same series tokens. No unsupported
claim of a swapped-line fix. Missing measurements remain unavailable.

UI returned explicit DONE for popup-ui generation43be3202900fa8370b9a6761c99cc44c.
Backend independently verified exact generation, rules0 and stopped enforcement,
sent its owned quit, then confirmed CLEANED and both API sockets removed. Evidence:
UI `.workspace/panes-real-PLjSai`, main `.workspace/popup-ui-owner.log` and
`.workspace/popup-ui/cleanup-before.json`. An earlier locator failure after successful
cleanup is documented; the corrected full real journey passed.

Installed host backend stays7ec89ad, PID1113279, generation3e696c4462fb777d9be0bc350a56df2e;
UDP active generationde1c7cda058de0f47be901dcdf92cfa3, enforcement stopped at the last
read-only host verification. No host runtime/network/policy action or Windows input
was performed in this increment. Prior Windows docking-restoration question remains
pending. Existing host receiver acceptance remains documented below, not rerun.

Normal launch: `scripts/run-electron.sh --daemon /run/flowgate-api/daemon.sock`.

## Current: released shared Activity panes integrated (round 6)

Exact UI **0fe0989e080a11a1e58b4eda7ac99a5a56cc8331** (pane checkpoint
**e3451ca**, base7760c35) was explicitly released with a clean frontend worktree
and merged without conflicts at **590d0393322ea1a3d3a0d6a1bb2f4778e7009503**.
All newer backend commits through b030f06 are preserved. Installed root backend
remains **7ec89ad**; no daemon restart, evaluation, collector control or host rule
mutation was performed for this UI integration. Host acceptance/runtime details
remain in the following section.

Real detached Info/chart share selection, display units, accounting source and
main-owned backend connection. Rule entry delegates to the single main setter;
secondary panes do not gain mutation IPC. Dock/close/reopen/main hide/show/Quit are
implemented. Chart pan/zoom/sample navigation uses retained actual observations;
no fabricated one-second history or persistent statistics. Double-click expands
parent rows or opens connection Info. Connected-peer dots do not imply protection
or delivery. Internet/Local Network are pinned informational rows, always above
apps irrespective of sort, with explicit unavailable measurements; they are not
policy targets and do not classify unknown traffic as Internet. Genuine zone
membership/accounting is separately scoped in PLAN.md.

New main-checkout build/typecheck and **25 focused panes/units/history/assets/model
tests** pass: `.workspace/ui-r6-integration-{build,tests}.log`. Reused released
sandboxed Wayland real isolated pane/process-rule create/delete (rules0), GUI-exit
daemon survival and bounded real TCP chart/shared-socket evidence, plus labelled
synthetic normal/narrow/disconnect/navigation presentation. No receiver, UDP or
firewall matrix repeated. Backend independently verified the held fixture's exact
generation and empty rules before owned quit; CLEANED and both sockets removed.
Reference/evidence/limitations: `electron/ACTIVITY-PARITY-R6.md`.

Complete-window comparison (local native crops, labelled actual/synthetic content):
`.workspace/netlimiter-reference/rule-status-r6/round6-comparison.png`.
Windows console input is paused pending the user's free-console confirmation;
inspection changed pane docking positions and restoration is **not** claimed.
Theme/units/rules unchanged; do not take Windows input to finish that restoration
without resolving the existing user question. This is not a visual-completion claim.

Launch from the main checkout:
` scripts/run-electron.sh --daemon /run/flowgate-api/daemon.sock `.

## Current: practical host incoming control restored (2026-10-18)

Installed backend source **7ec89ad52c841212fa84610b8a0c37cf8a8961ea**, following
**74b12144d7dd1334e52227778dfd9485579e6338**, on integrated UI/base **7760c3568895eec25ceb36222ebcbdfc00ec09fe**.
The separate pane/chart frontend remains owned by the UI partner and is not merged.
These runtime facts supersede the older absent-after-reboot reports below.

- Root PID **1113279**, generation **3e696c4462fb777d9be0bc350a56df2e**.
- Installed `.workspace/flowgate` SHA256
  `761c4991b8047d79680e6fc98f996bd328e401bf68a0ee9ac1b80cc75d5baf0e`.
- Primary `/run/flowgate-api/daemon.sock`, observer `.sock.monitor`, existing
  `/var/lib/flowgate/rules.db`; UID1000 explicit administrator, separate traffic
  control and bounded-evaluation grants. No competing database owner or service.
- Enforcement **stopped**, last evaluation cleanup **confirmed**. Primary
  `can_decide=false` outside evaluation; readonly companion cannot mutate/control.
- UDP **active**, collector generation **de1c7cda058de0f47be901dcdf92cfa3**;
  same generation throughout the successful evaluation and GUI exit. Coverage is
  explicitly partial when unregistered-cookie operations are missed. Restoring and
  diagnostic-upgrading the daemon introduced fresh baselines; no byte continuity
  across those restarts is claimed.
- Original stored inventory was empty; only test-owned rules were conditionally
  deleted, final inventory empty. Existing database retained, never downgraded,
  deleted or copied live without SQLite coordination. Durable inactive process
  rules remain supported by the installed schema even though this inventory had none.
- Capabilities include daemon-evaluation-v1, daemon-udp-monitor-v1, decision-log-v1,
  process-instance-rules-v1, observed-rule-any-protocol-v1, policy-explanations-v1,
  observed-rule-create-v1 and activity-initiation-v1.

### Concrete fixes and actual host results

Docker's standard opaque xt DNAT in ip/ip6 nat/DOCKER caused a readiness refusal.
74b1214 recognizes that narrowly verified non-mark-writing target; unknown targets,
mark conflicts and unsupported outgoing still refuse. Real disposable DNAT4/6
receiver/readiness and fixed-peer TCP/UDP4/6 checks passed before deployment.

First authorized host attempt showed an identifiable native TCP prompt, but Allow
Once was followed by retained identity rejection and **no receiver delivery**.
The evaluation was explicitly stopped and cleaned up. Isolated TCP Allow Once
then passed; bounded live attribution probes were stable. No root cause was proven.
7ec89ad adds precise retained-attribution failure reasons and a focused reproduction;
it does **not** weaken identity revalidation or change verdict behavior.

The user explicitly authorized one additional bounded evaluation. That run used
session **2cd74fec91ffc0638dfcadcb7dd90bf0**, original deadline
**2026-10-18T19:54:37.163577235+02:00** (300seconds, no renewal), and explicit Stop:

- Real UID1000 sandboxed Wayland Electron connected and showed native executable,
  PID, application/process identity, protocol, local/remote endpoints and incoming
  initiation. The actual permission window's Allow Once TCP4 delivered one payload.
- Separate UDP6 Deny Once delivered zero payloads.
- Remembered application UDP4 rule bound executable/revision/UID, peer192.0.2.2
  and local port24681; initial and subsequent matching attempts delivered.
- Out-of-scope TCP6 and a different executable's UDP4 each prompted independently;
  Deny prevented delivery. No guessed display/PID/port authorization.
- Backend-previewed application UDP4 Block plus alpha-process UDP4 Allow delivered
  to alpha; same-executable beta received nothing under application fallback.
  These two rules were created via the authoritative API, not the GUI editor.
- Final alpha counts TCP4=1, UDP4=3; all other fixture counters zero. Decision Log
  remained accessible, healthy, and stopped recording on Stop. Its verdict records
  corroborate rule selection; receiver counts separately establish delivery.
- Stop confirmed, test rules removed, GUI exited: same root daemon and UDP
  generation survived. Dedicated peer/receivers exited; fg-accept-h/fg-accept-p
  removed. Read-only before/after coexistence exports match for every field except
  the naturally changing conntrack-mark histogram: foreign firewall objects,
  Tailscale preferences and inspected routing rules/table52 unchanged.

Host evidence is private/local `.workspace/host-practical/`: `host-result.json`,
`host-journey-output.log`, `native-permission-window.png`, `pending-*.json`,
`after-final-coexistence.json`, `supervisor-2.log`; first failure under `attempt1/`
and `first-attempt-decisions.json`. Do not publish unrelated pending-process data.
The first failure remains a concrete intermittent limitation, not declared fixed
because a second run passed. Unknown/shared, stale, exec-changed and unsupported
namespace identities still refuse. Sampled Activity direction may be unknown even
when the separate incoming packet attribution can identify a pending request.

Focused race/vet passed daemon/queue/readiness/cmd packages; retained diagnostic
race/vet passed. Existing exact-release UI, process, UDP accounting, watchdog and
isolated outgoing receiver matrices were reused. No host outgoing control or real
encrypted-tailnet receiver result is claimed. During incoming evaluation, unrelated
new incoming attempts can also prompt/block; this is not a dedicated-port-only
interception profile. No unrelated prompts were approved to manufacture evidence.

### Launch, manual restoration and rollback

Normal unprivileged application launch:

```sh
scripts/run-electron.sh --daemon /run/flowgate-api/daemon.sock
```

After reboot, manual startup is still required. With no existing daemon/database
writer and after supported stale-resource inspection/recovery, the retained launch
configuration is:

```sh
sudo -n /home/flowgate-user/Apps/flowgate/.workspace/flowgate serve \
  --socket /run/flowgate-api/daemon.sock \
  --database /var/lib/flowgate/rules.db --uid 1000 --administrator \
  --allow-evaluation \
  --udp-helper /home/flowgate-user/Apps/flowgate/.workspace/udp-collector \
  --allow-traffic-control
```

`--allow-evaluation` grants bounded control; it does not Start enforcement.
UDP Start is a separate generation-checked action after connection; do not assume
serve automatically restores it. Use the existing UI Enable action if needed.
Readiness then an explicit reviewed Start is needed for any future evaluation;
this task has already used its two expressly authorized sessions. Do not renew.

Compatible rollback artifact: `.workspace/host-practical/running-74b-rollback`,
SHA256 `373c8daf0a38e205157c1776c845fc8519ee8abe008ba450b900fc4a805c9a2b`.
For a separately authorized rollback: query actual generation/state, explicitly Stop
any evaluation, use `monitor-stop --generation <actual-generation>`, wait for owned
helper exit and socket/database-lock release, atomically install a copy of that
artifact at the approved executable path, then use the exact serve arguments above.
Never truncate a running inode; never remove process documents to downgrade.
Restore UDP only if previously active, accepting a new generation and baseline.
No rollback or daemon Stop is requested now; leave monitoring and UDP running.

## Current: Activity round 5 (menus, display Units and chart presentation)

Exact clean UI release **f2f9ae43a1d0313fc7c420c46cee0c2107568f78**, based on
**4422cfa**, is fast-forward integrated with full prior history. Explicit source and
Windows ownership release was verified first. Backend/API remains **6c68f8c**;
no privileged deployment or new collection was needed.

Changes: File/Tools/Window/Help use existing operations; persistent display Units
(byte/bit, explicit decimal SI) are independent of TCP/UDP accounting Source and
raw sorting. Connection labels use compact endpoints while state/direction evidence
remains in glyphs/details. Chart legend uses source-specific unique-socket totals;
rate axes, timestamps, bounded10min window and sample details preserve unavailable,
partial, restart and discontinuity semantics. This is bounded client observation
history, not persistent statistics or connection lifecycle history. No incompatible
TCP/UDP totals, guessed zero counters or historical per-application inventory.

New main-checkout build/typecheck and **18 focused asset/units/history/model tests**
pass (`.workspace/ui-r5-integration-{build,tests}.log`). Reused exact-release sandboxed
Wayland real isolated menu/units/pause/selection/popup/narrow journey and real TCP
socket/application/shared-socket chart comparison. Rule journey evidence in UI
worktree `.workspace/round5-journey-yNI5mm/` includes `metadata-correction.txt`:
its original fixture description was stale; the run actually created application
In Allow and process Out Block via existing preview/save, then exact conditional
Delete restored0rules. Original results/screenshots are preserved, not silently
rewritten. TCP chart evidence: UI `.workspace/gr-RBo9Jd/`.

Fixture ownership was explicit: UI alone drove rsf-c780 until DONE. Backend verified
actual generation dabcebbbaf2bf66829b04c0d416edfa9, daemon-monitor and empty rules,
then sent only that fixture's quit command. Its supervisor logged CLEANED for daemon,
instances and peer; both API sockets are removed. TCP fixture/observer/UI cleanup was
reported by the UI owner. WinBoat Units/Rate/root selection restored, viewer closed,
preferences restored. No host daemon, UDP collector, policy or networking action.
The host root API remains unavailable after reboot; no host acceptance claimed.

Before/reference/after complete-window images (native scale, distinct controlled
Linux versus Windows content):
`.workspace/netlimiter-reference/rule-status-r5/01-before-reference-after.png`;
process-popup, real-chart and narrow captures are adjacent. Full account and exact
remaining work: `electron/ACTIVITY-PARITY-R5.md`. No visual completion score.
Undock needs a separately bounded shared-selection/window/mutation ownership design;
chart pan/zoom and richer one-second history remain different. Stored Ask stays
explicitly deferred; no new capability or working Ask control. Browser fault cause
is still unproven; readonly monitoring recorded faults even without Electron, with
no recorded OOM/GPU reset. No browser restart/profile changes were performed.

Basic launch: `scripts/run-electron.sh`. To use the root API after separately
authorized restoration: `scripts/run-electron.sh --daemon /run/flowgate-api/daemon.sock`.
This task neither restores it nor activates enforcement.

## Current: Activity round 4 and verified font delivery

Integrated exact released checkpoint **652dab3fdec0941698bc3d92b4b4f31849197c05**
by fast-forward from57cfd86, preserving complete UI2 release **f803ce3**, accepted
review fixes **01e3ab5**, and UI owner's font-delivery correction **652dab3**.
Backend remains **6c68f8c**; no API, policy, accounting or host deployment changes.
UI ownership transferred from UI2 to flowgate ui01a1465b at the user's direction;
the new owner explicitly released this immutable checkpoint before integration.
It may continue the next visual round independently; do not merge its moving branch.

Whole-window corrections: grouped toolbar and source/layout controls; default
four-column Status table with optional Details; Rate/Total view; unified footer;
chart options in its menu with pause/resume; compact Rules columns and popup scope.
Before-click direction, application/process target, protocol, lifetime and endpoint
scope remain visible; version, preview and uncertain-response safeguards remain.
The follow-up fixes preserve current selection on chart resume and reject stale
in-flight redraws. Stored Ask remains deferred; no working Ask control was added.

Font evidence now distinguishes intended and actual delivery: NetLimiter declares
Segoe UI explicitly; licensed Selawik is bundled as its metric-compatible alternative.
The original round4 protocol returned404 for the fonts. UI652dab3 serves exactly
three known font files with font/ttf and retains sandbox/CSP. Actual sandboxed
400/600/700 document.fonts.load failed before and succeeds after. Original round4
screenshots predate this fix and must not be cited as proof of Selawik rendering.
Corrected native-scale reference/before/after comparison:
`.workspace/round4-integrated/reference-before-after.png` (fixture content differs).

Reused UI2 build/typecheck,77 unit, synthetic normal/narrow, real private popup
journey, and populated real TCP chart evidence. New owner's read-only01e3 check
passed pane close/reopen, presets, Rate/Total, Status/Details, chart source/window,
pause-selection-resume (legend matches selection), and outside dismissal. Evidence
in UI worktree `.workspace/rs/r3-panes/result.json`; font probes/screenshots in
`.workspace/round5/`. New main-checkout build/typecheck and **8 focused tests** pass
(`.workspace/ui-r4-integration-{build,tests}.log`). No receiver/UDP/watchdog matrix
was repeated. Fixture rsf-c780 is intentionally retained under the new UI owner's
exclusive lifecycle responsibility for the next isolated round, not claimed cleaned.
WinBoat settings/Units/Rate restored and viewer closed by that owner.

Host daemon API remains unavailable after the external reboots; host acceptance
was not possible. No root daemon restoration, collector action, rule write or
network change was performed. A separate read-only Firefox investigation observed
faults with no Electron sampled; that does not establish an Electron cause or
prove launch safety. No browser restart/profile change was performed here.

Remaining visual differences include menu semantics, connection labels, missing
filter objects/unsupported rule families, no Undock, and Linux font rasterization.
No fidelity percentage or design-complete claim. Details: `electron/ACTIVITY-PARITY-R4.md`.
Basic unprivileged launch: `scripts/run-electron.sh`; daemon-connected launch needs
separately authorized monitor restoration before using
`scripts/run-electron.sh --daemon /run/flowgate-api/daemon.sock`.

## Current: UI2 Activity fidelity round 3 (released and integrated)

Released UI **fbe9737e7c65e25743007151ff46545a812a4c99** (including checkpoint
97b20af, based on aea5f1a) is integrated at **197ddece88fc61b871846f3134f39bf08232da5b**.
Clean release and explicit ownership release were verified before merging. The
stored-Ask dependency note in **0d0a2be** is retained; backend production code
remains **6c68f8cd0627bce69f15f4e995a3cf68fa161215**, with no API change this round.

Changes: Deny presentation still sends API action `block`; Ask/unsupported actions
remain neutral and read-only. Hover/selection rule-family icons, popup anchoring,
Priority composition, expanders, chart legend and local pane Open Window/Close
controls follow the inspected reference. Pane preferences do not change collection
or enforcement. Stored Ask remains deferred. Font family is unverified; this is
not a claim of complete NetLimiter fidelity. Details: `electron/ACTIVITY-PARITY-R3.md`.

Reused exact-release evidence: UI build/typecheck and **77 unit tests**; real private
fixture popup/exit journey (`electron` worktree `.workspace/rule-status-real-mkoDhk`);
pane/hover run (`.workspace/rs/r3-panes/result.json` in that worktree). UI owner
reported rsf-c778 orderly cleanup; earlier private fixtures died in the external
reboots. Backend owned no new fixture. New integrated checks: Electron
build/typecheck and **6 focused rule-chip/editor-presentation tests** passed; logs
`.workspace/ui2-r3-build.log` and `.workspace/ui2-r3-tests.log`. No kernel, UDP,
firewall or Go matrix was repeated for these presentation-only changes.

**Runtime correction after external reboots:** the previously deployed root daemon
is no longer available: `/run/flowgate-api/daemon.sock` and its runtime directory
are absent, and historical PID2847094 is gone. Thus the previous active UDP state
is historical, not current verified collection. The root storage directory remains;
no database mutation, daemon restoration, collector attachment or host networking
change was performed in this round. Host UI acceptance was **unavailable**, not
passed. Older deployment sections below describe historical state.

Basic unprivileged Activity launch from the main checkout: `scripts/run-electron.sh`
(owns a read-only observer). The daemon-connected command remains
`scripts/run-electron.sh --daemon /run/flowgate-api/daemon.sock`, but requires a
separately authorized restoration of the root monitor first; this integration does
not restore it or activate enforcement.

## Current integration: UI2 floating Rule Status and explicit TCP+UDP

Full released UI **09b56426a8a97677ce9489a0aaa0098a7208e646** (UI2 c772f7c2) is
fast-forward integrated atop clean backend/test/docs **77f7e6d**, preserving0989411
and all prior history. Explicit clean release and Electron ownership release were
verified first. Backend production release **6c68f8cd0627bce69f15f4e995a3cf68fa161215**
adds only the requested `observed-rule-any-protocol-v1`: explicit `*` means TCP+UDP
in one application/process rule, never all IP protocols. Validation, pure matching,
overlap, summaries, previews, history and persistence agree. Existing scope,
principal/identity, process tiers, versioned edits/Delete and replay rules remain.
Legacy implicit wildcard narrowing is rejected `protocol_scope_changed`.
Exact contract: [OBSERVED-RULES.md](OBSERVED-RULES.md#tcpudp-observed-creation-extension).

UI adds a floating quick-set popup, rule-family matrix, Info View composition and
compact cells. One click uses the displayed exact scope, backend preview and same
draft save; verified differences/errors/uncertainty stop the chain. Multiple rules
still require an exact selection; edits preserve target/filter/expiry/version,
stale Delete does not recreate anything. Current old-cap host keeps the explicit
TCP|UDP choice. Limit/priority/quota rows are **static unavailable**, not new policy
features. No Ask action, shaping, bandwidth allocation or new enforcement behavior.
Visual differences/measurements are recorded in `electron/RULE-STATUS.md`; this is
not a claim of complete NetLimiter fidelity.

Evidence reused: UI release real popup/creation, 76 unit checks, synthetic and
read-only host acceptance; earlier process/UDP/watchdog/coexistence evidence.
New bounded backend race/vet checks pass; `.workspace/ap-receiver` real namespace
TCP/UDP IPv4/6 both-direction Allow/Block, process override and sibling/app fallback,
uniform summary, wildcard decision snapshot and owned-only cleanup pass. Scoped
address/port restrictions and scoped/mixed summaries have focused regression tests.
Separate `.workspace/flowgate-any-protocol` source6c68f8c SHA256
`7b8fbbe065001c78641eb2157b747d085a93359eab045fdffe478eb70ab83893`;
no running executable was overwritten. The legacy-edit guard does not change the
receiver-tested wildcard matching path.

Main checkout build/typecheck, **14 focused consumer tests** and sandboxed synthetic
normal/narrow process presentation pass. Logs `.workspace/ui2-r2-{build,tests,presentation}.log`;
synthetic captures `.workspace/pp-28APSb`.
One additional real sandboxed Wayland journey was warranted by the UI release's
inactive-popup Delete fix (then only synthetically tested):
`FLOWGATE_TEST_READY=<fresh fixture>/ready.json FLOWGATE_EXIT_ALPHA=1 node electron/test/rule-status-workflow.mjs`.
It **passes** at exact UI09b5642/backend6c68f8c, including one-click wildcard creation,
process-only target/sibling independence, exact edit/disable/stale-delete/conditional
Delete, narrow view, actual alpha exit, inactive-popup Delete and GUI exit preserving
private daemon. Evidence `.workspace/rule-status-real-qxV6RE`, log
`.workspace/ui2-r2-real-exit.log`. This closes the specific live gap in the UI release
note; no firewall/accounting/expiry matrix was repeated.

Fixture ownership was explicit: UI alone drove `.workspace/ap-ui` until DONE;
backend then cleaned it. Main follow-up used a fresh `.workspace/ap-final-exit` with
one driver. Both supervisors exited0, daemon/instances/peer cleaned and primary+
companion sockets removed. Offline disposable DB/evidence retained only in workspace.

Host read-only before/after summaries match exactly: PID2847094,
generatione47c8938265ebf19cacc1fee5a681c8c, UDPac3056b3b8f3299dce5dc2b57985808f active,
enforcement stopped, rules0. No host restart/upgrade, policy write, collector action,
BPF attachment or networking change in this support round. Deployed60d35a3 already
supports process rules but **does not expose the new wildcard capability**. A later
separately authorized daemon upgrade is required for TCP+UDP one-click mode there;
current normal UI uses the explicit per-protocol fallback. Retained Qt has no
wildcard selector and is guarded against implicit narrowing, not fully migrated.
Normal launch from the main checkout remains:
`scripts/run-electron.sh --daemon /run/flowgate-api/daemon.sock`.

## Current integration: Activity Rule Status (UI 897cd43)

Released UI 897cd43f937998bb2b9ff4a810cf628caf19b36b fast-forwarded onto 99b13fc;
electron-only, pairs with the deployed backend 60d35a3 (no backend change). Reused
UI exact-release real isolated journey; new build/typecheck + 76/76 unit; read-only
host check and normal launcher run passed with host runtime unchanged. Full scope,
evidence paths and remaining differences: [HANDOFF.md](HANDOFF.md) and
`electron/RULE-STATUS.md`.

## Deployed: process-instance rules monitor upgrade (2026-10-18)

Running source **60d35a366ae0104f9131f36916ff4172ef71ce71** (exact-release
`.workspace/flowgate-process`, SHA256
`882556c5c977765b678c4dd09521bef6dc596e4532f6af223fcca073ea4ebd05`, `vcs.modified=false`).
Checkout bfed394 differs from it only in docs/electron, so the receiver/race-tested
release artifact was installed unchanged; no Go tests were rerun.

- Root daemon PID **2847094**, generation **e47c8938265ebf19cacc1fee5a681c8c**,
  `daemon-monitor`. Same sockets (`/run/flowgate-api/daemon.sock`, `.sock.monitor`,
  UID1000/root 0600, dir 0711), same `/var/lib/flowgate/rules.db`, same arguments:
  `serve --socket … --database … --uid 1000 --administrator --udp-helper … --allow-traffic-control`.
  No `--allow-evaluation`: the new `can_control_evaluation` permission is **false**;
  all previous permission fields are unchanged. Observer endpoint remains read-only.
- New capabilities: `process-instance-rules-v1`, `activity-initiation-v1`,
  `daemon-evaluation-v1` (advertised; not granted). Previous ones retained.
- UDP was active before and was restored by one guarded `traffic-start`: helper
  PID **2847108**, collector **ac3056b3b8f3299dce5dc2b57985808f**. Fresh baseline,
  ~0.23s control-path gap, no byte continuity claimed.
- Enforcement **stopped** throughout. Stored rules 0 before/after. Decision Log ok,
  `recording:false`, same log ID. Single database writer; no orphan helpers.

**Attempt 1 rolled back automatically.** The upgrade script's strict permission
equality rejected the additive `can_control_evaluation:false` field; the script
generation-stopped the candidate, reinstalled the retained running executable and
restored UDP (intermediate generation 573821314736bed2e74a26eae899113e). This
exercised the rollback path for real. The check was then narrowed to "all prior
fields equal, only that new field, and false"; attempt 2 succeeded. Two extra
collector restarts/baselines resulted. Evidence `.workspace/process-rollout/`
(`attempt1-*`, `before.json`, `after.json`, `upgrade.log`, `rules-inventory-before.json`).

### Rollback (prepared; path exercised in attempt 1)

`.workspace/process-rollout/flowgate-running-previous` is the exact previous running
executable (source1732584, SHA256 `a666b7dd…2c2681`), exported via generation-checked
`monitor-backup`. `flowgate-on-disk-7020db0` preserves the unrelated previous on-disk
file. Procedure: generation-checked `monitor-stop`, wait for daemon+helper exit,
copy backup to a temp file, chmod 755, rename over `.workspace/flowgate`, launch the
same arguments, restore prior UDP with the new generation.

Schema compatibility: "schema3" is per rule document; the SQLite file stays
`user_version 1`, and the Decision Log changes are additive JSON fields. The 1732584
executable rollback above is valid only **while no process rule is stored**; at this
rollout the inventory was empty, so it applied, and it was actually exercised.

Process rules are session-bound for **enforcement**, but their stored documents are
durable user data: definitions, binding metadata and the inactive inventory survive
restart and are part of the policy record. Deleting them is not a free or routine
rollback step. Once any process rule is stored, an older executable that rejects
schema3 must not be installed. Keep the compatible (60d35a3 or later) executable;
a downgrade first needs a concrete, reviewed data-preserving migration or restore
plan (for example a compatible reader, or an exported and later re-importable copy
of every stored document). Never strip or rewrite `filter.process`, and never
delete user rules automatically, to make an older binary start.

Backup scope: no file-level SQLite backup exists. The DB is root-only, and no
supported root reader exists; adding one would widen the sudo-authorized binary.
`rules-inventory-before.json` is only the authoritative `list` API inventory at
the pre-upgrade generation (zero rules). It records that state; it is not a
database backup or a restore source.

## Current integration: native process-instance rules

Backend **60d35a366ae0104f9131f36916ff4172ef71ce71** and explicitly released UI
**a73276ea4c846f5ea757bd01922a5455787b170a** are fully integrated by fast-forward,
retaining e2f3f29 and all earlier frontend history. UI worktree was clean and
ownership released before integration. No competing frontend edits were made.

Primary `process-instance-rules-v1`: server-issued pidfd/native/session binding,
process tier before application fallback; existing priority/ID order inside each.
Exact contract, permissions, schema3/inactive restart behavior and same-executable
exec limitation: [PROCESS-RULES.md](PROCESS-RULES.md). No PID-only permission or
implicit application widening; process lifetime is session-bound, not persistent.
Preview/save revalidation, versioned edits and conditional Delete retain full target.
Policy-view separates own instance rules and app fallback; Decision Log preserves
immutable actual-target snapshots. Creation never approves existing sockets.

Focused Go race tests pass for identity/policy/daemon/Decision Log/store; vet passes
for those plus hostfirewall/cmd. Real disposable receiver evidence `.workspace/pr-guard`
passes incoming/outgoing TCP/UDP IPv4/6 process Allow/Block versus sibling,
application override/fallback, disable/enable/delete, actual exit/different-executable
exec, inactive restart persistence and historical target snapshots. Exact-release
binary `.workspace/flowgate-process` source60d35a3 SHA256
`882556c5c977765b678c4dd09521bef6dc596e4532f6af223fcca073ea4ebd05`.
Final source adds application metadata labels only after receiver run; actual
verdict logic is unchanged. PID reuse is simulated generation coverage, not an
actual forced PID-wrap experiment. Fork/thread identity cases are deterministic;
no BPF/UDP accounting/watchdog matrix was repeated.

Exact60d35a3 held fixture `.workspace/pr-ui-release` was exclusively driven by UI:
real sandboxed Wayland first process Allow, distinct sibling/parent, application
Block fallback, exact edit/disable/enable/Delete preserving app rules, recreate,
alpha exit, inactive target/stale draft and input focus, GUI exit preserving daemon.
Evidence UI worktree `.workspace/process-rules-real-rbmfwl`; final surviving beta
narrow capture shows fallback only. UI explicitly sent DONE before backend cleanup;
supervisor exited0, both sockets removed, both instances/peer gone. Disposable
inactive/app records remain only in ignored offline evidence DB. UI initial runner
association-settling failure was corrected; only its final passing run is accepted.

Main-checkout build/typecheck, **23 focused frontend checks**, and sandboxed
**synthetic** process presentation pass (normal/narrow, exit, input/focus, no mutations).
Logs `.workspace/process-integration-{build,tests,presentation}.log`, captures
`.workspace/pp-nf0PUV`. Exact real UI/receiver evidence reused; no additional matrix.
This proves scope correctness, not overall NetLimiter visual fidelity or support
for its unsupported policy families. UI intentionally permits inactive Delete only;
backend also permits disabling inactive records, never re-enabling/rebinding them.

Read-only host check: same PID2201352/generation0840f7c256126f1708702f27c5b26551,
UDP43a091abb81a09901be2c9b460080ee1 active, enforcement stopped, rules0. No host
restart, executable replacement, policy write, collector interruption or BPF attach.
The deployed1732584 build **does not expose process-instance-rules-v1**. A future
separately authorized daemon upgrade is required; current host UI explicitly gates
this workflow rather than approximating process-only with application-wide scope.
Normal main-checkout launch remains:
`scripts/run-electron.sh --daemon /run/flowgate-api/daemon.sock`.

## Current integration: selected rules, quick setters and observed initiation

Full released frontend **d3268a4f94716c6b21314757736171c1e8dd1a48** is integrated by
fast-forward atop backend **b9840d01096d156d92ce515bd69a07fef443eef6** (retaining
4105194). Clean checkpoint and explicit ownership release verified first. Backend
adds only `activity-initiation-v1` observation evidence; existing policy-view
inventory and preview/versioned-save/conditional-delete contracts are reused.
UI shows all relevant scoped/disabled/expired rules for selected application,
process or supported socket, with explicit application-wide scope; it does not
pretend to support process-instance permissions. Live NetLimiter process-only
behavior is recorded as a separate bounded proposal in PLAN.md, not implemented.

Backend focused identity+daemon race tests/vet passed. Real authenticated private
TCP4/6 handshake fixture verifies observed incoming/outgoing retention into
established sockets, honest preexisting unknown, neutral listener/UDP and read-only
capability. Exact binary b9840d0 SHA256
91339fece1dacb077cfe7ff497ce282b9757f92d51cc15ec20fd21fef43bad06.
Fixture metadata and API rows: `.workspace/direction-ui-release/ready.json` and
result.json. UI alone drove mutations until explicit DONE; backend then touched
quit, supervisor exited0 and daemon socket was removed. Offline disposable rules
remain only in the ignored fixture database/evidence; no runtime owner remains.

Exact-release actual sandboxed Wayland journey reused from UI worktree
`.workspace/activity-rules-real-28BVUv/`: first rule without pending, three scoped
rules across directions, app/process/socket complete inventory, quick exact edit,
disable/re-enable preserving expiry, conditional Delete preserving siblings,
input/focus and read-only denial, GUI exit preserving daemon. Actual observed
TCP4/6 rows:2incoming+2outgoing. Not a new firewall verdict/receiver claim; settled
enforcement/UDP matrices reused. UI recorded its own Windows fixture cleanup.
New integrated checks: Electron build/typecheck,18 focused consumer tests and
sandboxed **synthetic** presentation runner pass (multiple scopes/disabled/expired,
selection/control refresh/read-only/disconnect); captures `.workspace/presentation-nYl0Sa`.
Logs `.workspace/activity-round2-{build,ui-tests,presentation}.log`.
No broad matrix repeat or claim that backend completion proves visual fidelity.

Host read-only final check: root peerPID2201352,
generation0840f7c256126f1708702f27c5b26551, UDP collector43a091abb81a09901be2c9b460080ee1
active, enforcement stopped, zero stored rules. Host executable/daemon/collector
never replaced/restarted/interrupted; no host policy writes. Old deployed1732584
**does not expose activity-initiation-v1**: known-direction arrows require a later
separately authorized rollout. Current UI uses explicit unknown on that old daemon;
rule inventory/create/edit support already exists there. Normal launch:
`scripts/run-electron.sh --daemon /run/flowgate-api/daemon.sock`.

## UI support integration: Activity composition and launcher separation

Released frontend **85364c94f170f88eede9fc79111ab98143f4ba48** is integrated in full
by fast-forward from backend bridge release **29436689afdaf86a8021558c27284e2c7c4bb3e7**,
retaining7020db0. Explicit clean checkpoint/ownership release verified. Adds an
observation-only overview, separate compatible TCP/UDP source totals/history,
compact policy/details composition and launcher diagnostics/Wayland graphics fix.
No new policy, attribution or accounting API was necessary. Shared bridges now
accept only the fixed --backend enum; Qt defaults unchanged. Normal Electron
builds electron-backend instead of overwriting the host-approved flowgate path.

Main-checkout build/typecheck,14 focused frontend checks,4 mocked bridge checks
and sandboxed Wayland measured presentation journey passed. Presentation fixture
is **synthetic**, not new kernel/receiver evidence; settled real evidence reused.
Logs: .workspace/ui-support-integration-{build,tests}.log,
ui-support-bridge-tests.log and ui-support-integrated-visual.log; captures in
.workspace/ui-support-integrated-visual/after. UI exact-release normal-host launch,
hardware/sandbox and exit evidence are in electron/ACTIVITY-COMPOSITION.md and
LAUNCH-DIAGNOSTICS.md. This does not prove overall NetLimiter fidelity.
No host daemon/collector lifecycle or host-policy operation was performed; deployed
source remains1732584 with active UDP/stopped enforcement. No rollout in this task.
Backend remains available for concrete UI dependencies; larger shaping/history/
quota/filter features need separate scoped proposals. Launch from main checkout:
`scripts/run-electron.sh --daemon /run/flowgate-api/daemon.sock`.

## Current checkout: evaluation, real UDP continuity and measured Activity integrated

Merge **11316c52b5f5f8a341d0f215d49ff2c7ce718072** integrates released visual
UI **1a53e355dd67933ac8cfc872ed6d4b12202b3bb9** into backendb4aaf82. It retains
full evaluation UI81c0aaac7a2245d4f0f3737bbcd0698413151c63,
backendbfa93b6a695fb1928b0f7d55b4aff5cd1d71f626 and measured reference
bf3b79d83aaf60ad4c851bb14d1642b59a643012. Frontend ownership was explicitly
released and its exact clean checkpoint checked before merge; no conflicts or API changes.

### Passed real-BPF continuity (reused, not rerun)

User-run `.workspace/evaluation-udp-1792313673-2574300` tests source
b4aaf82dcbad77d68819b61a6a8c2ae8ef1956f4. Binary SHA256
2bc9560ae648b5bbd299ad1764cad01131c43ca9e0adc0d37178c05c1d9a1b87;
native helper118a8877d7b58dba43f20622064e3b60c38138a3453cf4a9aa87305720ab205c.
Inspected `continuity.json`, source/artifact hashes, verification log and matching
route snapshots. Six registered UDP4/6 connected/unconnected socket records retain
IDs and observed-since baselines before/during/after incoming evaluation. Same daemon
351e14b015741c69fba93b72b68f11a1, helperPID66 (fixture PID namespace), collector
b914a94298fdfc998a95dd11501a207f survive Start/Stop. Exact final socket-API totals
sum to25,668 uploaded and25,668 downloaded bytes; they are not remote-delivery proof.
Separate incoming receivers show Allow1/Block0. TCP exchange and actual Decision Log
outcomes remain available. Stop confirms owned-only cleanup; foreign nft objects and
all route fields are unchanged. No host endpoints, collector or database were used.
This closes the active-BPF continuity gap; previous syntax and asynchronous IPv6
setup failures are documented in DAEMON-EVALUATION.md, not passing evidence.

New merge checks: Electron build/typecheck and actual sandboxed Wayland
`node electron/test/activity-measured.mjs` passed. Its rows/traffic are explicitly
synthetic; real kernel/receiver evidence above is separate. Reuse exact-release UI,
five-minute expiry, watchdog, Tailscale-shaped compatibility/refusal and other settled
matrices. No kernel suite or full acceptance matrix was rerun for this visual merge.

### Host unchanged; future rollout only

Read-only API confirms generation0840f7c256126f1708702f27c5b26551,
active collector43a091abb81a09901be2c9b460080ee1, enforcement stopped, zero stored
rules and explicit UID1000 administrator/collector control. The host still runs
source1732584 and lacks daemon-evaluation-v1. No daemon restart, executable replacement,
collection interruption, rule write or firewall/routing action occurred in this task.
Separate combined candidate: `.workspace/flowgate-integrated-candidate` (build with
scripts/go-env.sh sourced); source/hash manifest is kept beside it.

**Do not execute the following rollout until separately authorized.** It interrupts
monitoring and UDP collection briefly but does not activate enforcement:

1. Re-read authoritative generation, permissions, stored rule IDs/versions/expiry,
   collector state/helper identity and actual launch configuration. Require stopped
   enforcement. Record this state and retain the then-current running executable:

   ```sh
   mkdir -p .workspace/evaluation-rollout
   sudo -n /home/flowgate-user/Apps/flowgate/.workspace/flowgate monitor-backup \
     --generation <verified-current-generation> > .workspace/evaluation-rollout/flowgate-previous
   ```

   Verify this backup is a nonempty executable and record its hash and exact current
   arguments. Do not use an older rollback artifact as a substitute. Keep rules.db
   in place; no live SQLite copy is needed. Any additional backup must use the
   consistent SQLite backup procedure, not a bare database/WAL file copy.

2. Use generation-checked shutdown; wait for the verified daemon/helper to exit
   and database lock to release. Atomically replace only the stopped executable:

   ```sh
   sudo -n /home/flowgate-user/Apps/flowgate/.workspace/flowgate monitor-stop \
     --generation <verified-current-generation>
   # Only after confirmed exit and successful candidate/hash checks:
   cp .workspace/flowgate-integrated-candidate .workspace/flowgate.next
   chmod 755 .workspace/flowgate.next
   mv -T .workspace/flowgate.next .workspace/flowgate
   sudo -n /home/flowgate-user/Apps/flowgate/.workspace/flowgate serve \
     --socket /run/flowgate-api/daemon.sock --database /var/lib/flowgate/rules.db \
     --uid 1000 --administrator --allow-evaluation \
     --udp-helper /home/flowgate-user/Apps/flowgate/.workspace/udp-collector --allow-traffic-control
   ```

   Run serve under the established owned background launch procedure (or a dedicated
   terminal), without installing a service. Never launch a second database writer.
   Startup grants evaluation authority but **does not start interception**. Restore
   UDP only if active immediately before shutdown, through UID1000 primary API:

   ```json
   {"version":1,"operation":"traffic-start","generation":"<new verified daemon generation>","collector_generation":"<current traffic_monitor.generation, initially empty>"}
   ```

   Reconcile by list after ambiguous replies; do not blindly replay. Verify one helper,
   active UDP, unchanged rules/permissions, stopped enforcement and new capabilities.
   A new collector generation/baseline and collection gap are expected across restart.

3. On startup failure, inspect the actual error. Stop any verified partial candidate
   through its generation if it is running; wait for daemon/helper exit. Copy the
   retained `flowgate-previous` to `.workspace/flowgate.next`, set755 and atomically
   rename to `.workspace/flowgate`. Launch with the **retained original arguments**
   (currently without --allow-evaluation), same database/endpoints/UID/admin/helper,
   and restore prior active UDP through the new generation-checked API. Do not change
   or delete either database. Rollback is prepared, not executed/tested in this task.

A later explicit UI readiness/review/Start is separate from deployment. Incoming-only
Tailscale restrictions, unchanged-config-during-session limitation, watchdog and
five-minute deadline remain. No live encrypted-tailnet enforcement claim is made.

## Deployed: Decision Log rollout completed

```sh
cd /home/flowgate-user/Apps/flowgate
scripts/run-electron.sh --daemon /run/flowgate-api/daemon.sock
```

Released UI `ba4862b065dc7e092ccba253a0afc591f8e81afd` was merged in full as
**`1732584b7ba181ceeffb06fb92cdbbd8aa10b078`**. This is the running binary's
source revision (`vcs.modified=false`). It includes Decision Log backend028ca809,
correctness fixef1d237 and prior UI18ca65a. Later documentation-only commits do not
change the deployed source or require another restart.

### Actual runtime

- Root Go daemon PID **2201352**, generation **0840f7c256126f1708702f27c5b26551**.
- Running executable SHA256 **a666b7dd1e8aa5c7c8c955f262fcb4da47a959d3c0884421ff78e294279c2681**,
  verified by generation-checked export of the actual process executable.
- Primary `/run/flowgate-api/daemon.sock`; read-only companion `.sock.monitor`.
  Both remain UID1000/root group, mode0600; runtime directory root0711.
- Same `/var/lib/flowgate/rules.db`, root0700 storage directory. Authoritative
  rule inventory was empty before and after. No rule test writes or database
  migration/copy occurred. Exclusive database ownership passed through orderly
  shutdown; no live SQLite/WAL file was copied and no second writer was started.
- Selected UID1000 retains explicit administrator/machine visibility, rule
  management and collector-control grant; `can_decide:false` in monitoring mode.
- Enforcement **stopped** throughout; no NFQUEUE/firewall activation.
- UDP **active**, one daemon-owned native helper PID **2201368**, generation
  **43a091abb81a09901be2c9b460080ee1**. Reviewed helper source SHA256
  `118a8877d7b58dba43f20622064e3b60c38138a3453cf4a9aa87305720ab205c` is unchanged.
  Existing partial/unregistered-cookie coverage limitations remain.
- `decision-log-v1` advertised alongside existing policy/creation/conditional-delete/
  daemon-UDP capabilities. `/var/lib/flowgate/decisions.db` is a separate private
  log. Health **ok**, `recording:false`, empty history, zero reported drops/write
  failures. Log ID `51895974a3befdf96c212db757be8718`. Empty is expected: monitoring
  makes no firewall decisions. Crash loss remains unbounded in time, not a 1s guarantee.

### Controlled procedure and collection gap

The exact running old executable (f9c446c1...) was retained before interruption.
Old daemon2152405 generation4e18ec0723edb676c156a6b0ae4e9db9 and helper2155270
were verified, generation-stopped and exited. Only then was the prepared candidate
atomically renamed to `.workspace/flowgate` (no running inode was truncated) and
started with the same arguments. The former active UDP state was restored by one
UID1000 generation/collector-generation guarded `traffic-start`; no duplicate
helper or policy daemon was launched. The measured stop-to-collector-active control
interval was about **0.22s**. This is not an exact packet-measurement gap: collection
was interrupted and the new collector has a **fresh accounting baseline**, with
no claim of byte continuity or reconstructed traffic.

Actual launch (same permissions/configuration as before):

```sh
sudo -n /home/flowgate-user/Apps/flowgate/.workspace/flowgate serve \
  --socket /run/flowgate-api/daemon.sock --database /var/lib/flowgate/rules.db \
  --uid 1000 --administrator \
  --udp-helper /home/flowgate-user/Apps/flowgate/.workspace/udp-collector --allow-traffic-control
```

Do not run that command while this daemon owns the database. Fresh daemon startup
still leaves UDP disabled until an authorized explicit Start; this rollout restored
it only because it was active immediately before interruption.

Exact deliberate Stop (not performed after this rollout):

```sh
sudo -n /home/flowgate-user/Apps/flowgate/.workspace/flowgate monitor-stop \
  --generation 0840f7c256126f1708702f27c5b26551
```

### Rollback and evidence

Private workspace artifact `.workspace/decision-log-rollout/flowgate-running-previous`
is the exact old running executable, SHA256
`f9c446c1ede22ced0fff9b08281aabacda7ef14ea0c4adead926c89c93cf1b4c`.
`before.json` and `launch.json` retain the previous exact arguments, helper hash,
permissions, rule inventory and collector state. `flowgate-on-disk-previous` also
preserves the prior on-disk binary, which differed from the running inode.
The separate candidate remains `.workspace/decisionlog-build/flowgate-rollout-candidate`.

If rollback is needed, generation-check Stop of the verified current monitor, wait
for daemon/helper exit, atomically place a copy of the retained running executable
at the sudo-authorized `.workspace/flowgate` path, then launch with the same serve
arguments above. Use its **new** generation to restore the formerly active UDP
state through guarded `traffic-start`. Do not blindly reuse a token, overwrite a
live executable, or run a competing database owner. Startup succeeded, so rollback
was not exercised. The rule database schema/file is unchanged; the new separate
history file does not affect the older monitor.

New checks: build/typecheck, 11 focused model tests, synthetic sandboxed Wayland
navigation/copy/normal+narrow rendering. Reused32e7fa9 evidence: Go race/vet and
real isolated284-record paging/detail/filter/live/restart/receiver behavior; no
firewall, ownership or UDP matrix was rerun.

Actual UID1000 host API: private sockets, administrator/companion permission
separation, TCP Activity and measurements, both history reads, empty healthy log,
unchanged rules and active UDP. Actual sandboxed Wayland Electron: Activity usable,
Decision Log supported with correct empty/non-recording explanation; closing the
verification GUI preserves independent daemon/collector generations and rules.
No host test rules, synthetic history imports or enforcement traffic tests.

Evidence `.workspace/decision-log-rollout/`: `prepare.log`, `before.json`,
`upgrade.log`, `launch.json`, `after.json`, `uid1000-verification.json`,
`host-smoke.log`, `host-ui-result.json`, `host-decision-log.png`. Screenshot shows
**real host monitoring with empty decision history**, not enforced traffic.
Focused UI logs `.workspace/dlog-rollout-ui-tests.log` and
`.workspace/dlog-rollout-ui-display.log` (synthetic `.workspace/synlog-1LF76i`).

Live firewall activation/coexistence and live sudo evaluation remain unverified.
The authorized action here was one monitor upgrade and restoration of user-enabled
UDP collection, not protection. No Tailscale/routing/firewall/security, service,
autostart, package or sudoers changes. Incoming-only Tailscale limitation remains.

## Historical integration evidence

Backend policy explanations0aca36145adc857bdb59d52f1862a420bbdac9cf and verified
observed creation8ef90cde66c73c69bf8fd8b686e82d2298b98536 were preserved. The full
released frontend series was merged, not copied or tip-only cherry-picked:

- cc9ce4e794c473844aa66683875a955337a95fa5: traffic graphs.
- b8678fa1d306e652fb56bf582b07dd856099f1cc: visual refinement/rate sorting.
- 6c176474f9cc016105b16ea26712fa8a8aa9b082: palette/icons/scoped inventory.
- 1dbfef6d17a826132de315dfabfbe10fa4874dbc: permission-aware daemon connection.
- 3193056c407e848310a1f0431c35473942efdf91: backend policy summaries.
- 02554da757942887f3dff8b4c633bcd0f824a1b9: preview-bound first-rule creation.

Merge checkpoint e2ef7f734a102bbaa39a08ff43d3a81ed33e9899, with no conflicts.
Backend rollout utility03ff71f exports the exact running executable for rollback.
Final documentation commit is reported outside this file; no self-hash loop.

## Historical rollout verification

From the integration checkout, built Go/Electron and ran:

```
FLOWGATE_TEST_DAEMON="$PWD/.workspace/flowgate" \
  node electron/test/creation-workflow.mjs
```

Actual sandboxed Wayland + separate disposable root daemon/database: initially no
rules or pending requests, authoritative Activity summaries, first incoming and
outgoing scopes/preview/save, stored-only status, versioned edit, conditional delete,
policy refresh, actual preview expiry and lost-ACK list reconciliation. A second
read-only client connected after closing the first, proving independent daemon
survival. No full enforcement/accounting/frontend matrices were repeated.
Evidence `.workspace/monitor-rollout/integrated-wayland.log` and
`.workspace/creation-ui-ywyKVd/` (isolated screenshots, not host enforcement).

Before stopping the old daemon, authenticated root peer/current generation/arguments
and stopped state were checked; rule IDs/versions/absolute expiry recorded. The
inventory was empty and remained empty. The old process executable was already a
deleted inode differing from the on-disk binary. It was retained exactly using:

```
sudo -n /home/flowgate-user/Apps/flowgate/.workspace/flowgate monitor-backup \
  --generation <confirmed generation> > <private workspace backup>
```

This new root-read-only command validates the fixed secure monitor socket, root
SO_PEERCRED, exact generation, daemon-monitor/stopped response, and copies the
peer's open executable FD to stdout (64MiB bound). It accepts no PID or file paths,
writes no privileged paths and never stops anything. The ordinary shell owns the
backup destination. Wrong generation/non-root/extra-path invocations refuse.
Exact retained executable:
`.workspace/monitor-rollout/flowgate-running-previous`, SHA256
b327af50f8db64ea0a56c592e299e4b69638b4aee202049f77c83308221090d2.
Launch configuration and before/after metadata: same directory, private `before.json`
and `after.json`. Old monitor was generation-stopped and fully exited before new
serve acquired the same exclusive database lock. No competing DB writer was used.
A rollback procedure was prepared; startup succeeded, so rollback was not needed.

Actual UID1000 host checks confirmed the new generation, both capabilities
policy-explanations-v1/observed-rule-create-v1, machine administrator visibility,
private socket ownership/modes, stopped enforcement and companion mutation denial.
Actual sandboxed Wayland against these endpoints loaded live Activity and authoritative
policy; one workspace-owned listener was filtered and a restricted incoming Block
was **previewed only**. No Save or other real-database mutation was performed.
After GUI exit, daemon/generation and exact rule inventory were unchanged.
The exact normal launcher command also opened the Wayland application; its owned
verification GUI was closed separately without stopping the daemon.

Host preview evidence `.workspace/monitor-rollout/host-ui.log`, `host-ui-result.json`,
`host-preview-only.png`; screenshot shows real monitor data for the controlled
listener, not an enforced event. Only bounded summary metadata was retained; no
unrelated host arguments/environments or full inventories were archived.

## Remaining limits (including prior rollout evidence)

Live firewall activation/sudo evaluation, encrypted live-tailnet traffic and
privileged UDP activation through Electron remain unverified. Root observation
alone is not enforcement. First-rule creation requires a live supported native
single-holder target in the daemon's net/mount namespaces. Known shared/runtime/
unknown targets reject; snapshot inspection is not hostile-process race immunity.
TCP/UDP measurement coverage and separate UDP collector restrictions are unchanged.
Desktop refinements and icons are integrated.

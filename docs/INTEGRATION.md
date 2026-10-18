# Integrated desktop and non-enforcing root monitor

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

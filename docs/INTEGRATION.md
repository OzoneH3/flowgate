# Integrated desktop and non-enforcing root monitor

## Evaluation integration base and pending real-BPF continuity check

Clean integration base **90cbac500fb96542bb8adcd22d7c2307d8082b1e** includes backend
**bfa93b6a695fb1928b0f7d55b4aff5cd1d71f626**, full released evaluation UI
**81c0aaac7a2245d4f0f3737bbcd0698413151c63** (merge6c936d2), and measured reference
**bf3b79d83aaf60ad4c851bb14d1642b59a643012**. The UI owner advanced independently
from this base for the Activity visual pass; that moving pass is not integrated.
No API or enforcement implementation changed in this integration increment.

New focused fixture: `scripts/check-evaluation-udp.sh`. It builds only the separate
`.workspace/flowgate-eval-udp` binary and reuses the reviewed native helper/UDP
fixtures. It creates fresh network/PID/private mount namespaces, a separate
runtime/database, controlled UDP4/6 socket-API transfers, a TCP control connection,
and veth Allow/Block receivers. It checks daemon/helper/collector identity and
observed-since baselines across incoming Start/Stop, exact final cumulative fixture
byte counts, real Decision Log outcomes, TCP availability, unchanged foreign
rules/routes and owned cleanup. It never opens the host API or restarts its helper.
The native tracing hooks may attach globally but registration/counters are scoped
to this fixture's network namespace; the host collector is not reused or stopped.

**Kernel result remains unverified.** The one attempted noninteractive launch
stopped at `sudo: a password is required`, before unshare/fixture/BPF execution.
Evidence: `.workspace/evaluation-udp-1792310361-2539650/` (source/artifact hashes).
A sudo command-list query had succeeded; that did not establish permission to
execute the concrete unshare command. No repeated noninteractive attempts were
made. Minimum next action, from the main checkout:

```sh
cd /home/flowgate-user/Apps/flowgate
scripts/check-evaluation-udp.sh
```

Enter authentication for the existing isolated harness if requested. This is a
fixture run, **not host activation**. A successful run writes `continuity.json`
and `verification.log` under the printed fresh workspace evidence path. On failure,
inspect that path's `daemon.log` and actual error before retrying. The test does not
repeat the settled300s deadline, broader UDP protocol matrix or visual matrix.
Until this command passes, active real-BPF continuity is a coverage gap, not a claim
established by the existing collector-lifecycle model or syntax checks.

New checks: integrated Electron build/typecheck and8 focused evaluation tests
passed; Python compile and shell syntax passed; separate Go build passed. Reused
exact-release real Electron journey, evaluation expiry/receiver/watchdog/rollback/
Tailscale component evidence and previously verified UDP adapter behavior. No new
kernel counters or receiver results are claimed from the blocked launch.

Read-only host check: daemon generation0840f7c256126f1708702f27c5b26551,
collector43a091abb81a09901be2c9b460080ee1 active, enforcement stopped, zero stored
rules. Primary retains UID1000 administrator/machine visibility and explicit
collector control. Host still advertises Decision Log/policy/creation/UDP capabilities
but **not daemon-evaluation-v1**. Existing partial/unregistered-cookie UDP coverage
remains explicitly reported. No daemon restart, executable replacement, collection
interruption or host firewall/BPF/routing action occurred.

Future deployment requires a separately authorized controlled rollout, using the
procedure below: verify current generation/configuration; retain the **then-current
running executable** and arguments for rollback; generation-Stop and wait for
helper/database release; atomically replace the stopped executable with the prepared
build; start with the same database, endpoints, UID1000 administrator/helper/control
settings plus `--allow-evaluation`; restore formerly-active UDP via guarded Start.
Never copy a live SQLite file without its consistent backup procedure and never
start a competing database writer. If startup fails, restore the retained exact
executable/configuration and former collector state. Collector restart has a new
baseline, not byte continuity. Existing rollback artifacts below refer to the prior
Decision Log rollout, not a backup of this future rollout's running executable.

The future serve command is in [DAEMON-EVALUATION.md](DAEMON-EVALUATION.md#future-host-procedure--not-executed).
**Deploying `--allow-evaluation` grants authority only; it does not start enforcement.**
A separate deliberate UI review/readiness/Start is required; incoming-only Tailscale
limitations and original five-minute deadline remain. Neither step was executed here.

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

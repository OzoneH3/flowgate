# Deployment and release preparation

The supported deployment commands are:

```sh
scripts/prepare-release.sh                 # matched backend and Electron
scripts/prepare-release.sh --backend-only  # backend only
scripts/update-and-start.sh                # prepare, install, verify, activate
```

To start the desktop user's GUI automatically at login, use:

```sh
scripts/update-and-start.sh --local --profile preserve --autostart
```

After the matched GUI reports it loaded, this writes the current user's
`$XDG_CONFIG_HOME/autostart/flowgate.desktop` (normally
`~/.config/autostart/flowgate.desktop`). It launches the GUI in its existing tray
mode using the new login's desktop environment. It does not start protection or
change permissions. Future GUI updates refresh this managed entry to the matched
release; disabling it in desktop settings is preserved unless `--autostart` is
explicitly used again. An unrelated existing entry is never overwritten. Remove
the entry or disable it in desktop startup settings to stop login startup.
The release directory must remain available at login.

Upstream updates are noninteractive and have a 60-second timeout (with up to five
seconds for forced cleanup). Failure stops before preparation, authentication or
protection changes. Use `scripts/update-and-start.sh --local` to deliberately skip
upstream access and install the current committed local master; it still requires
a clean master branch. Interrupting the fetch does not stop the installed daemon.

Preparation requires clean master, builds collectors from current source, and
records current race/vet evidence. It never installs or activates protection.
Bundle paths remain `.workspace/daily-releases/<revision>` and
`.workspace/automatic-zone-releases/<revision>`. Existing bundles are hash-checked
before reuse. The old installer that combined installation with host acceptance
is retired and no longer shipped.

For a deliberate monitoring-only install use
`python3 scripts/install-prepared.py --bundle PATH`. It snapshots selected bytes
before authentication and uses isolated system Python with root-owned staging.
It refuses active protection or foreign units, quiesces the old writer, backs up
state, and verifies the new build in monitoring. Startup migrations are checked
against exact allowed rule transitions. If replacement fails, a verified previous
release and its matching database snapshots are restored together. Only a verified
rollback allows the updater to restore the previously active protection mode.
A failed rollback leaves explicit recovery instructions and retained evidence.

See [scripts/README.md](../scripts/README.md) for current command options, trust,
rollback limits, and test coverage. Monitoring/rollback tests exercise real SQLite
and files with mocked service/API boundaries. They do not claim a live host
rollback or reboot test. Live acceptance remains a separate explicit action.

## Historical implementation and incident notes

The notes below describe earlier checkpoints and host states. They are retained
as evidence, not current commands or rollout instructions. In particular,
statements about pinned helper binaries, absent host installation, the former
acceptance installer, and no database rollback have been superseded above.

## Essential preset implementation at the earlier checkpoint

The authoritative schema5 preview/apply/status/removal workflow and interface-scoped
DHCP guard are implemented. See [ESSENTIAL-NETWORKING.md](ESSENTIAL-NETWORKING.md)
for current permissions, exact API, update semantics and focused evidence. This
supersedes the historical review-only planner and blanket-DHCP descriptions below.
Host service currently absent; protection remains off. No preset permissions were
applied on the host. Exact running service identity export/review, matched install
in monitoring and focused protected-host usability acceptance remain separate.


## Operational incident: protection remains off pending essential policy review

The04c5159 install reached active both-direction protection, but default-deny with
no approved essential rules disrupted real use. User recovery and uninstall are
recorded08:24:33–08:24:38; current daemon/units are absent, host DNS works, NM,
resolved and Tailscale are active. Do not auto-reactivate or describe this as a
daily-ready installation. See [SYSTEM-NETWORKING.md](SYSTEM-NETWORKING.md).

The failed Activity action was `rule:preview` returning `stale_target`, before Save.
A real private-mount service rejection is fixed with target-bound namespace
verification; exact incident PID/executable needs the root-private export. The
review-only DNS preset grants no permissions automatically. Future installer
completion returns to persisted monitoring even after receiver checks pass.
Existing receiver/kernel/UI evidence is reused; host preset activation is pending
exact identity/VPN evidence, review and focused real DNS/application acceptance.


This increment adds continuous incoming/both-direction operation, not a longer
five-minute evaluation. `CONTINUOUS.md` is the API/failure contract. The matched
UI includes released ce8bb0f, continuous checkpoint4e93f8e and its accepted followups.
The earlier real kernel TCP collector evidence and zone/process/UDP matrices are
reused. No host install or reboot is claimed by this preparation document.

## Installation and exact identity

`scripts/prepare-release.sh --backend-only` requires a clean master and builds an immutable-
hash bundle under `.workspace/daily-releases/FULL_SHA`. It reuses the accepted UDP
and TCP helper binaries, compiles native test programs and includes typed control,
local recovery, unit/configuration and focused host acceptance adapters. The
manifest records source/hash/evidence. `flowgate version` and API `build` report
executing source and SHA256. Source files in the checkout are never the service's
executables; no running inode is overwritten.

The one authenticated install command printed by preparation performs root
readiness first. Refusal preserves the old runtime. It snapshots the old executable,
arguments and online SQLite backups under `/var/lib/flowgate/backups/FULL_SHA`,
then installs root-owned `/usr/local/lib/flowgate/releases/FULL_SHA`, atomically
sets `current`, stages/validates units, generation-stops the old writer, and starts
monitoring before explicit acceptance activation. No two writers share a database.
New schemas are never made readable by deleting process/zone records or restoring
an older database over newer policy. Previous artifact and data remain for review.

The focused host stage uses only dedicated native receivers and its fixed veth
peer, exact test rules, current readiness and original administrator UID1000.
It verifies Allow+delivery/Deny0 in both directions/families, remembered policy,
process override/inactive-after-restart, same-peer zone reclassification and another
executable. It restores original zone config and deletes exact test rule versions.
Failure preserves evidence and invokes local monitoring recovery, never declares
continuous protection passed. Root authentication is not available to the agent;
no repeated sudo attempts or sudoers change is used.

## Actual host adapter and startup failure policy

Observed CachyOS uses NetworkManager; networkd is disabled. Tailscale and bpftune
are enabled. `flowgate-guard.service` is before network-pre/NetworkManager/Tailscale,
and a FlowGate-owned NetworkManager drop-in **Requires** the guard with ordering.
This explicit dependency, not just Before=network-pre.target, prevents normal NM
startup after guard failure. The guard persists on daemon initialization/crash
failure and blocks new local TCP SYN/unestablished UDP; existing connections and
narrow DHCP bootstrap are preserved. Non-TCP/UDP and forwarded/other-namespace
traffic are not covered. Initramfs/pre-unit traffic and other network managers are
not guaranteed; no claim of full early-boot containment or reboot acceptance yet.

The actual daemon starts after NM, Tailscale and bpftune. This avoids a cycle:
bpftune itself is after network.target. While these dependencies start, the guard
holds new supported TCP/UDP. bpftune is Type=simple, so unit ordering alone is not
callback readiness: the root launch adapter waits for the observed connection-tuner
program inventory to settle before shared TCP attachment. Missing/unstable inventory
disables that optional source for this start, explicitly logged, rather than
weakening the foreign-program check. Enforcement remains independent. Accepted
running-session helper proof is reused; cold-boot callbacks remain a reboot check.

`flowgate.service` sends systemd READY only after rules/API and desired hooks are
ready (or deliberately monitoring). Crash restarts are bounded; repeated failure
leaves the guard and a failed service for local recovery. Optional collector loss
never bypasses enforcement. Queue/pending timeout denies without a GUI; saved rules
continue without Electron. Stop saves monitoring before cleanup; ordinary service
restart preserves desired protection, but process-instance permissions become
inactive and remain in inventory. Rules do not terminate existing admitted TCP.

Foreign nftables, Tailscale routing/marks and bpftune programs are not changed.
Supported Tailscale remains the inspected1.104.1 client profile with no exit/subnet
routing. No application/transport blanket exemption is installed. New root service
traffic can prompt; administrator decisions remain necessary. Existing admitted
transport sessions are preserved. Host acceptance must report actual state rather
than infer encrypted tailnet delivery from the simulated TUN component.

## Commands after successful installation

```sh
scripts/run-electron.sh --daemon /run/flowgate-api/daemon.sock
flowgate-control status
systemctl status flowgate.service flowgate-guard.service
journalctl -u flowgate.service -b
flowgate-control stop                    # intentional monitoring, persisted
flowgate-control both                    # explicit new Start; inspect status
sudo /usr/local/sbin/flowgate-recover     # local API-independent monitoring recovery
sudo /usr/local/sbin/flowgate-uninstall   # remove startup/daemon; preserve all data
```

Recovery is root-owned, uses fixed installed paths, saves monitoring atomically,
stops the service, verifies absence of the recorded consumer and removes only its
owned table/marks/guard, then starts monitoring/UDP again. Guard ownership binds a
root-private random token, network namespace and structural digest; a foreign or
modified guard refuses automatic removal for local inspection. Empty-state recovery
is a safe no-op. It does not depend on
network, GUI or a working API. Uninstall first recovers, stops/disables the two units
and removes only unchanged FlowGate unit/drop-in files. Policies/backups/releases
are preserved. Do not merely disable the daemon and leave the NM guard dependency
or a fail-closed table without understanding the result.

## Evidence and remaining boundaries

- Real isolated TUN/conntrack/NFQUEUE with simulated Tailscale configuration:
  `.workspace/continuous-component-i290r4k2/result.json` and
  `.workspace/continuous-component-f4fozgp6/result.json`; the latter remained active
  for310 actual seconds without GUI. Both direction/family TCP+UDP deliveries and
  blocked receivers, replies/masks, expiry, Stop, actual SIGKILL/stale recovery,
  foreign rule/routing preservation passed.
- `.workspace/daily-adapter-mwjqsow3/acceptance/result.json`: production acceptance
  driver exercised real private receiver/policy/identity/zone paths, using a
  **simulated systemd restart adapter**, not host systemd. Labels explicitly distinguish isolated receivers from host acceptance.
- `.workspace/daily-adapter-4vvk7z28/failure-result.json`: actual private guard
  prevented delivery before/during unsupported-tunnel initialization refusal;
  local owned recovery restored delivery. Unit syntax/dependency resolution lint
  passed with present candidate executable paths. Installed unit graph and boot
  still require privileged stage/reboot checks.
- Real sandboxed UI `.workspace/worktrees/electron/.workspace/continuous-real-5migP3/`
  passed concurrent prompts, expiry, queued selection, no Enter decision, lost ACK,
  reconnect, exact rule cleanup, GUI exit retaining active enforcement and explicit
  Stop. Backend independently verified generation/rules0 and cleaned its fixture.
- Earlier retained-identity rejection remains unexplained. Revalidation was not
  relaxed; current TCP admissions passed isolated checks. Host failures capture
  fresh attribution/Decision Log before any rerun.

Zones retain explicit configured-prefix semantics; no zone byte totals. Unknown
classification is not Internet. No process-only pending Remember or stored Ask.
BPF event coverage remains partial (pre-existing/closed-before-snapshot unknown).
UI source reliability improvements do not prove every intermittent stall resolved.

## Reboot acceptance (only after installed host acceptance passes)

One user action: reboot when convenient; no agent reboot.

After login, **before opening Electron**, inspect:

```sh
systemctl is-enabled flowgate.service flowgate-guard.service
systemctl status flowgate.service flowgate-guard.service
flowgate-control status
journalctl -b -u flowgate-guard.service -u flowgate.service --no-pager
```

Require a fresh daemon generation, intended `desired_mode: both`, actual `active`
profileboth (no countdown), active UDP, honest shared TCP collector state, and READY
only after hooks. Check guard-before-NM ordering with
`systemd-analyze critical-chain NetworkManager.service flowgate.service` and verify
Tailscale/bpftune remain active. Repeat one dedicated remembered/new request journey
as a separate reboot acceptance; an enabled unit alone is not evidence of protection.

## Final recovery boundary checks

`.workspace/daily-adapter-ofl4hfcl/stop-crash-result.json` injects SIGKILL after
monitoring intent is durable but before interception cleanup. A new daemon
finishes exact-owned cleanup before exposing stopped monitoring status.
`.workspace/daily-adapter-kxiw4xhv/failure-result.json` repeats the changed startup
path: real private guard blocks, unsupported tunnel readiness refuses, scoped
recovery restores delivery; foreign and modified guards are preserved.
`.workspace/daily-adapter-ri9_sdjq/acceptance/result.json` verifies the production
receiver driver after this ordering change (private namespace/simulated systemd).
`test-deployment-recovery.py` traces the fixed local command without host actions.
The earlier failure-only attempt `daily-adapter-113yb88q` stopped before guard
verification because the private loopback interface was down; the fixture now
explicitly enables only its private loopback, and the preserved rerun above passes.

READY notification follows policy/hook initialization; subsequent STATUS messages
track desired mode, actual state and failure reason. Actual installed systemd
notification and boot ordering still require the authenticated stage and reboot.

Uninstall first performs scoped monitoring recovery, removes only its verified
NetworkManager drop-in and reloads the dependency graph **before** stopping the
guard service. This avoids propagating a Requires stop into NetworkManager.
`scripts/checks/test-deployment-uninstall.py` checks the exact order with mocked systemd
calls and preserved immutable artifacts; installed uninstall remains unobserved.

## Installer doctor/activation distinction

The d7c969b installation attempt refused before runtime handoff because its
predicate rejected every firewall `not_checked` except queue census. Doctor
intentionally emits `firewall.activation / not_checked / not_attempted`: it never
binds NFQUEUE or mutates conntrack/rules. This is not an incompatibility finding.
The root-owned recorded preflight was not readable by the unprivileged agent;
the exact user-reported diagnostic is preserved in the focused regression.

The corrected installer validates doctor schema1 and presence/uniqueness of
required firewall/dependency checks. Only the exact activation tuple above and
`firewall.queue_census / not_checked / probe_failed` are deferred to guarded
activation. Recognized completed prerequisites retain their ready codes;
blocked, failed, unknown status/code/ID, missing dependency, incomplete report and
other unchecked prerequisites refuse before replacing the old runtime. The
original report remains unchanged; `preflight-disposition.json` records deferred
checks explicitly, without labelling them ready. Optional collector diagnostics
are separate from required firewall/dependency prerequisites.

At activation, `queue.RunConfigured` must open the exclusive NFQUEUE socket and
register callbacks before invoking the ready callback. In `Evaluation.run`, that
callback performs bounded conntrack snapshot/mark operations, atomic nft rules,
structural digest and persisted session record before removing the guard and
publishing active. Failure propagates through the host acceptance stage into the
installer's prepared recovery path; no successful host acceptance is printed.
The retired installer-readiness fixture reproduced the exact reported refusal and
checks real blockers, narrow census deferral, unknown/missing results and the
actual installer transaction's activation/acceptance failure handlers using
mocked privileged boundaries. Existing isolated receiver/kernel/UI evidence is
reused; this correction does not claim a new installed-host pass.

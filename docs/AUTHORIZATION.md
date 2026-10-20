# Root daemon and explicit administration

## Process-instance extension (not deployed)

Primary capability `process-instance-rules-v1` adds explicit process targets with
pinned native/session identity, process-tier precedence and inactive lifecycle
metadata. Application rules remain unchanged. See [PROCESS-RULES.md](PROCESS-RULES.md)
for schema3 preview/save/edit/delete, inventory, authorization and exact limitations.
Earlier application-only scope/precedence descriptions below refer to legacy rules.


## Daemon-owned incoming evaluation (new, isolated verification only)

`daemon-evaluation-v1` adds asynchronous readiness/Start/Stop to the existing root
`serve` daemon without another database/API owner. Selected administrator control
requires explicit `--allow-evaluation`; ordinary startup remains non-enforcing.
Fixed300s deadline, session/generation guards, cleanup acknowledgement, independent
watchdog; Activity, stored rules, Decision Log and UDP ownership survive Stop.
Exact contract, limitations, evidence and future deployment:
[DAEMON-EVALUATION.md](DAEMON-EVALUATION.md). **The running host daemon was not
restarted, granted this permission, or used for enforcement in this increment.**


## Daemon-owned optional UDP accounting

The root `serve` daemon now supports explicit optional UDP helper ownership and
measurement delivery via existing Activity. Capability `daemon-udp-monitor-v1`
adds traffic-status/start/stop, explicit `can_control_traffic`, and daemon+collector
generation guards. Root-configured selected administrator delegation requires
`--allow-traffic-control`; rule/decision permissions do not grant it. Startup is
still non-enforcing and collection-disabled; TCP/rules survive collector failure.
See [DAEMON-UDP.md](DAEMON-UDP.md) for exact API, privacy, semantics, compatibility
and test commands. Build `.workspace/flowgate-udp-daemon` is separate; the running
host monitor is unchanged. Authenticated isolated kernel acceptance passed
(`.workspace/daemon-udp-1792270674-2133903`): receiver-backed UDP4/UDP6 bytes,
lifecycle/restart/crash, privacy projection, continuous TCP, unchanged firewall/
routes. Consolidated UDP display in the UI still needs its isolated Wayland check.


Production target: **one privileged Go daemon** owns observation, accounting and
optional enforcement. Electron/Qt stay unprivileged. Root is an observation
capability, **not an instruction to install firewall rules**. Ordinary launchers
remain read-only and do not start a root daemon implicitly.

## Implemented foundation

`flowgate serve --socket ABS --database ABS --uid UID [--administrator]` is a
foreground **non-enforcing** root daemon. It combines native Activity/TCP snapshots,
authenticated local API and stored rule management. It does not bind NFQUEUE,
modify nftables/conntrack, attach BPF or initialize an enforcement watchdog.
Stored Block rules have no network effect in this mode. SIGTERM/Ctrl-C stops it.
The database and API directories must already exist and pass root ownership,
ancestor and permission validation. It never repairs/chowns an unsafe path.
The API directory may be 0711; sockets are 0600 and owned by the selected peer.

## Running host monitor (explicitly authorized)

The fixed paths are now prepared/validated. Existing directories and contents
were preserved: `/run/flowgate-api` root:root 0711, `/var/lib/flowgate` root:root
0700. The idempotent command accepts no path arguments, refuses unsafe ownership,
symlinks or unexpected modes, and does not repair existing paths:

```
sudo -n /home/flowgate-user/Apps/flowgate/.workspace/flowgate monitor-setup
```

Manual non-enforcing startup (do not run a second instance while one is active):

```
sudo -n /home/flowgate-user/Apps/flowgate/.workspace/flowgate serve \
  --socket /run/flowgate-api/daemon.sock \
  --database /var/lib/flowgate/rules.db --uid 1000 --administrator
```

Connect the unprivileged Electron Activity view, leaving this independent daemon
running on frontend exit:

```
cd /home/flowgate-user/Apps/flowgate
scripts/run-electron.sh --daemon /run/flowgate-api/daemon.sock
```

The companion returns `mode=host-monitor`, `backend_mode=daemon-monitor`,
`read_only=true`, with the same authenticated administrator observation scope.
All companion mutations are rejected. The integrated client uses the primary
`mode=daemon-monitor` endpoint for permission-aware summaries and stored-rule
management, separately from Activity. Its header accurately reports enforcement
stopped; stored Allow/Block is never a delivery/enforcement claim. Current rollout,
identity and bounded verification are in [INTEGRATION.md](INTEGRATION.md).

Stop only the intended monitor generation as root (not ordinary delegated admin):

```
sudo -n /home/flowgate-user/Apps/flowgate/.workspace/flowgate monitor-stop \
  --generation a0109011f97dad19dd723e7e483d7860
```

That token identifies the updated non-enforcing daemon, PID2095594. After a future
restart, inspect `flowgate pending --socket /run/flowgate-api/daemon.sock` for the
new generation and confirm it before stopping. `monitor-stop` has a fixed socket,
requires the exact generation and root SO_PEERCRED, never signals arbitrary PIDs
or stops enforcement instances. Its acknowledgement confirms shutdown requested;
check process/socket disappearance if the response is lost, without blind retry.
The database is retained and only that listener's sockets are cleaned up.

For a root read-only probe requiring no runtime files:

```
sudo -n /home/flowgate-user/Apps/flowgate/.workspace/flowgate doctor --json --uid "$(id -u)"
sudo -n /home/flowgate-user/Apps/flowgate/.workspace/flowgate sockets
```

## Roles are authority, not application identities

| Endpoint peer | Observation | Stored policy/decisions |
| --- | --- | --- |
| Selected UID, no administrative grant | Own-UID projection | Own-UID applications |
| Selected UID with explicit root-configured grant | Machine-visible current namespace | All supported application UIDs, including services |
| UID 0 | Machine-visible current namespace | Administrator |
| Other local UID | Rejected | Rejected |
| `.monitor` companion | Same role visibility | No mutations |

The grant is a root startup flag `--administrator`, tied to `--uid`, not a JSON
request, group membership or discovery metadata. It is refused from an ordinary
process. The same opt-in flag is available on explicit host-start/host-session;
existing evaluation launchers omit it and retain their prototype self-only policy.
Administrator can edit service rules without changing their application principal
UID/revision. A root census on an ordinary endpoint withholds foreign process
metadata and mixed-user shared rows rather than inventing exclusive ownership.
Existing unprivileged observers retain OS-readable visibility, labelled user-visible.

Admin status does not resolve ambiguous sockets, namespace omissions, shared
ownership or stale identity. Existing native corroboration and delayed-decision
rechecks still apply. No namespace traversal or game attribution is added.

## API and ownership

Capability `explicit-administrator-v1` adds `permissions` to responses. See API.md.
`daemon-monitor` returns Activity and rules together with enforcement `stopped`.
`can_manage_rules` may be true while `can_decide` is false. Connected, writable
policy storage never implies protection. Host enforcement now supplies Activity
in the same Go process too. All privileged authoritative writers take an exclusive
advisory lock on the SQLite database inode; a second daemon cannot publish a
competing in-memory policy against that database. Generations and conditional
rule version semantics are unchanged.

## Remaining consolidation and deployment

This is the native/root authorization foundation, not a complete production
service. Current UI launchers still use their existing monitor/control connections;
frontend permission-aware integration and a single-daemon mode transition remain
work. The optional UDP API/collector is still the separate selected-UID prototype;
machine-wide accounting and its integration into this daemon are **not implemented**.
A small native BPF helper may remain a subprocess; production should not need a
second privileged Go policy/observation daemon. No root service, autostart, generic
local-admin membership, privilege broker installation or new Stop authority is added.

Root observation improves system-service visibility; it does not make Tailscale
coexistence safe. The bounded incoming-only Tailscale client profile is now tested; see
COEXISTENCE.md for exact masked-copy/routing validation, unsupported cases and
the future user-triggered database handoff. Other tunnels/mark configurations
still refuse; live encrypted Tailscale interception remains unverified. No workaround disables Tailscale or weakens security.

## Evidence and limits

`scripts/checks/check-administrator.sh`: role/privacy tests, real ordinary Unix peer
self-grant rejection, SQLite exclusive writer test, race/vet, and isolated root
namespace non-enforcing daemon with actual UID0 listener and service rule edit/
conditional delete. Stored Block does not prevent delivery; nft state unchanged.
The isolated peer is UID0 in a user namespace. Subsequent authorized host verification
used a real UID1000 peer and root server, demonstrating machine-visible Activity
including other-UID system processes. The `.monitor` endpoint rejected rule
save/delete/legacy mutation, packet decisions and shutdown; primary rejected
UID1000 shutdown despite its administrative rule authority.

Authorized root host doctor saw UID0, 95 sockets/17 tasks, no inaccessible process
directories, 18 ms census. It reported tailscale0 and existing marks as blockers.
After that diagnostic, root monitor PID1973082 was explicitly authorized and
started with enforcement stopped. No NFQUEUE bind, BPF attach, root service or
host enforcement was started. Actual sandboxed UID1000 Electron Wayland connection
showed machine Activity; the test GUI exited while the independent daemon stayed
running. Evidence `.workspace/root-monitor-live-verification.json`,
`.workspace/root-monitor-ui.log`, `.workspace/root-monitor-ui-header.png`,
`.workspace/root-monitor-isolated.log`. Older diagnostic evidence:
`.workspace/root-doctor.json`,
`.workspace/root-sockets.json` and `.workspace/administrator-isolated.log`.

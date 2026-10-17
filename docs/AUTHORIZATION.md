# Root daemon and explicit administration

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

Prepared manual command (not a service installation):

```
sudo -n /home/flowgate-user/Apps/flowgate/.workspace/flowgate serve \
  --socket /run/flowgate-api/daemon.sock \
  --database /var/lib/flowgate/rules.db --uid "$(id -u)" --administrator
```

This requires deliberately prepared root-owned storage and runtime directories;
it is not runnable until those exist. This task writes files only inside the
repository, so it does not create `/var/lib/flowgate` or host runtime endpoints.
Do not substitute a user-writable repository database/directory: startup refuses
that privileged configuration. Passwordless permission for the executable does
not make unsafe storage acceptable.

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
coexistence safe. Current preflight still refuses tunnel interfaces/existing marks.
Allocation, routing, conntrack and hook-order tests are required before changing
that refusal. No workaround disables Tailscale or weakens security.

## Evidence and limits

`scripts/check-administrator.sh`: role/privacy tests, real ordinary Unix peer
self-grant rejection, SQLite exclusive writer test, race/vet, and isolated root
namespace non-enforcing daemon with actual UID0 listener and service rule edit/
conditional delete. Stored Block does not prevent delivery; nft state unchanged.
The isolated peer is UID0 in a user namespace; delegation to a different real
host UID is configuration/unit tested, not demonstrated by that fixture.

Authorized root host doctor saw UID0, 95 sockets/17 tasks, no inaccessible process
directories, 18 ms census. It reported tailscale0 and existing marks as blockers.
No NFQUEUE bind, BPF attach, root host endpoint, root service or host enforcement
was started. Raw local evidence is under `.workspace/root-doctor.json`,
`.workspace/root-sockets.json` and `.workspace/administrator-isolated.log`.

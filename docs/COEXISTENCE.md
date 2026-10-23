> Historical record: the vendor-specific adapter and commands described below have been removed. Current product-independent checks are documented in SEMANTICS.md. These historical test results do not establish current compatibility.

# Tailscale coexistence: bounded incoming-only evaluation

## What was observed on this host

Root read-only inspection found CLI **and daemon 1.104.1**, installed commit
`7f4efe814ff14b064eb080344389ceb9ea2d37ac`, `gitDirty=true`. This is not a claim
that the installed executable exactly equals an upstream release source tree.
Actual kernel rules, masks and routing are independently checked.

- Active rules are **iptables-nft compatibility rules** (iptables1.8.13), not
  legacy tables or Tailscale's native nft runner. Both ip/ip6 INPUT hooks are
  filter priority0; mangle PREROUTING filter and OUTPUT route hooks are -150.
  FlowGate input/output filter10 and input admission11 remain later.
- Tailscale packet mask `0x00ff0000`: subnet forwarding `0x00040000`, transport
  routing bypass `0x00080000`. FlowGate owns only **conntrack** `0x30000000`.
- Opaque xt MARK in ts-forward is `--set-xmark 0x40000/0xff0000`.
  CONNMARK saves in OUTPUT/NEW and restores in PREROUTING/RELATED,ESTABLISHED;
  both nfmask and ctmask are `0xff0000`. Save/restore selectors also read only
  that mask. Native nft mark comparisons use the same packet mask.
- Policy routing priorities5210(main),5230(default),5250(unreachable) match
  `0x80000/0xff0000`;5270 looks up table52. The sampled table52 has3 IPv4 and2
  IPv6 routes, all on tailscale0, no defaults or gateways.
- No selected exit node, accepted subnet routes (`RouteAll=false`) or advertised
  routes. Netfilter mode on, running. No other refused tunnel observed.
- Sampled conntrack mark histogram:178 zero,3 `0x00080000`; no FlowGate reserved
  bits observed. This is a transient census, not an allocation guarantee.
- Docker/libvirt forwarding/NAT objects exist and are retained. FlowGate does not
  claim to control their forwarded/container/router traffic.

Local evidence: `.workspace/tailscale-host-inspection.json`,
`tailscale-doctor-host.json`, `tailscale-doctor-host-both.json`. No peer names,
credentials, environments or full unrelated rules are emitted. Address selectors
in the diagnostic iptables summary are redacted; table52 routes are counts only.

## Exact supported profile

Preflight now recognizes only this **1.104.1 iptables-nft client** combination,
with corroborating interface, CLI/daemon version, preferences, actual nft objects,
iptables exports and IPv4/IPv6 routing. Interface name or version alone is not
sufficient. Both the kernel's opaque-writer locations/counts and their independently
exported target masks must agree. Known non-mark conntrack/addrtype matches and
MASQUERADE targets may coexist. The standard DNAT target is now also recognized
only at ip/ip6 `nat/DOCKER`, with xt type `target`. Its destination translation does
not write packet/conntrack marks; neighboring mark writers still undergo all mask
and location checks. DNAT elsewhere or as an unknown match still refuses. This
corrects the concrete Docker published-port refusal found after reboot; it is not
a Docker forwarding-control feature. Unknown opaque targets remain refused.

Focused evidence: `TestDockerDNATDoesNotHideMarkConflicts` covers both families,
wrong table/chain/type, unknown targets, adjacent native/opaque mark writes and
continued outgoing refusal. `daemon-evaluation-isolated.py --tailscale --docker-dnat`
checks real IPv4/IPv6 translated receiver delivery and read-only readiness without
activating interception; its shaped Tailscale metadata is not encrypted tailnet
evidence. Kernel definition: [xt_nat DNAT](https://kernel.googlesource.com/pub/scm/linux/kernel/git/torvalds/linux.git/+/627b7865c062ff642c0000f3a4775f1a44b986a4/net/netfilter/xt_nat.c).


Only `--profile incoming --administrator --uid 1000` is currently supported on
this host. An ordinary selected-user evaluation refuses `administrator_required`:
otherwise the GUI could not answer root-owned system-service attempts.
`--profile both` refuses `tailscale_profile_unsupported`. There is no force flag.

Full-value writes, unmasked mark reads/copies, additional mark writers/opaque
targets, reserved-bit overlaps, additional routing selectors, unsupported hooks,
other tunnels, exit/subnet modes and other Tailscale versions/backends refuse.
An apparently disjoint assignment such as `ct mark set 0x80000` is **not safe**:
it erases FlowGate's decision bits. It is rejected. Native nft mark writers remain
outside this finite compatibility profile; this is not a universal mark analyzer.

### Why these masks preserve each other

With identical TS masks, xt CONNMARK save computes
`new_ct=(old_ct & ~TS_MASK) ^ (packet_mark & TS_MASK)`; restore computes
`new_packet=(old_packet & ~TS_MASK) ^ (ct_mark & TS_MASK)`.
The preserved high bits are neither cleared nor copied into packet routing.
MARK xmark uses its explicit mask as well. FlowGate's NFQUEUE host verdict does
not set packet marks; nft OR and ctnetlink masked updates touch only FlowGate
conntrack bits. Cleanup clears those bits only. Routing reads packet marks under
TS_MASK, not FlowGate's conntrack approval state.

Reference behavior: [Tailscale1.104.1 firewall constants](https://github.com/tailscale/tailscale/blob/v1.104.1/tsconst/linuxfw.go),
[iptables runner: base, CONNMARK and transport rules](https://github.com/tailscale/tailscale/blob/v1.104.1/util/linuxfw/iptables_runner.go),
[kernel xt_connmark implementation](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/xt_connmark.c),
[Netfilter chain priorities and verdicts](https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains).
These sources were inspected, not incorporated as copied implementation code.

### Transport and inner applications are separate

**There is no infrastructure Allow exception**, no tailnet address/interface/UDP/
root-user bypass. New undecided encrypted-transport input to tailscaled is treated
as traffic to that current native executable/revision/UID0 listener. It may prompt
until an administrator explicitly allows its supported service/remote-address
scope. Unknown/shared/unobservable ownership still blocks; admin cannot invent
identity. A roaming/new transport peer can require a new rule/decision. Delayed
approval or Block can interrupt tunnel connectivity; existing retained-packet
bounds and expiry still apply. Preserved/outbound connections retain the existing
contract. There is no promise of uninterrupted Tailscale negotiation.

Inner packets arriving on the TUN go through input application policy separately.
Tailscale's earlier ACCEPT does not bypass a later FlowGate hook; FlowGate Allow
also does not bypass another chain's later Drop/Reject. Outgoing traffic is
FlowGate-permitted in this profile; outgoing transport control remains unverified.
Forwarded traffic is outside this milestone, including when subnet modes are off.

## Reproduce read-only inspection

```
sudo -n /home/flowgate-user/Apps/flowgate/.workspace/flowgate tailscale-inspect
sudo -n /home/flowgate-user/Apps/flowgate/.workspace/flowgate doctor --json \
  --uid 1000 --administrator --profile incoming
```

Neither command binds queues, attaches BPF, writes nft/route/sysctl state, starts
Tailscale or stops the monitor. The specialized command uses only fixed bounded
read-only probes plus a conntrack mark histogram (no endpoints). Doctor's planned
`--administrator` flag does not grant any client permission or activate anything.
The **profile compatibility checks now pass on the sampled host**. Actual activation,
queue bind, startup preservation, database ownership and coexistence are separate
checks. Startup repeats profile inspection; a diagnostic pass is not authorization.

## Historical separate-controller handoff (superseded)

The following records the earlier separate host-start workflow, not the current
daemon-evaluation-v1 procedure. Do not stop the current monitor to Start its embedded
evaluation or follow these old PID/generation values. Current deployment, actual
host acceptance and Stop/rollback are in INTEGRATION.md.

### Original handoff — not executed at that checkpoint

The current monitor remains PID1973082, generation
`5a559274aa006090cdc4bb5cd8faed47`, enforcement stopped, holding
`/var/lib/flowgate/rules.db`. Confirm its current generation before acting:

```
.workspace/flowgate pending --socket /run/flowgate-api/daemon.sock
```

Only after separately choosing to activate an evaluation:

1. Run the read-only diagnostics above and review the current findings.
2. Stop **that confirmed** monitor, then verify its sockets have disappeared:
   ```
   sudo -n /home/flowgate-user/Apps/flowgate/.workspace/flowgate monitor-stop \
     --generation 5a559274aa006090cdc4bb5cd8faed47
   ```
3. Start the bounded evaluation in a terminal (foreground, five-minute original
   deadline plus independent cleanup watchdog):
   ```
   sudo -n /home/flowgate-user/Apps/flowgate/.workspace/flowgate host-session \
     --action start --uid 1000 --administrator --profile incoming \
     --duration 5m --timeout 30s
   ```
4. Open the **unprivileged** desktop using the controller's own observation
   companion; no competing Go observer or policy database writer is needed:
   ```
   scripts/run-electron.sh \
     --observer /run/flowgate-api/control.sock.monitor \
     --control /run/flowgate-api/control.sock
   ```
   The observation companion advertises host-monitor + backend_mode
   host-enforcement, read_only=true; the primary reports actual enforcement health.
5. Inspect/Stop independently; recovery is only for a dead recorded instance:
   ```
   sudo -n /home/flowgate-user/Apps/flowgate/.workspace/flowgate host-session --action status
   sudo -n /home/flowgate-user/Apps/flowgate/.workspace/flowgate host-session --action stop
   # Only after inspecting a failed/dead owned instance:
   sudo -n /home/flowgate-user/Apps/flowgate/.workspace/flowgate host-session --action recover
   ```
6. Once the controller is confirmed stopped and has released the database, resume
   non-enforcing monitoring using the existing data:
   ```
   sudo -n /home/flowgate-user/Apps/flowgate/.workspace/flowgate serve \
     --socket /run/flowgate-api/daemon.sock \
     --database /var/lib/flowgate/rules.db --uid 1000 --administrator
   ```

No handoff is automatic. A second writer refuses `policy_database_owned`, before
queue installation, and does not stop the monitor. Generations change; old pending
IDs/confirmations do not survive. Rules, absolute expiry, identities and UID scope
are retained. If evaluation fails, inspect status/recover only owned resources
before resuming the monitor. There is no automatic restart or deadline extension.
The read-only frontend cannot transition the daemon into enforcement implicitly.

## Verification and remaining gap

`scripts/checks/check-tailscale.sh` runs focused parser/race/vet checks and an isolated
component fixture. It uses real kernel TUNs linked by a private userspace L3 relay,
two network namespaces, actual iptables-nft MARK/CONNMARK rules, routing and the
actual controller/NFQUEUE/API/receivers. Only Tailscale version/preferences responses
are emulated. It does **not** start tailscaled, encrypt traffic or enroll a device.

Passed IPv4/IPv6 TCP and retained one-shot UDP Allow/Block, input replies, marked
outbound exchanges without input prompts, masked save/restore preserving TS bits,
routing bypass selection, independent later Drop, startup TCP preservation,
exclusive database handoff/new generation/stale generation rejection, observation
companion contract, Stop/repeated recovery retaining foreign rules/routes/TS bits.
Full assignments, unsafe copies, overlapping CT writers and unsupported combined
profile refused. Source-state/parser tests cover malformed hooks/opaque targets,
read masks, routing masks and administrator requirements. Evidence:
`.workspace/tailscale-verification.log`, `tailscale-daemon-tests.log`,
`.workspace/tailscale-component-ex2euah1/`.

No live-host interception, live end-to-end tailnet/DERP/roaming test, live sudo
activation workflow, firewall-manager/VPN rewrite during evaluation or Tailscale
update behavior is established. Existing owned-table health checks remain active;
**foreign Tailscale/firewall/routing/preferences are not continuously revalidated**.
A later diagnostic/startup detects relevant configuration changes, but there is no
race-free transaction across external writers and no promise that they cannot
invalidate this profile after preflight. Keep the first evaluation bounded; inspect
again after configuration changes. Existing watchdog/expiry/UDP/ownership/UI
matrices were reused, not rerun. Root monitor stayed running throughout.


## Next bounded outgoing increment (not implemented or authorized here)

Current daemon lifecycle supports incoming only. Existing disposable outgoing
TCP/UDP4/6 receiver evidence proves the engine, not host/Tailscale coexistence.
A next increment must define an explicit outgoing/both capability/profile and
activation grant, recheck current mark/NAT/routing compatibility, and distinguish
root tailscaled encrypted transport from inner application policy. Use current
native service identity and explicit administrator decisions; no blanket root,
UDP, interface or tailnet Allow exception. Then verify packet/conntrack mark
preservation and replies in disposable fixtures, followed only with separate host
authorization by one bounded controlled existing-tailnet-peer receiver journey.
Do not enroll a device, alter routing or change defaults to make it pass. Unknown
writers, tunnel modes or routing interactions must still refuse. No estimate of
host readiness is a substitute for that missing end-to-end evidence.

# Read-only doctor and startup troubleshooting

## Current Tailscale inspection

`flowgate tailscale-inspect` performs fixed bounded read-only version/preferences,
chain/mark-export/routing probes and a conntrack mark histogram, omitting peer
identities and redacting address selectors. No arbitrary command runner is exposed.
`doctor --json --profile incoming --administrator --uid 1000` shares the actual
startup profile checks. --administrator describes a planned privileged grant;
it does not grant API authority. Incoming Tailscale profile compatibility passes
on the current sample; `both` refuses tailscale_profile_unsupported and missing
administrative grant refuses administrator_required. Other unsupported masks,
hooks, routes or builds report tailscale_unsupported. A running writer still
blocks actual startup with policy_database_owned. See COEXISTENCE.md for exact
scope and live-host gap; the older blanket-refusal sample below is historical.


## Build and inspect

From the repository root:

```sh
. scripts/go-env.sh
go build -o .workspace/flowgate ./cmd/flowgate
.workspace/flowgate doctor
.workspace/flowgate doctor --json
# Optional helper build only: does not load or attach BPF.
scripts/build-udp.sh
```

Normal launch remains `scripts/run-electron.sh` or the retained Qt
`scripts/run-desktop.sh`. Doctor starts neither frontend nor observer/controller/
collector, creates no runtime directories and requests no sudo. It never installs
rules, binds an enforcement queue, loads BPF, changes networking/permissions/sysctls,
or writes/uploads a support archive. Output is stdout only.

### Interpret each check

- **ready**: this named inspection completed with its stated evidence. Located
  executables, loaded modules, BTF names and ELF metadata are **not** proof of
  successful interception/attachment or universal coexistence.
- **blocked**: a definite current prerequisite or conservative startup refusal.
- **optional_unavailable**: optional UDP helper/BTF/library capability unavailable;
  basic unprivileged TCP monitoring remains available.
- **not_checked**: denied, absent, timed out, incomplete or deliberately unattempted.
  Read details/code; it is neither success nor proof of unsupported hardware.

There is deliberately no overall “activation ready” flag. Queue exclusivity,
conntrack cutover/mark updates, actual packet interception, BPF signatures/verifier/
load/attach and live coexistence remain startup-time checks. A clean inspection
cannot prevent another actor changing resources immediately afterward.

## Explicit additional privileged inspection

If desired, the user can independently run this **read-only** command:

```sh
sudo .workspace/flowgate doctor --json --uid "$(id -u)"
```

It enables permitted nft ruleset inspection and root-owned controller record/
ownership checks. It does not enable enforcement or collection. Capability bits
and namespace IDs are reported, not treated as proof of initial-user-namespace
BPF authority. No actual BPF permission probe is attempted.

The selected UID chooses the default collector socket path; it does not impersonate
that UID or bypass API peer credentials. The collector API intentionally authorizes
only its selected user, so root doctor may be unable to query another user's
collector API. Run ordinary doctor as that desktop user for its authorized API view.
Do not change socket permissions to make inspection pass.

Existing locations can be selected explicitly (no creation/repair):

```sh
.workspace/flowgate doctor --json \
  --state /run/flowgate \
  --controller-socket /run/flowgate-api/control.sock \
  --udp-socket /run/flowgate-traffic/1000/api.sock \
  --udp-helper "$PWD/.workspace/udp-collector"
```

Helper metadata is inspected, never executed. The helper now embeds
`FLOWGATE_UDP_HELPER_PROTOCOL=1`; rebuild with this checkout if an older helper
lacks it. This marker is compatibility metadata, not a code signature. ELF
architecture, direct dependencies and interpreter are inspected. Loader-cache
names do not establish transitive dependencies, ABI correctness or a successful
load. Go's basic observer has no libbpf dependency.

BTF inspection reads its bounded header/string table for the required
`btf_trace_sock_send_length` and `btf_trace_sock_recv_length` names, following the
[kernel BTF format](https://docs.kernel.org/bpf/btf.html). Names are prerequisite
evidence, not hook-signature or attach verification. No bpftool feature probe that
might load programs is run.

## JSON / startup error contract

JSON has `schema_version: 1`, kernel/architecture, current and selected UID,
namespace IDs, effective capability bits, duration, completed privileged-check IDs,
and `checks`. Each check has `id`, `status`, `code`, `detail`, optional `next`.
No full ruleset, arguments, environments, payloads, unrelated application paths,
private controller tokens or process records are emitted. Process/socket visibility
is summarized from the existing bounded observer; a partial census is explicit.
Doctor exits zero when it produced findings, including blockers; nonzero indicates
an invalid invocation or execution failure. Automation must inspect check statuses.

Example check (not an activation success):

```json
{"id":"udp.btf_hooks","status":"ready","code":"btf_names_present","detail":"BTF readable; required hook names present; attachment not verified"}
```

Known startup failures now retain concise error text prefixed by a stable
`[reason_code]`, with a legitimate next diagnostic action. Terminal bridges and
existing API fields are unchanged; no frontend password or automatic elevation.
The reusable read-only firewall checks are used by both doctor and startup, with
one queue/table allocation. Actual startup still performs its own checks/bind.

| Code | Meaning / next step |
|---|---|
| `dependency_missing` | Required executable absent; inspect normal approved dependency installation. |
| `permission_required` | Check/start denied by current credentials; doctor never weakens security. |
| `instance_active`, `instance_or_foreign_table`, `instance_or_socket_exists` | Inspect existing owner/status; Stop/recover only a confirmed owned instance. A table name alone proves no ownership. |
| `firewall_conflict`, `queue_occupied` | Existing interface/rules/allocation refused; retain monitoring and review coexistence. No disable-VPN/firewall shortcut. |
| `runtime_path_invalid` | Unsafe/occupied directory/socket/ancestor; inspect ownership/modes without blind chmod/unlink. |
| `helper_missing`, `helper_incompatible` | Rebuild the optional helper with this checkout; inspect its ELF/protocol/architecture. |
| `btf_missing`, `btf_invalid`, `hook_missing` | Optional UDP prerequisite missing/unsupported; retain TCP monitoring. |
| `library_unavailable` | Helper direct dependency/interpreter not observed; inspect loader configuration. |
| `bpf_load_failed` | Actual explicit collector startup did not load/attach; inspect its verifier/permission stderr. Doctor did not attempt this. |
| `probe_timeout`, `probe_failed`, `probe_invalid`, `probe_limit` | Inspection incomplete; no readiness established. |

Not every legacy failure is classified; unknown low-level errors keep their existing
text rather than being guessed into an inaccurate reason code.

External probes have a two-second deadline, private process group, 100 ms pipe
wait bound and 1 MiB output retention. A shared 15-second context bounds external
inspection scheduling. The existing proc/netlink census has its own budgets;
controller/collector IPC and status checks retain their finite deadlines. Overall
execution can exceed 15 seconds while those separately bounded operations finish
(roughly 30 seconds under multiple stalls; not a hard real-time guarantee). Raw
external probe output is not included in support JSON. Check text fields are
length-bounded and control characters are removed from the support summary.

## Recorded checks in this increment

Focused command:

```sh
scripts/checks/check-doctor.sh
```

Compiles optional metadata-bearing helper but does not attach it. Go race tests and
vet passed. Controlled tests cover denied checks, missing/incompatible helpers,
missing BTF hook names, bounded external timeout, unsafe/absent runtime paths and
human output. The disposable namespace checks cover healthy configuration, foreign
FlowGate table, mark conflict, non-stopped controller record, unsafe mode and missing
executables. Doctor leaves nft rules, interfaces and fixture state unchanged;
actual startup refuses the same foreign table without removing it. No queue/BPF
bind/load was needed. Evidence `.workspace/doctor-tests.log`, `doctor-vet.log`,
`doctor-isolated.log` (run directory printed there).

One actual unprivileged host JSON sample: `.workspace/doctor-host.json`, x86-64
CachyOS kernel 7.2.9-2-cachyos, UID 1000, 24 ms total. Basic visibility worked with
88 sockets / 10 visible tasks / 353 inaccessible process directories (partial).
`ip`, `nft`, running backend libraries, optional helper metadata/library names and
required BTF names were observed. At that earlier checkpoint tailscale0 was refused; the current bounded
profile described above supersedes the blanket refusal. nft
rules/queue and private controller record checks were not completed under this
UID; selected API sockets were absent. `unprivileged_bpf_disabled=2`; no BPF load
permission or attachment is claimed. No privileged host diagnostic, collector or
enforcement was run, and no host configuration was changed.

## Existing explicit workflows

[HOST-CONTROL.md](HOST-CONTROL.md) remains authoritative for the five-minute
Start/Stop/scoped recovery path. [UDP.md](UDP.md) describes explicit extended
monitoring and Stop. Doctor does not replace either startup preflight, authorize
activation, or run recovery automatically. [API.md](API.md) covers authenticated
policy IPC; no policy API mutation was added here.

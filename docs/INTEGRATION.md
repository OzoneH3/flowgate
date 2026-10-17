# Integrated desktop and non-enforcing root monitor

## Current launch

```
cd /home/flowgate-user/Apps/flowgate
scripts/run-electron.sh --daemon /run/flowgate-api/daemon.sock
```

Electron remains UID1000 and sandboxed. This reuses the independent root daemon's
companion for Activity and primary for authorized policy management. Closing/Quit
leaves the daemon running. Ordinary `scripts/run-electron.sh` and Qt
`scripts/run-desktop.sh` remain available; neither implicitly enables enforcement.

The authorized monitor update retains `/var/lib/flowgate/rules.db` and root-owned
path validation. Current PID **2152405**, generation
**4e18ec0723edb676c156a6b0ae4e9db9**, selected UID1000 explicitly administrator
with explicit UDP traffic-control grant (see "Daemon-owned UDP rollout" below).
Both sockets retain UID1000/root group,0600; primary daemon-monitor, companion
host-monitor/backend_mode daemon-monitor. Enforcement is **stopped**, can_manage_rules
true on primary, can_decide false. Companion mutations remain rejected. UDP
collection is **disabled** until the user explicitly Enables it in Activity. No
system service/autostart/BPF/queue/firewall activation was performed.

Exact Stop (only if deliberately stopping this monitor):

```
sudo -n /home/flowgate-user/Apps/flowgate/.workspace/flowgate monitor-stop \
  --generation 4e18ec0723edb676c156a6b0ae4e9db9
```

## Daemon-owned UDP rollout

Source `ea13560d5354b5714a91b447b263abd9b5e8b744` (UDP backend 15d6e1a + UI 66a0c02).
`.workspace/flowgate` SHA256 f9c446c1ede22ced0fff9b08281aabacda7ef14ea0c4adead926c89c93cf1b4c;
helper `.workspace/udp-collector` SHA256
118a8877d7b58dba43f20622064e3b60c38138a3453cf4a9aa87305720ab205c (pinned at startup).
Actual launch (via the existing NOPASSWD rule for that executable only):

```
sudo -n /home/flowgate-user/Apps/flowgate/.workspace/flowgate serve \
  --socket /run/flowgate-api/daemon.sock --database /var/lib/flowgate/rules.db \
  --uid 1000 --administrator \
  --udp-helper /home/flowgate-user/Apps/flowgate/.workspace/udp-collector --allow-traffic-control
```

Procedure (`.workspace/udp-rollout/rollout.py`, log/before/after/launch JSON there):
root peer, generation a0109011f97dad19dd723e7e483d7860, arguments and empty rule
inventory checked; running executable exported with `monitor-backup` to
`.workspace/udp-rollout/flowgate-running-previous` (SHA256 0d3feb00fea9646c700c67fec72ec3cd7cefaabd50056a3e6ba69c471ad8530d,
e2ef7f7); new build renamed into place (running inode never truncated);
generation-checked `monitor-stop`; old process exited before the new serve took the
database lock. Live UID1000 check (`live-verify.log`): daemon-udp-monitor-v1,
can_view_measurements/can_control_traffic true, collector disabled/available with no
helper process, enforcement stopped, TCP Activity and policy-view available, rules
still empty, companion Start/Stop `forbidden`, socket owners/modes unchanged.

Rollback (only if needed): generation-checked Stop of the current monitor, wait for
exit, rename the retained executable back to `.workspace/flowgate`, then start it
with the previous arguments (the launch above without the last two options).

After any later restart, inspect the new generation rather than reusing this token.
Do not launch a competing writer against the database. Evaluation remains separately
explicit; incoming-only Tailscale compatibility/limitations in COEXISTENCE.md remain.

## Included history

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

## Verification and rollout evidence

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

## Remaining limits

Live firewall activation/sudo evaluation, encrypted live-tailnet traffic and
privileged UDP activation through Electron remain unverified. Root observation
alone is not enforcement. First-rule creation requires a live supported native
single-holder target in the daemon's net/mount namespaces. Known shared/runtime/
unknown targets reject; snapshot inspection is not hostile-process race immunity.
TCP/UDP measurement coverage and separate UDP collector restrictions are unchanged.
Desktop refinements and icons are integrated.

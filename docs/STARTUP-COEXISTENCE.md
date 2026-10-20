# Startup does not depend on Tailscale initialization

FlowGate no longer starts or waits for `tailscaled.service`. Startup does not
query the Tailscale CLI version, login/preferences, advertised/accepted routes,
or require its complete set of hooks, mark operations and routing priorities.
This removes the dependency loop in which the boot guard prevents a VPN client
from connecting while FlowGate waits for that client to finish initialization.

Preflight still inspects current kernel rules. For the reviewed iptables-nft
mark/copy shapes, missing operations are allowed; present operations retain
mask, placement and duplicate validation. Independent iptables exports must
agree with the kernel's opaque mark-operation counts. Unknown writers, unsafe
masks, conflicting routing selectors, foreign queues and inconsistent snapshots
remain blocking. This is validation of present rule shapes, not a claim that all
future Tailscale versions or rule changes are supported.

No transport exemption or automatic Allow is introduced. System and tunnel
traffic still uses ordinary application permissions. The boot/crash guard,
work-VPN essential-permission exclusions and Tailscale transport exclusion from
essential permissions remain unchanged. The optional `tailscale-inspect`
read-only diagnostic remains available.

Validation: readiness race tests cover empty, partial and complete rule sets,
no Tailscale client probes, unsafe masks, missing/mismatched exports, duplicates
and foreign queues. These are simulated preflight snapshots; they do not claim
a reboot or protected receiver test on the user's host. Existing unrelated
receiver/enforcement acceptance is reused.

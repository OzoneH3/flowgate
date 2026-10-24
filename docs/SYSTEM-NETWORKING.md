# Essential system networking

The implemented review/apply/removal contract is maintained in
[ESSENTIAL-NETWORKING.md](ESSENTIAL-NETWORKING.md). This page does not assert that
the installed daemon is stopped or that any named host service has permission.
See [STATUS.md](STATUS.md) and inspect the live daemon.

An earlier default-deny installation disrupted essential traffic before its policy
was reviewed. Its exact recovery evidence and host-specific proposals are retained
in [SYSTEM-NETWORKING-HISTORY.md](SYSTEM-NETWORKING-HISTORY.md). That incident remains
relevant to first activation; its recovered host state is not current status.

Updates preserve the current mode. A fresh installation stays monitoring, and an
explicit updater transition to Both requires acknowledgement that DNS, DHCP, VPN
and kernel-origin traffic can be blocked. No preset or broad service Allow is
created automatically. Intentional deny-all/static-network configurations remain
possible after explicit review; absence of a preset is not proof of missing policy.

Review exact live executable/user/revision, configured resolver endpoints and
interface-scoped DHCP requirements through Essential networking before enabling
outgoing filtering. Custom rules may also provide these permissions. A displayed
service name never authorizes traffic. Kernel-origin clients such as CIFS may need
an explicitly reviewed [network-endpoint rule](NETWORK-ENDPOINTS.md).

Continuous protection has no automatic deadline. Explicit Stop returns to monitoring;
when the GUI/API cannot be used, root-local recovery is
`sudo /usr/local/sbin/flowgate-recover`. Do not treat a running service or a passing
prerequisite inspection as proof of working DNS/VPN/application delivery.

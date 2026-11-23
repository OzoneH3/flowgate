# Continuous protection (implementation candidate; deployment separate)

`continuous-firewall-v1` adds `protection` status and `protection-readiness`,
`protection-start`, `protection-stop`. All requests require the exact daemon
`generation`. Start supplies `profile: incoming|both`, last `protection_id` (empty
initially), and fresh lowercase 32-hex `request_id`. Stop supplies current
`protection_id`. Readiness is read-only. Primary endpoint and explicit
`permissions.can_control_protection` administrator grant are required for mutations.
A repeated Start nonce/profile returns the same operation, never another lease.
After an ambiguous response query status; never silently issue a fresh Start.

`protection.desired_mode` is durable `monitoring|incoming|both`. Actual `state` is
`stopped|starting|active|degraded|stopping|failed`, with reason and cleanup status.
There is no deadline/countdown. GUI presence is not required. The same queue owner
serializes bounded incoming evaluation and continuous protection; they cannot run
concurrently. Rules load before activation. Existing connections are preserved at
activation; admitted TCP is not deliberately terminated by policy changes.

Pending requests retain the existing bounded packet/byte/event/30-second limits.
Missing GUI, timeout, ambiguous identity and pressure deny; they never auto-Allow.
Expired requests cannot be acted on after reconnect. Process permissions retain
boot/session/start/executable bindings and become inactive after daemon restart.
Application/zone rules retain their schema, expiry, precedence and persistence.

Continuous consumer crash leaves its queue table without bypass: new supported
admissions drop. A boot/restart guard also blocks new TCP SYN and unestablished UDP,
while preserving established connections, non-TCP/UDP and narrow DHCP bootstrap.
An intentional Stop first durably saves monitoring, drops held packets, then removes
only owned interception/marks. Daemon/monitor/collectors survive Stop and GUI exit.
Normal service termination with desired protection still enabled retains fail-closed
interception for restart. A new daemon verifies the old consumer is absent, installs
the guard, reclaims only its exact recorded token/namespace, and starts normally.

Actual owned table structure is audited every second. Foreign interface, routing,
queue, mark and Tailscale client compatibility is rechecked every ten seconds
(bounded inspection up to fifteen seconds). Unsupported changes degrade and retain
a guard. The runtime audit can report `degraded` with `cleanup: unconfirmed`
before the separate `flowgate_guard` table is installed. The daemon keeps any
intact owned queue rules during that handoff. Those rules have no bypass on
consumer loss.
This is bounded detection, not instantaneous protection against another
privileged actor rewriting firewall/routing. Forwarded containers, other network
namespaces, non-TCP/UDP, unsupported IPv6 extension/fragment initiation and initramfs
traffic are not covered. Loopback traverses both hooks and can require both sides.

Tailscale client support remains explicitly bounded to inspected 1.104.1
iptables-nft/no subnet/exit-node forwarding, with mark masks disjoint. Neither inner
applications nor outer UID0 tailscaled transport has a blanket exemption. Other
firewalls may still deny an Allow. Collector failure is reported independently and
never silently disables policy or grants network access. TCP event evidence retains
its accepted optional shared bpftune, partial coverage and restart semantics.

## Evidence so far

`.workspace/continuous-component-i290r4k2/result.json`: real disposable TUN,
conntrack/NFQUEUE, emulated Tailscale metadata; IPv4/6 incoming/outgoing TCP+UDP
receiver-confirmed Allow/replies and Deny0; no-GUI expiry; Stop; actual SIGKILL and
fresh-generation restoration; unchanged foreign rules and routing. Not encrypted
tailnet or live-host proof. Existing accepted zone/process/collector evidence reused.
A separate accepted run remained active for310 actual seconds without Electron;
see DAILY-DEPLOYMENT.md for exact evidence and artifact preparation. Root installation/live-host acceptance is not yet run.

The earlier retained-identity rejection is preserved: strict fingerprint revalidation
was not relaxed. Current TCP retained admissions passed in the disposable fixture;
that does not establish the cause of the historical failure.

A crash between saving intentional Stop and removing interception is recovered
before a new monitoring API is opened. Recovery also recognizes stale embedded
bounded evaluation sessions; live consumers, standalone sessions, foreign namespace
or mismatching guard token/structure are refused rather than destructively cleaned.

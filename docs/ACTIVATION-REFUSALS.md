# Activation refusals from monitoring

An established TCP socket without a matching conntrack entry cannot be
preserved by the normal startup mark mechanism. This includes an IPv6 TCP
self-connection whose local and remote endpoints are identical. It remains
unsupported at activation; there is no loopback permission exemption.

Previously, continuous activation installed its fail-closed guard before this
compatibility check. The refusal then retained that guard and the desired
protection mode. New unrelated TCP/UDP traffic could remain blocked until an
explicit Stop, even though protection had never become active.

An explicit activation from clean monitoring now performs the same read-only
pre-claim validation before installing the guard. Reserved-mark collisions are
checked first and remain integrity failures. Activation repeats the validation
immediately before claiming marks; the early observation is not reused as proof.

If this specific compatibility refusal is the sole activation error, monitoring
is persisted before exact-owned cleanup. A socket appearing or becoming
untracked after preflight therefore also returns to monitoring. The result is
reported as stopped, desired monitoring, cleanup confirmed, with the explicit
`unsupported_established_tcp` reason. A fresh request is needed to retry.

This exception does not apply to persisted protection recovery, an already
present guard, joined queue/teardown errors, ownership/digest changes or other
integrity failures. Those retain fail-closed handling. A failed persistence or
cleanup operation never reports confirmed monitoring; early persistence failure
uses the normal Stop-aware failure guard. An I/O error after rename/fsync may
leave durability uncertain and is not reported as a successful mode change.
Concurrent explicit Stop retains its normal cleanup semantics.

Cleanup uses the existing session token and newly installed guard token/digest.
It never removes an unrelated table or a changed guard. Concurrent privileged
firewall mutation after an ownership read remains outside the non-atomic
ownership checks; this does not claim a kernel compare-and-swap operation.

The correction changes activation only. Application policy, incoming/outgoing
permissions, connection-lifetime grants, background check scheduling, the packet
path, profiler, holder iterator and Wine CPU corrections are unchanged.

Focused isolated verification covers canonical predecessor/current failures,
early refusal, a socket/conntrack change after preflight, concurrent Stop,
persisted protection, a pre-existing guard, mixed failures and changed ownership.
An independent peer receiver and actual nftables snapshots establish delivery or
blocking; API acknowledgement alone is not delivery evidence. The unsupported
self-connection is not claimed to work under ordinary Allow/Deny enforcement.

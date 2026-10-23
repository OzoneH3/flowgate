# Established TCP control

23 October 2026. First implementation gate for F03/B21 in the
[NetLimiter functionality audit](NETLIMITER-FUNCTIONAL-AUDIT.md).

The exact-socket abort primitive is implemented in
[`internal/socketcontrol`](../internal/socketcontrol/abort.go) and passes real
kernel tests in disposable namespaces. It has **no daemon API, GUI action or
policy caller**. Saving Deny still affects supported new admissions; this change
does not revoke existing connections automatically and has not been deployed.

## Proven operation

Linux `SOCK_DESTROY` can abort one local TCP socket. The request binds its network
namespace, address family, local/remote endpoints, interface and kernel cookie.
The kernel's TCP diagnostic lookup checks the cookie before invoking the abort.
The abort implementation locks the socket and closes its TCP state. See upstream
[TCP diagnostics](https://github.com/torvalds/linux/blob/master/net/ipv4/tcp_diag.c)
and [TCP abort](https://github.com/torvalds/linux/blob/master/net/ipv4/tcp.c).

The FlowGate primitive requires an established TCP observation with concrete
endpoints, nonzero inode and a nonzero, non-wildcard eight-byte cookie. It pins the
current OS thread, checks that thread's network namespace and opens its netlink
socket there. It never enters another namespace. A fresh exact diagnostic query
must still match the supplied cookie, tuple, interface, family, creator UID,
inode and established state before a single destroy request is sent. The
transport has a two-second deadline, shortened by the caller's deadline, and
responds to context cancellation.

Creator UID and the fresh diagnostic record detect identity drift; they do not
authorize the action. Neither a display label nor an Activity row is permission
to disconnect a connection. No conntrack entries or firewall marks are changed.

| Result | Meaning |
| --- | --- |
| `acknowledged` | One valid kernel acknowledgement accepted the exact local abort. |
| `not_found` | The exact socket was not found; no claim that this request closed it. |
| `rejected` | The supplied target was invalid or fresh socket evidence differed. |
| `forbidden` | Kernel permissions refused the query or operation. |
| `unsupported` | Kernel protocol/operation support was unavailable. |
| `unavailable` | A query/transport/context failure occurred before the destroy call. |
| `unknown` | The destroy call occurred but a trustworthy acknowledgement was not obtained. |

`Attempted` records whether the destroy transport call was reached. It does not
prove the kernel received that request. Unknown outcomes are never retried by
the primitive. An empty response or unexpected acknowledgement is unknown,
including a nominally successful transport result with no actual ACK frame.

An acknowledgement is not a remote delivery guarantee. It cannot erase payload
already queued at the peer. A fresh connection can be established afterward if
policy permits it. This operation affects the entire socket, including every
descriptor referring to it, rather than one process's copy of its descriptor.

## Ownership gate remains unresolved

The independent backend proof transferred a connected descriptor with
`SCM_RIGHTS` to a process created after the initial snapshot. The original holder
closed its descriptor and the new holder successfully transferred payload. The
original cookie remained valid: destroying it aborted the new holder's socket.
Forked co-holders were also affected together.

Consequently, cookie/tuple/UID/inode validation cannot establish continuous
application ownership. A fresh descriptor census can reject observed sharing or
transfer, but there is still a race after that census. Existing
[`VerifyObservedNative`](../internal/identity/observed.go) explicitly verifies
identity for rule creation, not exclusive socket authority. It must not be
reused as if it settled this stronger contract.

Two public outcomes require different contracts:

1. **Explicit administrator disconnect of one reviewed socket.** Authority is
   over the socket itself. A preview must explain that all current holders lose
   that connection, that identity is sampled, and that this creates no Deny rule.
   This is a possible next bounded feature, not implemented here.
2. **Automatic disconnection when effective policy becomes Deny.** Authority is
   tied to verified application/UID/runtime/prefix, initiation direction and the
   winning policy revision. This still needs an admission/ownership design,
   including transfer/sharing and concurrent rule/publication/connection races.
   An application-scoped Deny must not silently terminate a new holder's socket.

NetLimiter documents killing existing connections when a Block rule is created
in its [4.0.54 release notes](https://netlimiter.com/releases/4-0-54-0). An explicit
one-socket disconnect alone would not establish parity with that behavior.

## Required public API and UI contract

Before exposing a control, settle and implement all of these requirements:

- A dedicated server-derived permission and capability; no inference from
  `can_manage_rules`, measurement visibility, or a primary socket connection.
  Read-only endpoints cannot mutate sockets. Ordinary-user and runtime support
  require separate authority decisions and tests.
- A bounded, expiring preview binds the authenticated peer, daemon generation,
  exact kernel target and supported operation. The client supplies a selection,
  not trusted endpoints, UID or application metadata. Revalidate permission and
  target at commit; never widen a vanished selection into a new socket or app.
- A receipt records a submitted operation. A lost acknowledgement produces an
  explicit unknown result, not an automatic retry. Repeated client submissions
  must retrieve the same outcome rather than repeat an operation after reuse.
- Keep **rule saved**, **local abort acknowledged**, and **receiver outcome**
  distinct. A successful rule save must not imply existing traffic stopped.
  Lists of targets need per-target outcomes and explicit bounds/partial results.
- Stop/restart, kernel refusal, stale scope, unsupported namespaces, ambiguous
  direction, shared/runtime targets and concurrency must have explicit behavior.
  No broad PID kill, namespace-wide conntrack deletion or foreign mark clearing.

## Verification and scope

Run the committed package tests from the repository root:

```sh
. scripts/go-env.sh
scripts/lab.sh go test -race ./internal/socketcontrol -count=1 -v
```

The kernel test refuses to run outside the lab network namespace. It exercises
the actual Go package for IPv4/IPv6 and locally connected/accepted TCP sockets:
exact abort, terminal local I/O, peer exchange ending, unrelated connection
roundtrips, wrong cookie refusal and stale replay. These two connections live in
the same test process. Deterministic tests separately cover fresh identity drift,
malformed targets/responses, context cancellation, unavailable/forbidden results
and unknown acknowledgements without retry. No kernel test is silently skipped
for lack of destroy support after entering the private namespace.

Additional local evidence on Linux `7.3.0-3-cachyos`:

| Evidence | Actual scope |
| --- | --- |
| `.workspace/tcp-control-ui/package-kernel.log` | Actual package race tests and all four kernel cases. |
| `.workspace/tcp-control-ui/primitive-evidence.json` | Independent raw-netlink proof with two distinct compiled native executable paths, IPv4/IPv6 and connect/accept roles. Exact tuple replacement receives a new cookie; stale requests preserve replacement and unrelated transfers. Local abort and remote reset observed while target process remains alive. |
| `.workspace/tcp-revoke-proof/evidence.json`, `run3.log` | Backend's independent raw-kernel extension: 40 stale-cookie attempts per reused tuple; foreign network namespace and dropped-capability refusal; shared descriptors and later SCM_RIGHTS holder; 4,096 peer-buffered bytes remain readable after abort ACK, followed by reset. |

The raw-netlink extensions do not exercise the Go package or daemon policy API.
No effective-Deny transition, policy race, NAT/VRF combination, live Wine/Proton
runtime, cross-UID transfer, native GUI or installed-release control was tested
by this slice. The host's deployed `358d18c` and protection mode were unchanged.

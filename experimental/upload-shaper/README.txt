FlowGate M1: isolated native upload controller

Status: experimental, opt-in, available through an explicitly gated isolated serve API, NOT enabled in the
installed service, release preparation or updater. API: docs/UPLOAD-SHAPING-API.txt. No host activation is authorized by running
build.sh. There is no general NetLimiter-parity claim.

Supported contract
A socket is charged to the native application freshly verified when explicitly
bound. The controller uses the existing FlowGate resolver and process inspection,
then a second full socket/holder proof; a display name or process parent never
supplies authority. Different UID/application keys receive independent classes.
All bound sockets for one key share its aggregate upload cap on the selected
interface. A binding includes socket cookie, inode, protocol and network namespace.

Exec, fork or descriptor transfer AFTER binding does not automatically change
that assignment. It persists while the socket exists, unless removed or explicitly
revalidated and rebound. A fresh bind/rebind requires one unambiguous supported
native leader owner. Initially inherited/shared sockets are refused, including
same-application shared holders. A failed rebind leaves the accepted old binding
unchanged; it does not award another application's class. Socket/port reuse with
a different cookie cannot use an old binding. Unconnected UDP is socket-scoped,
so different peers on that socket share its binding on the selected interface.

Shaping maps are NEVER consulted for Allow/Deny. The BPF action assigns only
skb priority; it does not set routing/conntrack marks, accept a firewall verdict,
or bypass NFQUEUE. Existing firewall semantics remain independent.

M1 capability boundary
- Root in a disposable child network namespace; explicit interface and parent
  namespace identity required. Original M1 interface kind: veth,
  MTU576..9000, existing root noqueue, no foreign TC configuration.
- One interface; upload only; native TCP/UDP over IPv4/IPv6 using stable cookies.
- Explicit private stdin JSON control, not a public endpoint or daemon API.
- Cap range1..1000Mbit/s. Rates count qdisc bytes, including headers/retransmits,
  not only application payload. This is a cap, not a reserved bandwidth promise.
- The standalone controller has no automatic discovery/binding of new sockets;
  the daemon adapter adds bounded discovery and attribution hints. Unbound, unsupported,
  ambiguous or expired entries use a separate uncapped default class. They NEVER
  inherit a configured application's class. Traffic on another interface is not
  covered. Therefore there is NO guaranteed application-wide cap in this milestone.
- Host physical-NIC activation, VPN/tunnel/bridge interfaces, download, priorities, Wine/runtime
  support, persistence and UI are not enabled. Existing foreign HTB/fq_codel or
  clsact causes refusal, not replacement. Veth support is an isolated integration
  boundary; this is not yet a host-ready upload implementation.

Coverage states
Applying: controller is constructing/updating kernel objects; initial ready
message precedes bindings. Acknowledgements follow kernel mutation/verification.
Active: current requested binding set has unexpired kernel leases with the expected
class IDs and no known uncovered traffic/failures. This refers ONLY to that set.
Partial: no bindings, expired/missing leases, refused binding, reconciliation
requiring fresh bindings, or observed unclassified egress. Counters are conservative
and include unrelated/control traffic; M1 cannot attribute uncovered packets to
an application without fresh discovery. Partial is sticky for observed gaps within
a controller generation. Every status says application_wide_guarantee=false and
reports covered_bindings, coverage scope, interface and counters.
Unsupported: wrong interface/capability, changed/foreign TC objects, lost kernel
object identity or operational failure. No further renewal/mutation is attempted
except verified cleanup. Active never substitutes for a firewall permission.

Bounds / failure behavior
128 bindings;16 concurrent classes, monotonically allocated IDs1..65533 with
no class-ID recycling until a clean instance restart. The daemon adapter rotates
a fully exhausted generation through verified cleanup and fresh discovery. A configured cap applies across its bindings.
Every kernel binding and the controller heartbeat have a five-second monotonic
lease. A bounded socket census (max1024 rows) checks cookie/inode/protocol/netns
existence approximately once per second; it does not rescan process ownership
per packet or silently change binding ownership. Census/ownership failure stops
renewal. Expiry sends subsequent packets to default: shaping fails open, firewall
Deny does not. Already queued packets may drain under the former cap.
Closed sockets are unbound at the next successful census; idle classes retire
after10 seconds. A failed census retains no guaranteed coverage.

Each app leaf has128-packet and bounded byte retention, nominally25ms of rate,
with two-MTU floor and256KiB ceiling. The default leaf is128packets/64KiB. These
bounds do not bound application socket buffers, retransmission or end-to-end delay.
FQ-CoDel5ms target/100ms interval and a small HTB burst replace the tiny M0 demo's
latency configuration. Very low rates below1Mbit/s are deliberately unsupported
here. Live changes preserve the class/bindings; decreasing queue memory may drop
pending packets. Removal unbinds first, then retires the leaf/class; pending leaf
packets may be purged. Further packets take default immediately.

Ownership / restart
A private root-owned0700 journal directory with non-writable ancestors and flock
serializes control. Random handles, pinned BPF IDs, network namespace and interface
index, and structural TC snapshots identify owned objects. Dynamic FQ-CoDel flow
buckets and traffic counters are not administrative configuration.
Every mutation and cleanup verifies expected ownership first. Restart reconciles
an intact owned generation by removing it, then starts empty/Partial. It never
restores old socket bindings or caps from stale process data. If a crash interrupts
mutation before its new structural snapshot is durably recorded, or an external
administrator changes objects, reconciliation refuses and requires review; kernel
leases still expire. Files named owner.new or a mismatching journal are not blindly
deleted. A foreign root, filter or changed object is never automatically removed.
This is not an atomic CAS against concurrent privileged administrators: such
concurrency is outside the M1 contract. No protection against a malicious root
rewriting BPF maps is claimed.

Build / test
Run build.sh in the existing capped build environment. All outputs must be under
this repository's .workspace. Dependencies: Go, clang BPF target, C compiler,
libbpf development files, Python3; isolated guest needs tc/ip and relevant modules.
The tests/run.py and integration/run.py fixtures execute ONLY inside the capped
disposable VM, with no
NIC/host shares; never invoke it in the host namespace. It uses synthetic native
executables and the unchanged25db firewall. tests/check_results.py checks exported
receiver evidence. test_controller.py is pure in-memory model coverage.
M0 TCP/UDP v4/v6, exec/transfer/socket-reuse and packet-path evidence is reused.
M1 evidence/failure ledger: .workspace/shaping-m1/README.txt.

Private protocol (root-owned stdin; no network listener)
{"op":"bind","protocol":"udp","local":"IP:port","remote":"IP:port","rate":4000000}
Returns the verified app key and cookie. IPv6 endpoints use brackets. Add
"rebind":true for explicit revalidation. Existing socket ownership changes never
implicitly move an assignment. Multiple binds for an app share/update its one cap.
{"op":"cap","app":"returned UID:key","rate":8000000}
{"op":"remove","app":"returned UID:key"}
{"op":"status"}   (includes compatibility, counters and segmentation telemetry:
                   superpackets classified/unbound, segment sums, per-app burst
                   and leaf memory limit; telemetry only, never authority)
{"op":"stop"}
All results are JSON lines; failures explicitly report Partial/Unsupported.

Next integration step
The disabled-by-default daemon adapter now publishes independently verified
socket bindings with generation/version-checked configuration and coverage
reporting; see docs/UPLOAD-SHAPING-API.txt. It must not read shaping maps as
permission evidence. Before any host-ready release: test physical-interface
ownership/coexistence, link replacement/routing coverage, interrupted-startup
recovery UX and sustained resource overhead. Keep download/VPN/priorities/UI
separate. Deployment and host activation require a later approval.

NIC preflight increment
See docs/UPLOAD-SHAPING-PREFLIGHT.txt and physical/run.py. Single-queue default
fq_codel PCI/virtio NICs are experimental in a disposable namespace only, with
segmentation off and exact restoration checks. Existing host offloads are never
changed. The actual host currently fails this capability gate. M1 veth evidence
is not claimed as physical-interface proof.

Download extension: see ../../docs/DOWNLOAD-LIMITER.txt. Same service/binding
contract, with verified established-TCP ingress lookup and an owned IFB. The
native fixture remains isolated; this is not host activation authorization.

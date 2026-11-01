# Errata to frozen SPEC v2.1 (recorded after freeze; no expectation or tolerance change)

E1 (§4, 2026-11-01 ~17:48): the UL receiver-payload bound must also include the PEER receiver's unread kernel
queue at window start (FIONREAD on the accepted UL sockets at t0). This is the mirror of the DL RECVQ term. Found
from pilot-v3 window 0, where payload exceeded class + fffe + backlog by ~175 kB.
E2 (§4/§5 classification, pilot-v3): when bytes of A's not-yet-bound sockets are charged to fffe/fff1 in a cap
window, that is a **coverage escape** (documented limitation: first packets and unbound sockets). Record it per
cell with time-to-bind; it is not "sampling invalid". Cap compliance is measured after every A cookie
reports its class. "payload > charged + backlog ⇒ Inconclusive" applies only when no non-app class received
A-attributable bytes.
A1 (supplementary measurement, DECLARED BEFORE EXECUTION, 2026-11-01 ~18:45): P1 upload re-measurement with the
frozen §7 phase order, saturation precondition and thresholds unchanged, but with 2 s settle + **2 × 8 s** windows per phase
(N = |window0 − window1| per phase, as frozen). Reported as a separate "P1-UL-8s supplementary" result beside the
frozen 4 s verdict (Inconclusive), which remains the official frozen-spec outcome. Post-hoc pairing of existing or newly
collected 4 s windows is NOT permitted. RESEARCH's earlier "4 windows per phase" suggestion is withdrawn: with
N defined as the maximum pairwise difference, more windows would not reduce N.
E3 (evaluator, §7 P2): "phase variance" means the within-phase range across repeats. The priority.py spread over both phases
combined is an implementation defect; re-assessing the retained records under the frozen text is not a threshold change.

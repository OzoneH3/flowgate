# Independent review of spec v2 against frozen 93eaa868 (read-only, 2026-11-01)

Scope: source reading only, no execution. Kernel/iproute2 behaviour is from kernel and iproute2 knowledge, not
from files in this tree, and is marked as such. Paths are relative to the worktree root.

## Findings

1. **CONFIRMED: per-direction class rule.** controller.py:1042-1044 `has_class` = cap_d, or (priority != normal
   and budget_d), or zone_direction. Go mirror: zones.go:43-53 `directionRelevant` (budget>0 && prio non-Normal at
   All scope) feeds `aggregateCaps` -> `allocationAdmitted` (manager.go:390). expected.py:29-30 matches for unzoned cells.
2. **CONFIRMED: the tuple fields.** No budget: targets() gives `(cap, cap, 0)` (controller.py:1063), so ceil=cap
   and htb_prio=0. With a budget: allocate() gives `(floor, min(cap or b, b), HTB_PRIO[prio])` with
   high0/normal1/low2 (controller.py:32,75). These equal expected.py:43-46. expected.py does not give the floor (rate).
   SPEC §3.2 compares it to the status value only, so the floor is never checked against an independent
   expectation (non-blocking).
3. **CONFIRMED: Normal-only rejection.** Configure turns an All-scope "normal" into "" (manager.go:404-406).
   validateConfig then rejects rate=0, dl=0, prio="" (manager.go:379), so V1 fails with "invalid native
   application cap or rate". The controller also rejects it (controller.py:90, 1255). Zone explicit Normal is
   allowed (manager.go:379 `!(v.Scope != "" && ...normal)`; controller.py:104), so V2 holds.
4. **CONFIRMED with a wording problem: default class fffe.** The fffe class and its fq_codel always exist at
   100gbit in both trees from setup (controller.py:425-428, 439-441). Only its budget tuple and the BPF marking
   flag depend on the budget (controller.py:1115-1128, 1146-1147; classify.bpf.c:33-49).
   `traffic_priority.default_class.upload` is non-null only with a budget (controller.py:1496 + 1121/1128).
   `default_ul_class_fffe` must therefore mean "status default_class non-null / budget-shaped". It must not mean
   "the tc class exists", or every cell fails. Without a budget, unmarked egress always goes to the root default fff1
   (controller.py:424; classify.bpf.c:18-20). "bypass_fff1_or_unshaped" can be tightened to fff1 while the shaper is up.
5. **CONFIRMED: priority-only entry (low/high, no caps, no budget).** The binding is NOT refused. A binding is
   created without a class:
   - Offer/census marks the app wanted (manager.go:519-524, 829-883).
   - bind() sends rate=0, download_rate=0, priority=low|high (manager.go:900-922).
   - The controller's rates() accepts it (controller.py:85-92).
   - set_cap creates `self.apps[app]` with a minor, which counts toward MAX_APPS 16 (controller.py:1258-1265).
     has_class is false in both directions, so targets() creates no class.
   - class_ids returns ('0','0') (controller.py:1289), and `k bind cookie 0 0` installs a map entry with minor 0
     (1356).
   - In status the binding is listed with upload_class=false and download_class=false (1487-1488), and
     `traffic_priority.apps[A].upload` is None.
   - BPF: b->minor=0, so the packet is not app-classified and idx stays 0, not 17 (classify.bpf.c:24-30).
   So `entry_without_class` is accurate, but a binding will exist. The harness must not treat "any binding" as
   class evidence (H5 is correct to require `download_class`/`upload_class`). With a budget in only one direction,
   the class exists only in that direction.
6. **CONFIRMED (kernel knowledge): S+28+14.** At the egress root qdisc of an Ethernet device the MAC header has
   been pushed. HTB charges `qdisc_pkt_len` = skb->len for a non-GSO skb, so connected IPv4 UDP without IP options
   is S+8+20+14. The BPF counters also use skb->len (shaping.bpf.h:172). Precondition missing from the spec:
   S <= MTU-28 (no IP fragmentation) and no hardware VLAN. The same holds on the IFB after bpf_redirect.
7. **REFUTED: SPEC §3.3 equality and the loss arithmetic.** HTB class bstats are charged at DEQUEUE, in
   htb_charge_class (kernel knowledge). Packets dropped by the leaf fq_codel (enqueue overlimit or CoDel dequeue
   drop) and packets still in backlog at the after-snapshot are NOT in the class counters. Consequences:
   - (a) `packets == N_sent - sender_errors` holds only if leaf drops are 0 and backlog is 0 at the after-snapshot.
     "Snapshot immediately after the window" breaks this whenever the 2 Mbit/s cap is binding.
   - (b) "Receiver count = packets - shaping drops" double-subtracts. Correct: received = class packets
     (dequeued) - downstream loss. Charged = sent - sender_errors - leaf drops - final backlog_packets.
   Fix: wait until leaf backlog is 0, take the after-snapshot (still before PING), and include drops and backlog
   in the identity.
8. **CONFIRMED: classify.bpf.c classification.**
   - App classification is a cookie lookup on skb->sk (classify.bpf.c:16-26). It needs a live config lease and
     binding lease, and minor 1..ffef.
   - BPF does not require a connected socket for app classes. The connected requirement comes from binding:
     census skips unconnected sockets (manager.go:839-842), validFlow requires remote port != 0 (manager.go:932),
     and the probe proof applies.
   - The connected-exact check (fg_exact, shaping.bpf.h:155-166) applies only to the budget default marking
     (classify.bpf.c:33-52).
   - There is NO GSO exclusion. GSO skbs are classified and only counted in indices 2-4 (classify.bpf.c:58-78).
     "UDP UL GSO unsupported" is a documented unvalidated gate (UPLOAD-SHAPING-STATUS.txt:5; UI text
     upload-shaping-view.ts:165), not a code exclusion. Keep it Unsupported, but word it "unvalidated", not
     "excluded".
9. **UNCERTAIN (iproute2-version dependent): §4 burst/cburst units.** Modern `tc -j` prints HTB burst/cburst as
   integer bytes (print_size). Older iproute2 printed strings such as "1600b". The values come from buffer ticks
   via tc_calc_xmitsize and can differ by rounding from the configured value (controller.py:1032-1034,
   burst_bytes). Also, `tc -j` "rate"/"ceil" are BYTES per second, not bits. §3.2 compares the tc tuple with
   status (bits) and §4 uses rate×T, so the harness must convert ×8 explicitly. Record the iproute2 version and
   cross-check against status `per_app_burst_bytes`.
10. **REFUTED / incomplete: §4 bound terms.**
    - (a) The ceiling term must be **ceil**, not rate. In budget cells rate=floor < ceil (allocate), and a class
      may borrow up to ceil, so "rate × T" yields false Fails. This applies to both checks and to fff0 (rate=ceil=b
      there).
    - (b) Add one max skb to the charged-bytes check. HTB dequeues one packet once the bucket is non-negative and
      repays the deficit later (controller.py:142-149 comment: burst plus at most one superpacket).
    - (c) T in the charged-bytes formula is undefined (only T_min is defined). Use the tc-snapshot interval.
    - (d) burst+cburst summed is conservative, which is acceptable.
11. **CONFIRMED: D2.** StartSessionSocketAuthorization (socket_session.go:39-61, condition at line 42, not 41)
    has no UploadShaping check. The lab StartSocketAuthorization refuses `e.UploadShaping != nil`
    (socket_authorization.go:82; rationale comment at 76-78). Nothing else blocks coexistence:
    - serve.go:139-143 sets e.UploadShaping, and serve.go:249 calls configureSocketAuthorization without a
      shaping check.
    - socket_session_enabled.go:11-13 and hostfirewall/socket_runtime_linux.go:58 contain no shaping reference.
    - The only gate is the build tag: without `socketprototype`, socket_session_disabled.go:12 refuses
      --socket-authorization.
    CONTRACT.txt:96-101 (item 8) says a mode that cannot preserve shaping "cannot use the prototype fast path" and
    needs measured kernel evidence, so "Fail unless §3 proves coexistence" is consistent. Mechanism notes:
    - The fast ACCEPT is in an nft OUTPUT chain (CONTRACT.txt:104-108), so tc egress still runs afterwards.
    - Offer is called only from ObserveResolved, the queue path (engine.go:309-311). Accelerated datagrams after
      the grant never reach Offer. Binding then relies on the first queued packet or the shaper's own census
      (manager.go:763-884). Record which path produced the binding.
12. **CONFIRMED: D1 code path.** For a zone without its own entry, loadZone sets
    `level.value = c?.traffic_priority ?? defaults.priority` (upload-shaping-view.ts:189). For a zone scope, Save
    is enabled whenever `t.revision` is set, for any level (line 180). save.onclick -> apply(null, level.value) ->
    replacePriority stores explicit zone `traffic_priority:"normal"` (upload-shaping.ts:97). The Go side keeps zone
    "normal" (manager.go:404 only strips All-scope Normal). The hint shows "All applies" (line 193-194) while the
    select shows the Options default. Doc basis: ZONE-SHAPING.txt:20-22 and 88-90 ("Opening ... do not write";
    explicit zone Normal is an override). The doc does not literally forbid an untouched OK write, so D1 is a
    defect against the stated inheritance intent (reasonable, but label it as intent-derived). D3 is CONFIRMED:
    paintAvailability rewrites aria-label to `${kind} for ${row}` with kind "upload"/"download"/"priority"
    (upload-shaping-view.ts:18-24, called after lines 87/97). electron/test/zone-popup-ui.mjs:216-217 and 320 look
    for "Upload limit for ..." and "Traffic priority for ...".
13. **REFUTED: V6 as written cannot reach allocation_below_minimum.** For a 16 M budget with Low apps, the
    per-app floor is 1.6M·9.6M/(2.4M+1.6M·n), which first drops below 256k at n=37. With 1 M Low caps it stays at
    or above ~0.52M for n=16. MaxCaps=16 (manager.go:19, zones.go:116) and MAX_APPS=16 (controller.py:20,1224)
    give class_capacity at 17 apps first. So V6 records class_capacity, not the intended refusal.
    allocation_below_minimum at 16 M is reachable only through zone child floors (zones.go:160-198;
    controller.py:110-125), for example zoned apps with low All caps. Redesign V6 around zones or a minimum-cap
    population.
14. **REFUTED: §6 "Bypass continuing after applied_version is a Fail" contradicts the docs.**
    TRAFFIC-PRIORITY.txt:95-96 says the applied version "does not prove complete socket coverage". An app's class
    is created only at its first bind (targets uses `live` = self.apps, controller.py:1057; set_policy only updates
    existing apps, 1240-1243). Binding is asynchronous (hint or census tick, manager.go:756-884). On a transition
    from no entry to an entry, A's probe is legitimately in fff1/fffe after applied_version until the bind.
    Restrict the Fail to bindings that already existed before the edit, or measure "applied -> first upload_class
    binding" separately. The budget-transition window itself matches code (publish_budget around the TC change,
    controller.py:1100-1101, 1146-1147).
15. **CONFIRMED with a missing item: §5 gap names.** `unsupported_or_shared_observation` and `binding_refused`
    exist (manager.go:515, 924). Missing from the attribution category: `unsupported_or_shared_discovery` (873),
    `discovery_generation_changed` (877), `unsupported_flow` (915), `hint_capacity` (539),
    `unconnected_or_listener_needs_observed_peer` (841), `discovery_failed` (780, 859).
16. **Mislabel: SPEC §2 Supported row.** It lists "UL caps (TCP, connected non-GSO UDP)", while the Experimental
    row lists "connected UDP UL shaping". UDP UL is in two classes. The UI says only "TCP caps receiver-tested"
    (upload-shaping-view.ts:165), so UDP UL belongs in Experimental only. The whole shaper is
    experimental/opt-in (serve.go:69,72; TRAFFIC-PRIORITY.txt:1; manifest host_shaping_activation_authorized=false).
    "Supported" should read "documented within the experimental shaper".
17. **CONFIRMED: Unsupported items.** Wine/Proton per-app shaping is not eligible (manager.go:496 requires
    Kind "native"). Per-app UDP DL is unsupported (ingress.bpf.c:67-86; TRAFFIC-PRIORITY.txt:59). Restart
    persistence is unsupported (ZONE-SHAPING.txt:55). Note: the fast path covers native AND Wine IPv4 UDP output
    (CONTRACT.txt:28-29), so Wine fast grants are in scope while Wine shaping is not.
18. **UNCERTAIN: off-mode binding path.** Without protection there is no queue, so no Observe/ObserveResolved
    call reaches Offer (engine.go:232-311 is called from the queue path only). In off mode, binding is
    census-only (about 1 s tick, manager.go:763). Expect a longer first-traffic unshaped interval. Report it per
    cell; do not count it as a defect.
19. **CONFIRMED: provenance spot checks.**
    - `git diff 50835463 93eaa868 -- internal/uploadshape experimental/upload-shaper internal/daemon/upload_shaping.go`
      is empty.
    - Against 3761aa9e, the listed shaping/docs paths are identical.
    - 93eaa868 is not an ancestor of 3761aa9e.
    - controller.py sha256 starts with 1bc75830.
    - The 12 `*-none-normal-*` cells (3 modes × 4 budgets) are correct.
    - Validation bounds V3/V4/V5 match manager.go:48-49, 373, 379, 117.
20. **Minor: §3.2 vs §3.4.** "Exactly one leaf else Inconclusive" must apply only where app_ul_class is true.
    Otherwise every no-class cell is Inconclusive instead of being covered by the §3.4 zero-delta negative check.

## Blockers (spec changes needed before running)
- B1 (#7): §3.3 packet/byte identity and receiver arithmetic ignore that HTB counts at dequeue. This gives false
  Fail/Pass whenever there are drops or backlog.
- B2 (#10a/b): §4 uses rate instead of ceil and omits the one-skb deficit, which causes false Fails in budget cells.
- B3 (#13): V6 cannot produce allocation_below_minimum in the All-scope population.
- B4 (#14): the §6 Fail rule contradicts the documented coverage semantics for newly configured apps.
- B5 (#9): tc JSON rate/ceil are bytes/s. Without explicit conversion, the §3.2 tuple equality always fails.

## Non-blocking notes
- #4 wording of `default_*_class_fffe`. #5 priority-only entries produce a class-less binding (not refused)
  and use an app slot. #8 the GSO label is "unvalidated", not excluded. #11 D2 line ref 41 -> 42; record the
  binding source in fast mode. #12 D1 is intent-derived. #15 add the gap names. #16 the UDP UL double
  classification. #18 off-mode census-only binding. #20 §3.2 applicability. Record the socketprototype build tag
  and the iproute2 version in the provenance.

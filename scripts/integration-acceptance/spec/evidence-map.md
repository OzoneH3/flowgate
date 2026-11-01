# Prior evidence vs candidate 93eaa868 (shaping layer)

Code relation computed with `git diff <trial> 93eaa868 -- internal/uploadshape experimental/upload-shaper internal/daemon/upload_shaping.go`.

| Evidence | Build | Kind | Code relation to candidate | Applicability |
|---|---|---|---|---|
| shaping-host-trial (UL, first) | 94f7876 | **physical enp7s0 + Unraid** | 41 files differ | UNSUCCESSFUL (GUI row selection); no shaping claim |
| shaping-host-retry (UL 8/16/off: 7.67/15.29/938.7 Mbit/s, TCP Deny 0) | 94f7876 | **physical** | 41 files differ (pre-DL, pre-priority, pre-zone controller/BPF) | Predecessor: physical TCP UL cap mechanism on this NIC. Not current-code evidence |
| shaping-download-host (DL 8/16/off: 7.66/15.31/937.0, UDP Deny 48→0) | b06ae6a | **physical** | 29 files differ incl. classify/ingress BPF, kernel.c | Predecessor: physical TCP DL/IFB on enp7s0. Not current code |
| priority-host-517 (40 M budget Low/High UL 4.00/35.30 ↔ 35.62/4.03, DL 6.16/34.06 ↔ 35.27/5.13; capped High 7.91/8.42; UDP RTT p95 small sample; Deny 8→0) | 517f001d | **physical** | 16 files differ: controller.py (+205/−), manager.go, NEW zones.go. **BPF/kernel helpers identical** | Closest physical evidence: same BPF/kernel datapath, pre-zone controller/manager. Supports All-scope legacy priority behaviour on enp7s0; it does NOT prove the zone-hierarchy controller now installed |
| zone-receiver run2/3/4, reclassification | 4a478da3 | isolated guest (netdevsim) | **0 files differ** | Current shaping code, guest only: zone caps, inheritance, swap, cross-app reversal |
| shaping-prio bundles 28b1a7ba / 39466cb | — | isolated guest | 20 / 18 files differ | Predecessor guest, includes recorded failures (min-budget Low misses) |
| socket-shaping-control-v1 (fast path vs TCP DL) | socket-auth prototype | isolated guest | prototype lineage | Supports TCP DL alongside accelerated UDP UL only; UDP DL expectation was wrong; no same-flow class proof |

None establishes current Wine, UDP-class (same-flow), fast-path coexistence or zone behaviour on the physical host.
No physical trial ran on 93eaa868 (manifest: host_shaping_activation_authorized=false).

# Current status

Started from an empty directory with no starting SHA. Worktree `/home/flowgate-user/Apps/flowgate`, branch `milestone/backend`. Run `git rev-parse HEAD` for the committed snapshot.

## Implemented

Go CLI and v1 peer-authenticated Unix API; read-only diagnostics; inet_diag/proc socket-owner snapshots; native identities; initial Wine/Proton metadata resolver; separate filter/action rules with deterministic precedence; bounded pending decisions; drop/retry approval; isolated nftables/NFQUEUE enforcement; focused tests and PE networking fixtures. Application rules and history are memory-only. Authoritative remaining roadmap: PLAN.md.

## Direct evidence on this machine

CachyOS, Linux 7.2.9-2-cachyos x86-64, Go 1.27.2, Wine 11.19. No GUI/init dependency in the test processes. `scripts/check.sh --wine` is the complete reproducible test command; `.workspace/verification.log` records the latest run.

- Go race-enabled unit/API tests: precedence/ties, distinct app/revision match, unauthorized answers, replaced identity, deduplication, pending timeout, stale answers, UDP lease expiry, rule expiry/cache invalidation, bounded events/rate, read-only API/version rejection, packet parser and a real listener socket dump.
- Receiver-observed isolated incoming TCP/UDP IPv4 and IPv6: no data before approval, delivery after approval/retry.
- Receiver-observed block, timeout/retry, stale CLI answer, UDP listener replacement, SO_REUSEPORT ambiguity, repeated attempts with bounded state, SIGKILL/no queue consumer.
- Receiver-observed outgoing TCP and UDP approval.
- Actual separate native executable paths: application Allow versus Block; a different executable reusing the allowed port is prompted and receives nothing before approval.
- Actual PE32+ Windows executables alpha.exe and beta.exe: same runtime and same prefix, different logical keys. Both sockets have the application plus wineserver as owners. Shared ownership remains explicit; ambiguous traffic is denied at both receivers. Evidence: `.workspace/run/wine-attribution.json`.

**The decisive Windows Allow-one/Block-the-other scenario has not passed.** Initial Wine identity resolution is implemented and exercised, but per-application Wine enforcement is blocked by the observed shared descriptor ownership. No game behavior is verified. This is a working native laboratory slice, not a complete production or Wine milestone.

## Capability results and limits

Unprivileged user/network/PID/mount namespaces, nftables transactions, real NFQUEUE binding, conntrack decision marking and socket diagnostics worked in the isolated harness. Host nft table inspection is denied without CAP_NET_ADMIN; coexistence with host firewall/VPN managers is therefore unverified. BTF is present, unprivileged BPF is disabled (2), hooks/load permissions were not exercised. Host process visibility is reduced. No eBPF dependency was introduced.

Default Go build was checked using file/ldd: x86-64 ELF with libc, libresolv and dynamic loader dependencies; no static/portable claim. No arm64, Debian/Ubuntu or Fedora runtime validation. Test processes require no init system, but no separate non-systemd distribution has been tested.

Unverified: independent prefixes/same basename; launcher spawning another executable; real Proton/Heroic/Lutris/Bottles/Flatpak; adversarial FD transfers; actual PID number reuse (start-time rejection is tested synthetically); dual-stack ambiguity at receivers; VPN interaction; hostile local applications; real traffic throughput. No persistent SQLite, Qt, domain policy or rate limiting of bandwidth.

## Host changes and next step

No host firewall rules, routes, interfaces, services, launch settings or existing prefixes were changed. Namespace firewall objects and loopback changes were disposable. Kernel networking modules may be autoloaded by namespace feature use. Build/cache/output and the fresh Wine prefix live under `.workspace`.

Next: determine whether non-invasive Wine handle/FD lifecycle evidence can identify the receiving Windows application despite wineserver's retained socket, including duplicated/inherited handles and broker-only periods. Do not simply exempt wineserver from the owner set. If baseline observation cannot safely distinguish it, document that boundary and design opt-in per-launch isolation with explicit shared-relay limitations. Current blocker is attribution correctness, not a missing privileged operation; no additional host authorization is requested.

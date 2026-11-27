# FlowGate project audit and roadmap

22 November 2026 · Source reviewed at `6df60ab3dab378899ce1323cf34103b2deb78071`

Prioritize a patched, independently verified standalone release. Then make the
same checks repeatable across supported desktops and measure the remaining UDP
and shaping limits before widening their support.

## Audit findings

| Area | Observed state | Work to close |
| --- | --- | --- |
| Release integrity | Standalone packages carry source and version metadata, pin helper bytes, and have separate archive and installer receipts. The reviewed `8338adf2` archive passed the Debian 13.7 upgrade from RC8, UDP accounting on stock `/run` with `noexec`, collector start and cleanup on the reverse mount layout, and rollback. COSMIC run `063496d36be5` passed Next and Allow once on those exact bytes. | Keep those receipts as a baseline. Record candidate SHA, asset hashes, runner SHA, profile, scenario, and run outcome together for the next release. [Release procedure](STANDALONE-RELEASE.md#maintainer-release-handoff) |
| Shipped runtime | Both retained archives, `8338adf2` and `6df60ab3`, contain Electron `44.9.0`. npm reports the upstream eMudhra certificate advisory, fixed in the 44.x line at `44.9.1`. The advisory requires an interceptable TLS connection. FlowGate-specific exposure remains unverified. | Move to a patched runtime and check the runtime actually shipped in the new archive. [Electron advisory](https://github.com/electron/electron/security/advisories/GHSA-jr5w-w6x2-84p9) |
| Desktop confidence | `6df60ab3` fits the action rows in an 848×480 native Wayland fixture and passed a synthetic Pending-to-Decision-Log journey on KWin. Archived runs show GNOME footer clipping or movement, and some lab attempts stopped on ambiguous request or control selection. | Verify the candidate on the stock guest profiles. Record product layout failures, verifier stops, and terminal receiver results distinctly. [Compatibility record](COMPATIBILITY.md) |
| Policy and attribution | Rules use executable, user, direction, and supported runtime/prefix evidence. Ambiguous holders remain explicit. Established TCP disconnect is limited to a newly winning Block on an eligible socket. Prior Wine UDP receiver measurements still show loss under concurrent flows or overload. | Preserve these boundaries and measure current throughput with receiver counts and queue/attribution counters on the same workload. [Attribution](ATTRIBUTION.md) · [Established TCP control](ESTABLISHED-TCP-CONTROL.md) · [UDP capacity evidence](UDP-ATTRIBUTION-CAPACITY.md) |
| Test and distribution maintenance | Local checks passed at the reviewed checkout. `make check` covers 32 installer, freshness and version tests. The Electron build and 457 unit tests passed, as did focused Go packages for the CLI, daemon, readiness, policy, store, UDP collector, firewall and accounting. The snapshot has no tracked CI workflow or project-level license file. The font has a separate tracked license. | Add a versioned check entry point for routine development. Record the maintainer’s licensing decision and review notices for the shipped payload before wider distribution. [Make targets](../Makefile) · [Electron checks](../electron/package.json) · [Font license](../electron/assets/fonts/LICENSE-Selawik-OFL.txt) |

## Roadmap

### TODO · Fedora GNOME permission popup

- [ ] Investigate supported GNOME Wayland integration for bottom-right placement
  and above-window stacking. Verify both on stock Fedora without focus theft.

### P0 · Qualify the next release

1. **Patch Electron and select one candidate.** Update the lockfile to a patched
   version, build from a clean commit, verify the packaged runtime version, and
   retain the archive, installer and both SHA-256 receipts. Re-run the dependency
   advisory check. Finish when the candidate carries the same version and source
   in its manifest, CLI, installed path and About view. Record project licensing
   and shipped notices in the release checklist.
2. **Re-run the installer and policy gates on those bytes.** Use the committed
   Debian lifecycle and capture the install, upgrade and rollback identities.
   Require automatic restoration of both protection directions, unchanged saved
   Block ID/version and zero matching TCP deliveries. Recheck both mount layouts
   and anonymous helper cleanup after forced and clean exits. Require the 12 UDP
   requests and 12 echoes to match the probe’s expected 14,400 uploaded and 4,800
   downloaded payload bytes. [Debian lifecycle fixture](../scripts/acceptance/standalone-lifecycle/README.md)
3. **Close the native desktop gaps.** Run the chosen archive first on COSMIC and
   a short GNOME output, then on KDE and Hyprland where recent fixtures stopped.
   Confirm the footer stays reachable during handoff. Require the exact request
   and both endpoints before clicking, one enabled Once action, a linked final
   decision, unchanged saved rules, and the expected terminal delivery count
   with the competitor still pending at zero. Exercise keyboard focus and the
   Pending → Decision Log journey. Report results by candidate and profile. [Desktop pass criteria](COMPATIBILITY.md#what-counts-as-a-desktop-pass)

### P1 · Make regression checks repeatable

- **Add a clean, unprivileged check job.** Run the standalone checks, focused Go
  tests and Electron build/tests from a single documented entry point. Record
  toolchain versions and keep dependency advisory results with the package
  evidence. Keep native/kernel and VM checks in the guarded lab workflow.
- **Give operator docs one current release record.** Refresh the README and
  compatibility matrix from the selected manifest and verified runs. Put older
  deployment and profiling results behind their historical links. Keep the
  standalone workflow prominent and document the pinned checkout workflow for
  developer use. [Status](STATUS.md) · [Developer deployment](DAILY-DEPLOYMENT.md)
- **Reduce desktop verifier ambiguity.** Replay stale geometry, same-app
  different-dial, and ambiguous rule-control cases before sending input. Use the
  selected rule ID, version and scope to verify edits and deletion. Promote a
  fixture result to the compatibility record after a matching native run.

### P2 · Measure before widening coverage

- **Profile native and supported Wine UDP under load.** Compare a pinned baseline
  and candidate with the same steady and burst workloads. Record allowed
  delivery, tail latency, CPU and the reason counters for queue or attribution
  loss. Require zero delivery for denied probes and negative checks across two
  Windows executables and two prefixes. Keep inconclusive ownership explicit.
  [UDP capacity method](UDP-ATTRIBUTION-CAPACITY.md) · [Wine support](WINE.md)
- **Keep traffic shaping experimental until recovery and coverage are measured.**
  Exercise eligible upload and download sockets separately, scoped exclusions,
  competing traffic, service restart, and owned-state cleanup. Keep observed
  usage separate from delivery and billable totals. Defer quotas and schedules
  until there is a defined accounting and restart contract. [Shaping coverage](ZONE-SHAPING.txt) · [Usage history](USAGE-HISTORY.md)

Audit scope includes repository inspection, local build and test results, both
retained archive receipts, and earlier lab evidence. Fresh guest runs and a
full security review of the daemon and its dependencies remain outside this audit.

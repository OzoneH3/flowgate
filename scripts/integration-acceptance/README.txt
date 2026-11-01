FlowGate integration acceptance (test-only; isolated execution)

Frozen installed production source: 93eaa868ec2a1f98c0b66b27a682e2f332a23746.
All new tracked files belong to this suite. Do not alter production to get a pass.
Expected contract: spec/FROZEN.txt + SPEC + expected matrix when present;
EXPECTATIONS.txt is the original reviewed draft, not a replacement for final spec.
Core144 = protection mode3 * limits4 * priority3 * directional budgets4.
Scopes/lifecycle/runtime/load are separately enumerated extensions, not implied by
that denominator. report.py always emits all144 cells, missing = Not tested.

Dependencies/inputs:
- Python3, QEMU TCG, cpio/gzip, module dependency metadata and matching guest kernel.
- Existing initramfs with Python/ip/nft/nsenter and base runtime (explicit input).
- Exact released backend + helper manifest (stage verifies every selected artifact).
- Test inspect helper and sender.c compiled with cc -O2 -Wall -Wextra. Compile ONLY
  test code; no backend/helper rebuild is necessary. Set TMPDIR within workspace.
- Chromium/playwright/esbuild for GUI fixture; frontend node_modules from repository
  lockfile. gui.mjs bundles test imports only; never opens installed GUI/API.

Example (all paths absolute, all outputs beneath the workspace):
  cc -O2 -Wall -Wextra sender.c -o "$EVIDENCE/helpers/sender"
  # Supply existing inspect helper beside sender; record its hash.
  python3 vm.py stage --workspace "$WORKSPACE" --output "$EVIDENCE/fast" \
    --mode fast --case core --release "$EXACT_RELEASE/backend" \
    --helpers "$EVIDENCE/helpers" --kernel "$GUEST_KERNEL" \
    --base-initrd "$BASE_INITRAMFS" --kernel-release "$KERNEL_RELEASE"
  python3 vm.py run --workspace "$WORKSPACE" --output "$EVIDENCE/fast" --timeout 1800
Repeat stage/run for protected and off into NEW dirs, serially (TCG1CPU/2GiB).
No network device or filesystem share is supplied to QEMU. Internal netdevsim
links only; no host API, launcher, service manager, module load or protection toggle.
Stage uses read-only modprobe --show-depends; loading occurs only INSIDE guest.
Stage/run refuse overwritten evidence and hash-check the immutable guest images.
Use extensions-stage.py (same stage arguments, no --case) for scope, priority,
UDP-only loss, coverage escape, policy receiver and validation extensions. It
overlays the reviewed modules and re-hashes the image. A bare --case extensions
is insufficient: it does not include those additional modules.
Use lifecycle-stage.py with --tests pointing at the compiled tagged test directory
for cold-boot, kernel receiver and recovery components. Compile on the host only;
execute the resulting test binaries exclusively inside the guarded disposable VM.
  python3 report.py "$EVIDENCE" --output "$EVIDENCE/core-report.json"
  node gui.mjs

Guest failures retain serial.log, execution.json and exported JSON/errors.
Timeout leaves incomplete cells Not tested. Failure is not changed to Unsupported
unless the frozen capability contract explicitly says so. Do not tweak acceptance
bands after seeing results. A harness defect is fixed in a new version/run, with
prior evidence retained and clearly invalidated for that particular claim.

Measurements:
- receiver sequence counts/delay/reordering/duplicates + sequence-matched echo RTT;
- quiet and deliberately constrained bulk windows separated;
- TCP multi-socket payload aggregate, DL receiver bytes; actual tc/IFB counters;
- same UDP socket across edits, fast hits, class-byte charge in UDP-only window;
- per-cell daemon CPU, driver CPU, queue/shaper snapshots, configuration apply and
  binding wait. All times are guest monotonic; TCG result is not physical latency.
- No summing BPF hit counts into application usage/accounting.
- Current lower-rate/latency target is observational; cap bound derives rate*time,
  burst, superpacket and receiver-buffer allowance. Final spec controls verdicts.

Reuse existing focused Go tests (Connection*, SocketInitial*, SocketSession*,
SocketZone*, FastPath*, TrafficPriority*, ZoneSchema*, ZoneCapacity* etc) with
GOCACHE/GOTMPDIR/TMPDIR inside workspace. Create .workspace/tmp before daemon
tests. Kernel-tagged tests must NOT be run on host. Retained lifecycle receiver
runs have a distinct evidence map; component tests do not prove receiver delivery.

PHYSICAL-PLAN.txt is NOT executed by any command in this suite.

Assessment and exact run scope:
- Frozen expectations v2.1 plus explicit spec/ERRATA.md are authoritative.
- priority_assess.py preserves Pass/Fail/Inconclusive; an unsaturated priority
  experiment is never a pass. Exact UDP-only loss attribution is separate from
  mixed TCP/UDP leaf-drop upper bounds.
- capabilities.py generates the 6912 extended combinations with explicit
  capability limitations; these are not 6912 executed receiver tests.
- Core serve argv is retained in each evidence directory. It uses production
  protection startup but omits optional UDP accounting/TCP initiation collectors,
  the holder iterator, Wine observers and systemd recovery integration. Therefore
  tc class charges and fast hits do not establish application-usage accounting.
- Lifecycle results are tagged Go kernel components, not full-daemon end-to-end
  recovery. GUI uses the exact bundle against a synthetic API, not the host.

Optional case isolation and declared supplement:
- extensions-stage.py --modules policy_receiver,validation runs those reviewed
  modules in a fresh guest (same --mode and pinned release inputs).
- --modules priority --p1-only --p1-window-ms 8000 stages the declared A1
  supplementary 8-second-window priority experiment. It never replaces the
  official frozen 4-second result. See spec/ERRATA.md before using it.
- summarize.py applies the E3 P2 within-phase-variation correction to retained
  records, exposing raw and assessed verdicts without rewriting guest evidence.
For future releases, retain the expected contract, independently review any
changed capability semantics, pass the new exact release/manifest into staging,
and label the tested revision explicitly in the report. Never reuse 93eaa
coverage claims simply because a later manifest can be staged.

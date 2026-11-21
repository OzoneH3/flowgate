# Standalone upgrade, UDP accounting, and rollback on stock Debian

Run from the FlowGate checkout after coordinating one disposable Debian SUT slot
with the lab runner. Run as the ordinary host user with `qemu:///session`.
The runner owns the host TCP receiver and guest cleanup. The lifecycle binds
its UDP echo receiver to an ephemeral loopback port on the lab host.
Build the committed candidate with `make package VERSION=0.1.0-rc.8` and a
separate `ARTIFACT` path under `build/dist/`. Set `CANDIDATE_DIR` to that
directory, `CANDIDATE_SOURCE` to the full source commit, and the two SHA-256
variables to the trusted receipt digests.

```sh
python3 -B scripts/acceptance/standalone-lifecycle/run.py --lab ../flowgate-lab \
  --new-dir "$CANDIDATE_DIR" --new-source "$CANDIDATE_SOURCE" \
  --new-archive-sha256 "$CANDIDATE_ARCHIVE_SHA256" \
  --new-installer-sha256 "$CANDIDATE_INSTALLER_SHA256"
```

The test pins the published bytes of RC8 predecessor `13e3029a`. By default
it reads the archive and its installer from `build/dist/rc8-13e3029a/`.
Use `--old-dir` to locate those same files elsewhere. Both pairs are checked
against their digests on the host and in the guest.

1. Install the unmodified predecessor in monitoring. Activate both directions,
   save an outgoing application Block using the preview/save API, and verify
   zero TCP delivery with that rule's ID and version winning the decision.
   Record the collector's helper-execution failure and verify that
   `/run/flowgate-api` is on the stock `/run` mount with `noexec`.
2. Use the candidate's documented offline `preflight` and `install`.
   Verify the running and on-disk build, a new daemon generation, an active
   collector, automatically restored protection in both directions, the
   unchanged Block, and zero TCP delivery.
3. Exchange 12 labeled IPv4 UDP requests of 1,200 payload bytes and replies of
   400 payload bytes. Check every sequence at the host and at the guest.
   Compare Activity deltas against 14,400 uploaded bytes and 4,800 downloaded
   bytes on the same registered probe socket and collector generation. Remove
   the scoped UDP Allow and verify that the original Block is unchanged.
4. Use the installed `flowgate-recover --rollback`. Verify that the predecessor
   runs in monitoring with a fresh generation, retains the rule, and again
   reports the helper-execution failure. Reactivate both directions through
   the API, confirm zero TCP delivery and the same winning rule, then delete
   the disposable rule.

Run `6a50c67f791d` at fixture commit `db778b70` is the historical comparison.
It passed after creating an executable API submount in the disposable guest.
The stock regression uses no submount and checks the mount at each stage.

Each run writes `standalone-lifecycle.json` and matching JSONL evidence under
`.workspace/standalone-lifecycle/runs/<run-id>/`. The runner returns nonzero if
a stage, receiver assertion, or guest cleanup fails.

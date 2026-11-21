# Standalone upgrade and rollback on Debian

Run from the FlowGate checkout. The existing flowgate-lab runner starts one
disposable Debian guest, runs the enrolled user's probe over SSH, and owns the
host TCP receiver and guest cleanup.

```sh
python3 -B scripts/acceptance/standalone-lifecycle/run.py --lab ../flowgate-lab
```

The test pins the previously verified RC8 predecessor `13e3029a` and the
public-audit RC8 candidate `7511ac17`. The defaults point to the predecessor
in `build/dist/rc8-13e3029a/` and the audited candidate in
`.workspace/public-audit-01a1ff88/source/build/dist/rc8/`. Use `--old-dir`
and `--new-dir` if those same files are stored elsewhere. Each directory needs
the archive and `flowgate-release.py`. The fixture checks their pinned digests
on the host and in the guest.

If the guest mounts `/run` with `noexec`, the predecessor's UDP collector
cannot execute its pinned helper and the installer refuses the upgrade. To
test the rest of the lifecycle on that guest, append `--guest-api-exec-mount`.
This puts a root-owned executable tmpfs at `/run/flowgate-api` only in the
disposable guest. The installer still checks the collector and protection state.

1. Install the predecessor in monitoring. Activate incoming and outgoing
   protection, save an outbound application Block with the ordinary
   preview/save API, then confirm its rule ID and version win a fresh TCP
   attempt. The probe must finish denied and the receiver must count zero.
2. Upgrade using the documented offline path, `preflight` and `install`
   through the verified candidate installer. Verify the running and on-disk
   build, new daemon generation, restored protection mode, complete saved rule,
   and a fresh blocked attempt.
3. Run `sudo /usr/local/sbin/flowgate-recover --rollback` in the guest. Verify
   the predecessor, a new generation, and the documented monitoring state.
   Reactivate protection through the normal API and test the same rule against
   a third labeled attempt. Remove the disposable rule.

Each run writes `standalone-lifecycle.json` and matching JSONL evidence under
`.workspace/standalone-lifecycle/runs/<run-id>/`. The runner returns nonzero
if any stage, receiver assertion, or guest cleanup fails.

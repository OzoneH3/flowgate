# Fedora 45 failed-collector upgrade regression

From the FlowGate checkout, run once the lab VM slot is free:

```sh
python3 -B scripts/acceptance/fedora-collector-upgrade/run.py
```

Use the prepared Fedora 45 profile, x86-64 base image, SSH key, and
`flowgate-lab` runner at `bd60c80a` or a compatible successor. The script
pins the source revisions and both artifact digests for each release.
Its default paths are under `build/dist/fg-lab-fedora` for `7b3e8e51`, and
`build/dist/fg-lab-fedora-guard-final` for `64a07da1`. Override those paths
with `--old-dir` and `--new-dir`, and the sibling lab checkout with `--lab`.

The existing lab runner owns the one disposable overlay, old installation,
host-loopback TCP receiver, and teardown. The fixture creates an explicit
outgoing TCP endpoint Allow for the host receiver. It checks the two refusal states and monitoring
recovery, uninstalls without purge, verifies the retained database and installs
the exact replacement. It requires an active collector, an identical saved
rule, and one labeled host delivery with a matching Decision Log Allow while
protection is active. SELinux must remain enforcing.

The result includes the verified artifacts, collector states, saved rule ID
and version, and receiver evidence. It is written under the printed
`.workspace/fedora-collector-upgrade/runs/<id>/` directory. The command exits
nonzero on failure. See the [administrator sequence](../../../docs/STANDALONE-RELEASE.md#fedora-45-recovery-from-the-rc8-collector-failure)
for the supported upgrade procedure.

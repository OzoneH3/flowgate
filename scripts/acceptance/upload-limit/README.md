# Per-application bandwidth limit acceptance

Run from the FlowGate checkout after coordinating one disposable Debian guest
with flowgate-lab. The default locations are the sibling flowgate-lab checkout,
its Debian 13 profile, and the locally packaged RC8 `13e3029a` pair under
`build/dist/rc8-13e3029a`.

```sh
python3 -B scripts/acceptance/upload-limit/run.py
```

For download, use the host as sender on the same TCP connections:

```sh
python3 -B scripts/acceptance/upload-limit/run.py --direction download
```

Use `--lab`, `--profile`, or `--dist` to override those locations. The tested lab
runner is `75af5ee`. The runner checks both package digests and the installed
daemon's source and executable digests. Go builds two distinct static native
test executables. Use `--local-check` for a loopback test of the probes, receiver,
and rate calculations without a guest.

Only the guest opts into the packaged shaping controller. The test checks the
existing single-queue NIC preflight and installs `ethtool` from the guest's Debian
repositories if absent. It uses the existing TCP link and SSH transport and
opens one verified stream per application under the same enrolled
UID. Both streams use the same guest interface and the same host service
address and port. Shaping state is changed on the primary Unix socket with the
current daemon generation and expected version. The test waits for applied
configuration and a binding for the selected direction on A's exact socket
cookie before measuring the capped phase. Payload bytes are counted at the host
for upload and inside each guest application for download. The download case
also requires a positive IFB redirect counter delta during A's capped phase.

| Check | Criterion |
|---|---|
| Headroom | Both unrestricted baselines at least 5× the selected cap |
| Cap | Highest whole Mbit/s meeting headroom, within 4–20 Mbit/s |
| A under cap | 75–120% of the configured rate |
| B with A capped | 70–130% of B's baseline |
| A after removal | 70–130% of A's baseline |

The values use decimal Mbit/s from receiver bytes and monotonic elapsed time.
Each sample uses a seven-second window after three seconds of warm-up.
Applications transfer in separate windows to avoid sharing the link's throughput
during measurement. The same sockets are retained throughout.

An unsupported interface, missing download binding, or inadequate route is
inconclusive and returns nonzero. Other failures also return nonzero. The lab
removes the guest overlay. See `.workspace/application-upload-limit/runs/` or
`.workspace/application-download-limit/runs/` for phase results, receiver
counters, stream identities, API replies, and shaping status and counters.

# Isolated zone receiver checks

These fixtures extend the existing limiter VM test. They never attach a host
interface or contact an external peer. The existing authoritative classifier is
configured with `--zone-local 10.79.0.2/32` and `--zone-internet fd79::2/128`.
Both assignments are synthetic; neither demonstrates public Internet access.

Run from the repository root, with the original bounded test artifacts present:

- `.workspace/holder-work/initramfs.gz`
- `.workspace/shaping-m1/vmlinuz` (7.3.0-4-cachyos) and its installed module files
- `.workspace/priority-continuation-guest/core-journey/helpers/`: unchanged
  `sender`, `probe`, `inspect`, `kernel`, and `classify.bpf.o`

The stage script reuses these files and the current controller/peer source. It
never accesses the old worktrees. QEMU has one TCG CPU, 2 GiB RAM, a 3600-second
outer timeout, and only an internal virtual network hub. Staging copies modules;
it does not load host modules. All output goes under `.workspace/zone-receiver`.

```sh
mkdir -p .workspace/zone-receiver .workspace/tmp
TMPDIR="$PWD/.workspace/tmp" go build -o .workspace/zone-receiver/flowgate-new ./cmd/flowgate
python3 experimental/upload-shaper/zones/stage.py receivers
python3 experimental/upload-shaper/zones/run-vm.py > .workspace/zone-receiver/receivers.log 2>&1
python3 experimental/upload-shaper/zones/extract.py receivers
```

Replace `receivers` with `capacity` or `api` in the stage argument and log/extract
name. Run cases sequentially: they share the staging directory. Preserve
`staged-hashes.json` alongside each run before staging another case.

- `receivers`: one executable simultaneously uses Local and Internet peers, two
  UL process sockets plus two DL sockets per zone. Independent caps, cumulative
  All networks ceiling, live zone deletion, shared-budget priorities and swaps.
  Measurements drain/settle for three seconds, then count receiver delivery for
  eight seconds; the initial window is repeated to detect sustained overshoot.
- `capacity`: four zoned applications (16 application class nodes), eight sockets,
  both-direction budget/priority edit, kernel lease margins, and cross-application
  priority swap measurements. Relative delivery is recorded without promising
  strict global scheduling order.
- `api`: real schema-2 rejection, stale CAS, one submission with a deliberately
  unread receipt followed by status reconciliation, and DL class/queue identity
  plus receiver measurements across last-zone removal and an added UL zone.

Each run retains independent Deny checks and verifies original-qdisc restoration
and unchanged fixture firewall rules. The thresholds are fixed in the case files;
API acceptance is never used as delivery evidence. These tests do not exercise
public connectivity, physical topology events, or foreign-object recovery.

The optional `reclassification` case builds a test-only stdin driver:

```sh
TMPDIR="$PWD/.workspace/tmp" go build -o .workspace/zone-receiver/classifier-driver ./experimental/upload-shaper/zones/classifier
python3 experimental/upload-shaper/zones/stage.py reclassification
python3 experimental/upload-shaper/zones/run-vm.py > .workspace/zone-receiver/reclassification.log 2>&1
python3 experimental/upload-shaper/zones/extract.py reclassification
```

The driver uses the production uploadshape.Manager and daemon.Engine.CurrentZones
with immutable NewNetworkZones fixtures. It changes the same live IPv4 socket
from Local to synthetic Internet to Unknown. The normal daemon's shaping is
disabled first; its separate firewall remains active. The test records receiver
rates and kernel map cookies/class IDs after each classification. No production
API or alternate classification algorithm is added. The host-trial option is
used only inside this disposable network/PID namespace, never on the host.

# Fedora 45 protected boot and daemon restart

Run from the FlowGate checkout with the prepared Fedora 45 base and SSH key
from the adjacent `flowgate-lab` checkout. Build an RC8 package with the
normal standalone workflow. Use the generated archive, offline installer,
and their SHA-256 receipts.

```sh
make package VERSION=0.1.0-rc.8 \
  ARTIFACT="$PWD/build/dist/fg-lab-fedora-guard/flowgate-0.1.0-rc.8-linux-x86_64.tar.gz"
python3 -B scripts/acceptance/fedora-guard/run.py
```

Use `--artifact-dir` or `--lab` for other locations. The lab runner verifies
the artifacts, owns the one disposable overlay, and compares the installed
build with the manifest. SELinux must remain enforcing.

The fixture persists both-direction protection via the guest API and powers the
guest off. It starts that same overlay again to exercise the real early-boot
unit. A fixture unit ordered after the guard and before NetworkManager records
the guard's owned table and sends one outbound TCP attempt. A fixture-only
check appended after the daemon's existing `ExecStartPre` takes a second
snapshot. It repeats during a protected daemon restart. The production unit
commands execute unchanged, and their systemd status and journal are saved.

For each attempt, temporary nft counters match its exact tuple at output
priorities 8 and 10, bracketing the FlowGate guard at priority 9. The fixture
requires a hit before the guard, no hits afterward, and no host delivery.
A previewed endpoint Allow scoped to the private receiver verifies one payload
after each handoff under active protection. The fixture stops protection after
its checks to recover SSH management, removes its test units and Allow, and
then invokes the committed lab `udp-fast-path` scenario on the installed bytes.

The command exits nonzero on failure and saves the journal, guard tables,
invocation status, payload counts and UDP results under the printed
`.workspace/fedora-guard/runs/<id>/` directory. The host receiver binds
loopback. All temporary rules and service units live in the disposable guest.

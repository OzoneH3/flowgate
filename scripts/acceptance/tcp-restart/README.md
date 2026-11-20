# TCP disconnect across a daemon restart

This SSH-only case reproduces the retained TCP stream from the KRDC report using
two disposable copies of Python. It requires the existing `flowgate-lab`
Debian 13 and Ubuntu 26.04 profiles and lab runner at `02620ef` or a compatible
successor. The lab runner verifies and installs the RC8 artifacts, starts one
guest overlay and a host-loopback TCP receiver, and tears both down. No desktop,
VPN or host firewall changes are needed.

Use the RC8 archive and offline installer from the `5359baf0` AppArmor handoff.
The test pins both digests. The default artifact directory is
`build/dist/fg-lab-apparmor`. Use `--artifact-dir` if stored elsewhere.
Use `--lab` if the lab checkout is somewhere other than `../flowgate-lab`.

Run from the FlowGate checkout on the x86-64 lab host.

```sh
. ./scripts/go-env.sh
mkdir -p build/tcp-restart-acceptance
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
  -o build/tcp-restart-acceptance/conntrack-mark ./scripts/acceptance/tcp-restart
python3 -B scripts/acceptance/tcp-restart/run.py debian-13
python3 -B scripts/acceptance/tcp-restart/run.py ubuntu-26.04
```

Each case opens target-to-Local, target-to-Internet and second-app-to-Local
streams. Both guest addresses are private SLIRP gateways to the lab receiver.
Explicit guest zone prefixes give the two routes distinct policy classifications.
The lab probe sends one uniquely labeled payload per write and never reconnects
an established stream. An exact tuple and socket inode identify each retained
stream. A guest-only read of conntrack verifies the original tuple, row ID and
FlowGate mark bits without sending a packet on that tuple.

The runner restarts the installed daemon with the original streams still open.
It resets the guest unit’s start counter before each deliberate restart, then
waits for a new active protection generation and verifies the saved rules.
Each variant opens new sockets and creates its own rules.

| Variant | FlowGate mark bits before enable | Target Local after enable | Target Internet and other Local | Fresh target Local |
| --- | --- | --- | --- | --- |
| Preserved only | `0x20000000` | Terminated, 0 | 1 each | Block, 0 |
| Preserved and approved | `0x30000000` | Terminated, 0 | 1 each | Block, 0 |
| Losing Block, higher-priority Allow | `0x20000000` | Usable, 1 | 1 each | Allow, 1 |

Evidence is under the printed `.workspace/tcp-lab/<run-id>/` directory.
`established-disconnect-after-restart.json` records the two application
identities, generations, socket inodes and endpoint pairs, conntrack marks,
rule IDs and versions, client outcomes and receiver counts. The adjacent JSONL
contains the API exchanges. Failure returns a nonzero exit status.

# Real lwp / Proton outgoing-connection reproduction

This is a **known-failure reproduction**, not a claim that Proton permission
control works. A successful run means it reproduced the bug and completed the
receiver controls. No production attribution or policy code is modified.

## Run

From the repository root (the `env` form also works in fish):

```sh
env \
  FLOWGATE_TEST_PROTON="$HOME/.local/share/Steam/compatibilitytools.d/dwproton-11.0-4" \
  FLOWGATE_TEST_UMU_RUNTIME="$HOME/.local/share/umu/steamrt4" \
  FLOWGATE_TEST_PREFIX_SOURCE="$PWD/.workspace/proton-prefix" \
  scripts/checks/check-proton-launcher.sh
```

`FLOWGATE_TEST_LWP` can select the actual script; otherwise `command -v lwp`
selects it. The prefix source must be an initialized **workspace** Proton compat
directory containing `pfx/system.reg`. Installed runtime directories are read
and copied with reflinks where available. The copied runtime is not patched.
The original `lwp` script runs unchanged with a disposable HOME, an explicit
prefix argument, and a copied Proton directory in its expected Steam layout.

The runner creates a fresh `.workspace/proton-launcher-*` directory containing
builds, copied runtimes/prefixes, logs and `evidence/result.json`. It requires
unprivileged user/network/PID/mount namespaces, nftables/NFQUEUE, Clang/LLD,
installed UMU, and a compatible installed Proton/steamrt4. Runtime downloads and
updates are disabled; the private network has loopback only. No sudo, host
firewall changes, real game prefix access or daemon installation occurs.

## What runs

1. A labelled synthetic Python preflight connects to a local TCP receiver.
   The test approves its real pending request with a one-hour application rule
   in the private daemon's memory. This models a launcher's network request;
   it is not presented as an actual UMU update/HTTPS request.
2. The actual `lwp` script invokes installed Python/UMU, real pressure-vessel,
   copied unmodified Proton, `umu.exe`, and a freestanding Windows GUI-subsystem
   client. The client opens a plain blocking TCP connection to **the same
   receiver address and port**. No Wine FD-materialization workaround is used.
3. The matrix covers Alpha and Beta in prefix A, then Alpha in prefix B.
   Executable paths and canonical prefixes produce three separate identities.
4. Packet-drop evidence comes from the private daemon's SQLite Decision Log.
   The ordinary-user API correctly withholds unidentified events; waiting only
   on that API would incorrectly suggest an attribution hang.
5. After stopping the private interceptor, Alpha and Beta are launched through
   `lwp` again and must deliver their distinct payloads to the receiver.

Namespaces and UID maps for the daemon, broker and PE client, process generation,
launch provenance, raw socket cookie/inode and holder snapshots, exact decision
records, the synthetic Python rule, received payloads, and relevant file hashes
are retained. The launcher receives no inherited namespace capabilities;
otherwise bubblewrap refuses to start and the test would not represent a
normal desktop launch. The test daemon retains capabilities only in its private
namespace. Test descendants and in-memory rules disappear on namespace teardown.

## Observed baseline result

Verified on source `f1d545e`, DWProton 11.0-4 and the installed steamrt4:

- The Python preflight is allowed and reaches the receiver.
- Both EXEs and the second-prefix case are recognized individually as Wine
  applications, with verified UMU/pressure-vessel launch provenance.
- For the exact held outgoing TCP socket, the complete visible FD snapshot
  contains **wineserver alone**. The live Windows client is not a Unix FD holder.
- FlowGate records `unidentified`, reason `runtime observed but Windows
  image/prefix not corroborated`, followed by `drop_submitted`. No PE payload
  reaches the receiver under enforcement.
- Both control PE payloads arrive with the private interceptor removed.

This proves a generic broker/socket attribution gap in the real launcher path.
It does not prove that launch ancestry identifies the Windows requester, that a
Python rule should cover a game, or that assigning a rule to wineserver is safe.
A subsequent fix must supply verified per-socket application evidence and use
this real launcher test, rather than relying only on direct-Wine fixtures.

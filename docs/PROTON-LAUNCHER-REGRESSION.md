# Real lwp / Proton connection-control regression

The default run verifies connection control through the actual installed `lwp`
launcher. The original known-failure mode remains available by invoking the
Python runner without `--verify`; baseline evidence is described below.

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
   in the private daemon's workspace-only SQLite store. This models a launcher's network request;
   it is not presented as an actual UMU update/HTTPS request.
2. The actual `lwp` script invokes installed Python/UMU, real pressure-vessel,
   copied unmodified Proton, `umu.exe`, and a freestanding Windows GUI-subsystem
   client. The client opens a plain blocking TCP connection to **the same
   receiver address and port**. No Wine FD-materialization workaround is used.
3. The matrix covers Alpha and Beta in prefix A, then Alpha in prefix B.
   Each opens three simultaneous TCP connections. Their exact backend group
   identity must match, and one remembered decision settles the group. The
   executable directory contains spaces and `bash -c` invokes the real launcher.
   Executable paths and canonical prefixes produce three separate identities.
4. Alpha is allowed; Beta in the same prefix is denied; Alpha in another prefix
   requires an independent decision. New instances repeat these saved decisions.
   The receiver must receive Allow payloads and never receive Deny payloads.
5. Fresh Activity contains a separately verified Windows application association,
   while its original Unix FD holder remains wineserver. A real Activity rule
   preview/save must target the PE identity. All private rules are conditionally
   deleted, with the SQLite store checked empty before teardown.
6. After stopping the private interceptor, Alpha and Beta are launched through
   `lwp` again and must deliver their distinct payloads to the receiver.

Namespaces and UID maps for the daemon, broker and PE client, process generation,
launch provenance, raw socket cookie/inode and holder snapshots, exact decision
records, the synthetic Python rule, received payloads, and relevant file hashes
are retained. The launcher receives no inherited namespace capabilities;
otherwise bubblewrap refuses to start and the test would not represent a
normal desktop launch. The test daemon retains capabilities only in its private
namespace. Test descendants disappear on namespace teardown; the private rule database is emptied explicitly.

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

## Verified fix and boundaries

DWProton 11.0-4 (broker SHA256
`3f84ad1bc5116a82ec54ee15588f000dbc5d570c9c77c6007d82545d375fd792`)
passes the full real-launcher matrix. Wine 11.19 remains a hash-pinned supported
census version; this regression does not claim all Wine/Proton builds work.
Steam, Heroic and UMU use the same broker evidence when running a supported build;
launcher ancestry supplies no permission authority.

The collector joins the existing broker as the desktop user inside its pinned
mount namespace. It cannot start a replacement wineserver. Two Windows TCP owner
snapshots (exact local/remote endpoints, Windows PID, creation time and image)
bookend a kernel socket-cookie census. The broker generation, same-server Unix
channel, mapped PE image/revision and canonical prefix must agree. A broker's
extra FD is transport evidence. Conflicting clients or missing evidence reject.
A bounded 40ms publication retry does not wait for connection completion.

Runtime Activity rows retain their FD-owner list and carry a separate verified
Windows application. Preview and save re-resolve that socket; reused cookies,
changed broker generations or different executable/prefix identities reject.
Process-scoped rules and For-a-while leases remain unavailable for a table-only
Windows owner: a Windows PID is not a verified Linux requester generation.

The shipped launcher enables discovery of hash-pinned brokers for its configured
API user. Unsupported builds remain unidentified. Existing `/etc/flowgate/wine.json`
explicit runtime/prefix allowlists remain authoritative when present; these limit
observation, never grant permission. No old Python rule is migrated or broadened.
The permission key is UID + canonical Wine prefix + exact PE executable; file
revision is matched separately. Socket snapshots are not an adversarial guarantee
against a hostile same-user program transferring handles between observations.
Outgoing connected TCP is covered; outgoing unconnected UDP and scoped link-local
interface mapping are not newly supported by this change.

Host deployment and a real user's game retry are separate from this isolated
acceptance. Preparing the release does not activate host protection or alter
stored host rules.

The burst check also exercises ordinary Allow (`scope=once`) before saving the
application rule: exactly one of three payloads arrives and two requests in the
same backend group remain awaiting a decision. The application decision then
settles the remaining requests. This distinguishes display grouping from decision
scope: this test does **not** certify one prompt per application, nor a native
popup journey. A Remember-only receiver pass must not be reported as proof that
ordinary Allow suppresses repeated prompts.

To replace an old explicit Wine-prefix allowlist with supported-build discovery,
run `scripts/update-and-start.sh --profile preserve --wine-discovery`. This is an
explicit host update: it backs up the prior `/etc/flowgate/wine.json`, writes
`{"schema":1,"mode":"discover"}`, installs the matched release, and restores the
previous protection mode. Subsequent ordinary updates retain discovery mode.
No game/prefix list is required; only running brokers of the configured desktop
UID and supported pinned builds are observed. Application/prefix permission keys
stay independent, and no stored rule is broadened or created by this option.
Unsupported Wine/Proton builds still require separate collector support.

Executable artwork uses exact desktop/Steam association first, then a bounded
read-only PE32/PE32+ RT_GROUP_ICON/RT_ICON resource lookup. No executable is loaded
or run to obtain its icon. The reader loads at most 64 KiB of headers and a 16 MiB resource section,
with individual icon frames limited to 1 MiB; unsupported images retain the neutral
fallback. Layout follows Microsoft's PE resource specification:
https://learn.microsoft.com/en-us/windows/win32/debug/pe-format

Anonymous Wine PE mappings are corroborated generically through a currently
mapped, executable `wine-mapping` memfd with matching complete PE headers and
image size. The candidate source must be a regular file with an unchanged inode,
size, mtime and ctime, last modified before the Linux process began. A source
replacement or modification after process creation fails closed. This is the
ordinary same-user snapshot model, not an attestation against malicious memory
or timestamp manipulation. The process name alone never supplies authority.

Executable display names use bounded VERSIONINFO FileDescription strings, with
ProductName as a fallback. They are local-file display metadata, not publisher
verification or permission authority. Keys, revisions, UID and prefix bindings
never derive from these labels. Metadata is cached by exact application identity
and revision; malformed/absent strings retain the normal filename fallback.

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
passes the full real-launcher matrix. GE-Proton11-6 (Wine 11.0) also passes
the two-application/two-prefix receiver matrix. Discovery negotiates the live
schema-2 Wine 10.0 or Wine 11.x census contract instead of checking a broker hash allowlist;
this regression does not claim all Wine/Proton versions work.
Steam, Heroic and UMU use the same broker evidence when running a supported build;
launcher ancestry supplies no permission authority.

Wine 10.0 was additionally validated with GE-Proton10-34 and Steam Runtime 3
using the real launcher matrix for outgoing IPv4 TCP and UDP. SyntheticAlpha and
SyntheticBeta in prefix A and SyntheticAlpha in prefix B have independent keys:
Allow delivers, Deny does not, and a fresh launch observes each remembered rule.
The burst check also verifies ordinary Once allows one payload while the other
two requests remain pending. This does not establish that Once suppresses later
prompts, that IPv6/incoming works on this version, or that a real game passes EAC.
Other 10.x versions remain unsupported until validated. Both schema-2 negotiation
and the existing socket/broker/executable evidence are still required.

Select the matching installed `steamrt3` or `steamrt4` directory through
`FLOWGATE_TEST_UMU_RUNTIME`. The fixture waits at most ten seconds for asynchronous
Activity policy enrichment and retries a transient `unsupported_target` preview;
receiver delivery checks remain separate. It does not prove the UI never exposes
that transient unavailable state.

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

The shipped launcher enables discovery of running brokers for its configured
API user. Unsupported census contracts remain explicitly unidentified. Existing `/etc/flowgate/wine.json`
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

To replace an old explicit Wine-prefix allowlist with runtime discovery,
run `scripts/update-and-start.sh --profile preserve --wine-discovery`. This is an
explicit host update: it backs up the prior `/etc/flowgate/wine.json`, writes
`{"schema":1,"mode":"discover"}`, installs the matched release, and restores the
previous protection mode. Subsequent ordinary updates retain discovery mode.
No game/prefix list is required; only running brokers of the configured desktop
UID are considered; attribution requires a supported live census contract. Application/prefix permission keys
stay independent, and no stored rule is broadened or created by this option.
Other Wine version families still require validation of the collector contract.

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


## Disposable runtime hard links

Pressure-vessel can run native helpers from a fresh `var/tmp-*/usr/...`
hard-linked tree on every launch. FlowGate resolves such a file to a runtime
 deployment's `files/` tree only when device and inode match and the deployment
has its runtime manifest. Candidate discovery is bounded; a filename, manifest
or identical content alone is insufficient. This applies to any executable in
that runtime layout, not a particular interpreter or game.

The application key uses the proven deployment path and UID. Its revision uses
SHA-256 of the opened executable, with bounded hashing and a cache invalidated
by inode/size/mtime/ctime. Creating or removing temporary hard links changes
ctime but no longer changes this application's content revision. Retained
request verification still requires the same backing device/inode and matching
content; modified or substituted files fail. Process rules additionally retain
 the original kernel file stamp and process generation.

Existing rules keyed to temporary paths are not migrated or widened. A new
Remember decision establishes the stable deployment rule; separate directions
remain separate. Python/native helper permissions do not authorize Windows games.

Validation: `TestRuntimeBackingLiveNamespace` runs two real native processes in
separate mount namespaces, with distinct temporary trees backed by one deployment.
`TestRuntimeContentRuleSurvivesTemporaryHardlinkChurn` verifies saved rule reuse
and rejection for another deployment, user or revision. These are native identity
and policy checks, not another end-to-end game receiver test.


## Outgoing UDP owner census

Outgoing UDP uses the same schema-2 Windows owner census as incoming UDP. Its
bound local endpoint identifies candidate Windows holders; the table does not
supply a remote endpoint. The intercepted packet supplies peer/direction policy
scope. Attribution still requires exactly one matching kernel socket, a stable
cookie and broker generation, matching Windows holder sets in two snapshots,
one Windows process generation/image, verified mapped PE revision and prefix.
Shared or absent holders remain unresolved. TCP retains its exact remote and
SYN_SENT/ESTABLISHED requirements. No destination or application exceptions exist.

Run the real isolated launcher matrix with `FLOWGATE_TEST_PROTOCOL=udp` plus the
usual runtime/prefix environment for `scripts/checks/check-proton-launcher.sh`.
It covers IPv4 unconnected sendto, Allow/Deny, subsequent-instance Remember,
two executables and two prefixes, a burst of three distinct sockets, and receiver
control with enforcement removed. UDP Activity-row rule editing is not asserted
by this test; current live row enrichment remains TCP-only. IPv6 row selection
has model checks; this matrix does not prove IPv6 UDP receiver delivery.

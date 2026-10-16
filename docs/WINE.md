# Wine broker association: supported path and observation boundary

## Evidence and supported model

Observed locally: Wine 11.19, `/usr/bin/wineserver`, x86-64 Wine PE fixtures. Matching upstream tag was inspected, not assumed identical to every distribution patch:

- [server/sock.c at wine-11.19](https://github.com/wine-mirror/wine/blob/wine-11.19/server/sock.c): socket objects retain Unix FDs; the server implements creation, bind/listen and accept/async operations. A server descriptor is not necessarily passive bookkeeping.
- [ntdll Unix server.c](https://github.com/wine-mirror/wine/blob/wine-11.19/dlls/ntdll/unix/server.c): `server_get_unix_fd` requests a handle FD, receives it via SCM_RIGHTS and caches eligible descriptors. A Windows handle need not already have a visible client Unix FD.
- [ntdll Unix socket.c](https://github.com/wine-mirror/wine/blob/wine-11.19/dlls/ntdll/unix/socket.c): several operations fall back to server handling; FIONREAD obtains the Unix FD. This explains the observed plain-TCP versus polling-TCP difference.
- [ws2_32 socket.c](https://github.com/wine-mirror/wine/blob/wine-11.19/dlls/ws2_32/socket.c) and [server/handle.c](https://github.com/wine-mirror/wine/blob/wine-11.19/server/handle.c): duplication/inheritance can create additional Windows handle references. WSADuplicateSocket uses handle duplication. Direct WSADuplicateSocket execution is not claimed tested; CreateProcess inheritable handles were tested.

No Wine code was copied into the implementation. Source snapshots for inspection are generated under `.workspace/wine-source`.

The opt-in `FLOWGATE_WINE_BROKER=/usr/bin/wineserver` enables a **non-sharing ordinary-client model**, not an assertion that all possible recipients are known. Acceptance requires exactly one socket, two observed holders, a resolved Windows client image, and a broker whose live executable matches the configured file's device/inode. Both must have the same UID, namespaces and explicit canonical prefix. Reciprocal UNIX_DIAG_PEER evidence must connect their current Unix socket descriptors. This is stronger than name/prefix matching and preserves the entire holder set. The fingerprint includes process start times, executable revisions, socket cookie and broker-channel inodes. Delayed release resolves all evidence again.

Default mode remains conservative. Other versions/runtimes, missing peer/FD evidence, hidden processes and multiple visible clients are not silently accommodated. No trust is granted to every process called wineserver. A name, prefix or Steam ID alone never authorizes traffic.

## Receiver results and limitations

`wine-increment.py` runs alpha and beta concurrently using one runtime/prefix. Both Allow-alpha/Block-beta and Block-alpha/Allow-beta pass for single-send UDP and for TCP listeners that call FIONREAD before accepting. Each remembered permission has the client's own image/revision key. TCP FIONREAD is a labelled fixture behavior, not an injected fix or a claim that arbitrary applications perform it.

`wine-boundary.py` reproduces four distinct states:

1. A plain TCP listener before accept exposes only wineserver's FD. No client can be selected; it remains blocked.
2. Parent alpha and inherited child beta both materialize their Unix FDs: all three holders are reported, traffic is denied, and an earlier pending approval becomes stale.
3. Child beta inherits a Windows handle but waits before touching it. Only alpha and wineserver appear in `/proc`. **The opt-in model cannot see the dormant second recipient.** This is a demonstrated counterexample to treating descriptor holders as the complete recipient set.
4. Alpha exits while beta is dormant: only wineserver holds the Unix FD; attribution denies. After beta materializes the FD, it gains its own association and a different fingerprint.

Thus the supported threat model excludes cross-process dormant handle sharing, arbitrary same-user descriptor manipulation, runtime tampering and external multiplexing proxies. The opt-in mode is useful for ordinary independently owned fixture sockets under those assumptions; it is not reliable transparent enforcement for every Windows application. Default mode does not take this assumption. No game/Proton validation is implied.

## Smallest next step

The missing observation is the mapping from a server socket object to **every live Windows handle reference**, including creation, inheritance, duplication, close and client exit before FD-cache materialization. A syscall hook observing only socket creation or SCM_RIGHTS cannot reconstruct dormant Windows handles. Full Wine-protocol/lifecycle tracking would require matching-version protocol parsing or focused probes and explicit loss handling; a generic eBPF subsystem does not solve that automatically.

The smallest optional alternative is a fresh network namespace and dedicated Wine server instance per opt-in launch, so the namespace can identify a launch even when the only visible descriptor belongs to its broker. A separate prefix (or a disposable prepared prefix copy) may be needed to avoid Wine's shared-server rendezvous; do not silently rewrite existing prefixes or launcher settings. This is proposed, not implemented or required by basic native operation. It does not separate helper processes within that launch or traffic already multiplexed by an external relay. Any implementation should remain explicit and validate receiver behavior before claiming coverage.

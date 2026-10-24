# Service hardening draft (review only, not installed)

Status: **proposal**. Nothing here is shipped, installed or tested on a host.
The installer refuses foreign unit/drop-in content, so this text must become a
reviewed change to `deployment/systemd/flowgate.service` only after the VM
checks below pass. Every option is marked **needs VM test**. The daemon stays
root; `DynamicUser`, `PrivateNetwork`, `ProtectProc`, `ProtectHome` and
`MemoryDenyWriteExecute` are deliberately excluded (see "Why not").

## What the daemon actually needs (from source, HEAD 4e95d34b)

| Need | Evidence | Capability / path |
| --- | --- | --- |
| nftables tables, NFQUEUE 101, conntrack marks | `internal/hostfirewall/firewall.go`, `conntrack.go`, `cmd/flowgate/main.go:343` (`nft`) | `CAP_NET_ADMIN`, `AF_NETLINK` |
| SOCK_DIAG socket census, UNIX_DIAG peers | `internal/identity/socket.go:69-164`, `table.go:478-521` | `CAP_NET_ADMIN`, `AF_NETLINK` |
| `/proc/<pid>/{exe,fd,maps,environ,ns}` of every user, kcmp | `holder_census.go`, `holder_identity.go`, `process.go` | `CAP_SYS_PTRACE`, `CAP_DAC_READ_SEARCH` |
| Run Wine helpers as the broker's UID/GID | `identity/wine_observer.go:356`, `table.go:130`, `wine_namespace.go:159` | `CAP_SETUID`, `CAP_SETGID` |
| Enter a Wine process's mount namespace | `identity/wine_namespace.go:39` (`/usr/bin/nsenter`) | `CAP_SYS_ADMIN`, `CAP_SYS_CHROOT` |
| BPF UDP accounting and TCP sockops helpers, cgroup attach | `internal/udpaccount/session.go:51`, `tcpinit/collector.go:177`, `/sys/fs/cgroup`, `/sys/kernel/btf/vmlinux` | `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_ADMIN` on older kernels |
| Sockets owned by the administrator UID, 0600 | `internal/daemon/api.go:154-163` | `CAP_CHOWN`, `CAP_FOWNER` |
| Detached watchdog, helper `Pdeathsig`, process-group kills | `hostfirewall/embedded.go:577`, `readiness/checks.go:87` | `CAP_KILL` |
| Writable state | `/var/lib/flowgate`, `/run/flowgate-api`, `/run/flowgate-enforcement`, `/run/flowgate-evaluation`, `/run/flowgate` | `ReadWritePaths` |
| Read-only inputs | `/etc/flowgate`, `/usr/local/lib/flowgate/releases/<sha>`, `/proc/sys/kernel/*`, `/sys/fs/cgroup` | default |

## Proposed drop-in (every line needs VM test)

```ini
# deployment/systemd/flowgate.service [Service] additions — DRAFT
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_PTRACE CAP_DAC_READ_SEARCH CAP_DAC_OVERRIDE CAP_SETUID CAP_SETGID CAP_SETPCAP CAP_SYS_ADMIN CAP_SYS_CHROOT CAP_BPF CAP_PERFMON CAP_CHOWN CAP_FOWNER CAP_KILL CAP_SYS_RESOURCE
ProtectSystem=strict
ReadWritePaths=/var/lib/flowgate /run/flowgate-api /run/flowgate-enforcement /run/flowgate-evaluation /run/flowgate
PrivateTmp=yes
ProtectKernelLogs=yes
ProtectClock=yes
ProtectHostname=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictNamespaces=~user
RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6
SystemCallFilter=@system-service @network-io bpf kcmp setns unshare perf_event_open
SystemCallFilter=~@mount @swap @reboot @obsolete
SystemCallErrorNumber=EPERM
```

Per-option notes:

- `CapabilityBoundingSet` **needs VM test**: removes `CAP_SYS_MODULE`,
  `CAP_SYS_RAWIO`, `CAP_SYS_BOOT`, `CAP_MKNOD`, `CAP_AUDIT_*`, `CAP_MAC_*`,
  `CAP_LINUX_IMMUTABLE`, `CAP_NET_BIND_SERVICE`, `CAP_IPC_LOCK`, `CAP_SYS_TIME`.
  Risk: nft module autoload is kernel-side and does not need `CAP_SYS_MODULE`,
  but this must be shown on a VM with `nfnetlink_queue` unloaded at boot.
  `CAP_SYS_ADMIN` stays because of `nsenter` and older-kernel BPF attach.
- `ProtectSystem=strict` **needs VM test**: `/usr`, `/etc`, `/boot` read-only.
  The installer runs outside the unit, so release directories are unaffected.
  Verify that nothing writes under `/etc/flowgate` from the daemon (`zones.json`
  and `administrator.json` are read by `deployment/launch`).
- `ReadWritePaths` **needs VM test**: confirm `/run/flowgate` and
  `/run/flowgate-evaluation` are the only other runtime writers (`cmd/flowgate`
  string table above). Missing paths are created by `monitor-setup`
  (`ExecStartPre`), which runs under the same sandbox, so `RuntimeDirectory=`
  is **not** used here to avoid changing ownership semantics.
- `PrivateTmp` **needs VM test**: the Wine observer runs under the user's
  prefix via `nsenter`, not `/tmp`; verify no helper hands a `/tmp` path to a
  user process.
- `RestrictNamespaces=~user` **needs VM test**: blocks creating user namespaces
  only; `setns` into existing mount namespaces for Wine stays allowed. The lab
  (`scripts/lab.sh`) uses `unshare`, but it never runs under this unit.
- `RestrictAddressFamilies` **needs VM test**: the daemon opens `AF_NETLINK`
  (sock_diag, nfqueue, conntrack, rtnetlink), `AF_UNIX` (API, peers) and
  `AF_INET/6` (self-connect update, probes). `AF_PACKET` is not used.
- `SystemCallFilter` **needs VM test** with `strace -f -c` on a full receiver
  run including Wine helper, UDP and TCP collectors. Compatibility of `setns`
  with the `~@mount` denial is **unverified**: systemd's `@mount` group may
  include `setns` on the target version, and a later deny line wins over an
  earlier allow. Check `systemd-analyze syscall-filter @mount` on the VM first;
  if `setns` is listed, drop `~@mount` rather than assume. If the Wine helper
  needs more, widen with evidence, not by removing the filter.
- `ReadWritePaths` **needs VM test** for ordering too: the paths must exist
  before the sandbox is set up or the unit fails to start. `monitor-setup`
  creates them from inside the unit, so a first boot on a clean host may need
  `RuntimeDirectory=`/`StateDirectory=` or a tmpfiles entry instead; that
  changes ownership/mode semantics and is not decided here.

## Why not

- `DynamicUser`, `User=`: the daemon must read every user's `/proc` and run
  helpers as other UIDs. Not applicable.
- `ProtectHome=read-only|yes`: Wine prefixes, Steam libraries and Flatpak app
  data live under `/home`; the observer must execute user binaries there.
- `ProtectProc=invisible`: hides other users' processes, which is the whole
  attribution model.
- `MemoryDenyWriteExecute`: Wine needs writable+executable mappings in the
  observer helper, which is a child of this unit.
- `SystemCallArchitectures=native`: 32-bit Wine prefixes issue x86 syscalls.
- `PrivateNetwork`, `PrivateDevices`, `ProtectKernelTunables=yes`:
  interception and `/proc/sys/kernel/unprivileged_bpf_disabled` reads need the
  host namespace; tunables are only read, so `ProtectKernelTunables` *may* be
  acceptable, but it also makes `/sys/fs/cgroup` read-only in some systemd
  versions and is therefore left out of the first draft.
- `NoNewPrivileges=yes`: safe for the Go daemon, but it is inherited by the
  Wine observer and breaks any setuid helper in a prefix (for example
  `wine`-bundled `ping`). Revisit once the helper's needs are measured.

## Acceptance plan (VM only)

1. Boot the capped guest with the drop-in, `nfnetlink_queue` unloaded, guard
   enabled. Expect: guard installed, daemon READY, `systemctl show` reports the
   restricted bounding set.
2. Run the isolated incoming/outgoing receiver suites, the UDP collector and the
   TCP initiation collector. Expect: identical results to the unhardened run.
3. Run the Wine two-app/two-prefix matrix. Expect: table census, broker peering
   and prefix separation unchanged; no `EPERM` in the journal.
4. Kill the daemon during active protection. Expect: fail-closed table retained,
   restart succeeds under the same sandbox, recovery path still works.
5. Record `systemd-analyze security flowgate.service` before and after. The
   score is informational; the receiver results are the acceptance evidence.

Related backlog from the audit, not part of this draft: signed release
bundles (currently SHA256 self-consistency only) and administrator-mandatory
policy semantics (a user Priority can outrank an administrator Deny at equal
weight; `internal/policy/precedence.go`).

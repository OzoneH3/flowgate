# Standalone FlowGate release candidate

The source build uses GNU Make. Installation uses an exact offline archive. The daemon, desktop, helpers, upgrade and rescue tools run without the source checkout. The initial release candidate targets Linux x86_64 with systemd. It uses the Electron desktop, including the existing Plasma Wayland integrations. The Qt client and lab tools are outside the package.

Build prerequisites are Go and a C toolchain, Clang with BPF support, bpftool, libbpf, libmnl and libnftnl development files, a kernel BTF file, Wine development headers and import libraries, Node and the Electron dependencies in the lockfile. The installed host needs systemd, iproute2, nftables, runuser, the dynamically linked system libraries and the kernel features checked by FlowGate. BPF, traffic collector and Wine features still depend on their individual runtime checks.

Both the build machine and the installation host need Python 3.9 or newer
and `/usr/bin/sha256sum` (from coreutils). The host's system Python must
provide `os.pidfd_open` and `signal.pidfd_send_signal` for safe desktop
shutdown during upgrades.
Preflight checks for an executable `runuser` in the system's standard
binary directories before staging an installation.

On hosts with AppArmor's unprivileged user-namespace restriction enabled,
standalone installation requires the system `apparmor_parser`. It loads and
persists `/etc/apparmor.d/flowgate-standalone-electron`, which permits user
namespaces only for Electron in FlowGate's managed versioned desktop tree.
Chromium sandboxing and the host's AppArmor settings stay enabled. The one
profile covers upgrades and retained rollback versions. The standalone
uninstaller unloads and removes the unmodified managed profile. After rolling
back to a release that predates this support, use the newer offline
`flowgate-release.py uninstall` to include profile cleanup.

On stock Fedora 45 with SELinux enforcing, the root daemon starts through
`/usr/bin/env`. The stock policy transitions it to `unconfined_service_t`, which
permits its subprocess probes and UDP collector. Monitor setup and both
protection-guard commands run directly in the stock `init_t` context. The
installer leaves host policy and enforcing mode intact. FlowGate ships no
dedicated SELinux confinement policy. Preflight reports the command behavior
on SELinux hosts. Other policies can assign different domains.

The package target installs the pinned Electron runtime when needed, builds the
desktop and native components, and runs the release checks.

```sh
make package
```

Build from a clean committed revision. The build and package targets write to build/. The archive and the offline bootstrap land in build/dist. Copy them to a convenient location. Distribute their SHA256 digests through the trusted release channel. Check the bootstrap itself against the trusted digest before executing it as root. The archive SHA256 is an argument and the bootstrap verifies privately staged bytes before parsing the payload or running any packaged code.

To build and upgrade the installed daemon and desktop on this machine in one command:

```sh
make update
```

This builds the current committed checkout in build/, verifies the archive against its checksum receipt, then runs preflight and install in order. Run it as the intended desktop user. Preflight and install invoke sudo. From a desktop terminal, the command closes any running installed GUI and opens the version matching the new daemon, including when the GUI was already closed. A shell without a display completes the installation and leaves desktop launch for your next graphical session.

```sh
make preflight BUNDLE=/absolute/path/to/flowgate.tar.gz SHA256=<trusted-sha256>
make install BUNDLE=/absolute/path/to/flowgate.tar.gz SHA256=<trusted-sha256>
```

Use actual digest text in place of the placeholder. On a computer without a checkout, use the verified bootstrap from the archive's output directory in the same way.

```sh
sudo /usr/bin/python3 -I ./flowgate-release.py preflight --bundle ./flowgate.tar.gz --sha256 <trusted-sha256>
sudo /usr/bin/python3 -I ./flowgate-release.py install --bundle ./flowgate.tar.gz --sha256 <trusted-sha256>
```

Invoke fresh installation with sudo from the intended desktop administrator's account. Fresh installation starts monitoring. Upgrades authenticate and verify the candidate, check existing policy schema, preserve configuration, snapshot the stopped writer's state, and verify monitoring before restoring the previously active mode. A retained shaping journal or configured shaping requires a verified transition before upgrade. Installation preserves the disabled host-trial interface of a legacy installation when one is reported and verified.

### Fedora 45 recovery from the RC8 collector failure

On Fedora 45, build `7b3e8e51` can report a failed UDP collector and refuse an
in-place update with `Current collector is not settled`. Collector Stop reports
`disabled`, which these RC8 installers also reject. Monitoring recovery restarts
the old daemon and its collector in the same service context.

To move from `7b3e8e51` to `64a07da1`, use the non-purge uninstall and then
install the verified replacement. This preserves the saved rules database at
`/var/lib/flowgate/rules.db`. Use the enrolled desktop administrator's account.
Obtain the archive, offline installer, and receipts for the replacement, and
check the SHA-256 values against the trusted release channel before removing
the old installation.

```sh
bundle=flowgate-0.1.0-rc.8-linux-x86_64.tar.gz
/usr/bin/sha256sum -c "$bundle.sha256" flowgate-release.py.sha256 &&
digest=$(cut -d ' ' -f 1 "$bundle.sha256") &&
sudo /usr/local/sbin/flowgate-uninstall &&
sudo test -s /var/lib/flowgate/rules.db &&
sudo /usr/bin/python3 -I -B ./flowgate-release.py preflight --bundle "$bundle" --sha256 "$digest" &&
sudo /usr/bin/python3 -I -B ./flowgate-release.py install --bundle "$bundle" --sha256 "$digest" &&
flowgate-control status
```

Omit `--purge` to retain the database. Protection stays off during removal and
reinstallation. After verifying the active collector and the saved rules in
the Rules view, re-enable the appropriate protection mode and reapply any
automatic desktop launch preference. This path
removes the registered predecessor, so the new installation has no
`flowgate-recover --rollback` target.

Launch the new UI from the application menu or with flowgate-ui. Close any older desktop session copy before launching it. The installed GUI stores preferences in XDG_CONFIG_HOME/flowgate and transient state in XDG_RUNTIME_DIR/flowgate. The installer updates the enrolled user's managed login entry while preserving its opt-out flags. It saves the original entry for migration rollback. It does not enable an absent login entry. For a non-default config root pass --desktop-config during install. For a legacy preference import, compare the saved files from the old GUI releases and pass --import-preferences with the selected absolute path using INSTALL_FLAGS. The import refuses to overwrite different installed preferences.

```sh
make desktop DESKTOP_FLAGS='--enable-autostart'
make desktop DESKTOP_FLAGS='--import-preferences /absolute/path/to/electron-preferences.json'
```

If installation fails after cutover, it tries to restore the verified previous build and its database in monitoring. The independently installed rescue entry point can remove owned interception even when the API, desktop or selected release pointer is broken. Consult the local report when it refuses an ownership mismatch.

```sh
make recover
make recover RECOVER_FLAGS=--stop-only
make recover RECOVER_FLAGS=--rollback
make uninstall
make uninstall UNINSTALL_FLAGS=--purge
```

Without Make, run sudo /usr/local/sbin/flowgate-recover or sudo /usr/local/sbin/flowgate-uninstall with the same options. If the normal recovery wrapper is missing during a partial install, use sudo /usr/local/libexec/flowgate/rescue. Recovery persists monitoring and verifies interception cleanup. Explicit rollback switches to the previous compatible executable using the latest rules and settings. It checks the state contract and rule schema before stopping protection. If a predecessor is incompatible or has no compatibility declaration, rollback refuses. An interrupted installation uses its own transaction snapshot. An older archive is a separate recovery decision because restoring it can discard later edits. If the current executable is damaged, use local rescue to remove interception. Inspect the kept backup and reinstall a verified compatible package before selecting a different build.

Uninstall stops the managed daemon and desktop, verifies cleanup, and removes managed units and the registered login and application entries. The normal operation preserves policy, preferences and recovery data. The purge option removes the system configuration and machine state after verified cleanup. It leaves per-user preferences with the user. Legacy development releases and the optional old passwordless update configuration require separate ownership review. Keep their copies until a standalone migration has been verified.

Review the host with preflight before scheduling a migration. Validate the exact archive and complete lifecycle in a guest before release approval.

# Standalone FlowGate release candidate

The source build uses GNU Make. Installation uses an exact offline archive. The daemon, desktop, helpers, upgrade and rescue tools run without the source checkout or .workspace. The initial release candidate targets Linux x86_64 with systemd. It uses the Electron desktop, including the existing Plasma Wayland integrations. The Qt client and lab tools are outside the package.

Build prerequisites are Go and a C toolchain, Clang with BPF support, bpftool, libbpf, libmnl and libnftnl development files, a kernel BTF file, Wine development headers and import libraries, Python 3, Node and the Electron dependencies in the lockfile. The installed host needs systemd, Python 3, iproute2, nftables, runuser, the dynamically linked system libraries and the kernel features checked by FlowGate. BPF, traffic collector and Wine features still depend on their individual runtime checks.

The package target installs the pinned Electron runtime when needed, builds the
desktop and native components, and runs the release checks.

```sh
make package VERSION=0.1.0-rc.1
```

Build from a clean committed revision. The build and package targets write to .workspace. The archive and the offline bootstrap land in .workspace/dist. Copy them to a convenient location. Distribute their SHA256 digests through the trusted release channel. Check the bootstrap itself against the trusted digest before executing it as root. The archive SHA256 is an argument and the bootstrap verifies privately staged bytes before parsing the payload or running any packaged code.

To build and upgrade the installed daemon and desktop on this machine in one command, use a new release version:

```sh
make update VERSION=0.1.0-rc.7
```

This packages the current commit, verifies the archive against its checksum receipt, then runs preflight and install in order. Run it as the intended desktop user. Preflight and install invoke sudo. Close any older desktop window and launch `flowgate-ui` after the update.

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

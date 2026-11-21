# Standalone FlowGate releases

The source build uses GNU Make. Installation uses an exact offline archive. The daemon, desktop, helpers, upgrade and rescue tools run without the source checkout. The initial release candidate targets Linux x86_64 with systemd. It uses the Electron desktop, including the existing Plasma Wayland integrations. The Qt client and lab tools are outside the package.

## Requirements

Build from a clean Git checkout with GNU Make, Go 1.24 or newer, a C toolchain,
Clang with BPF support, LLD, pkg-config, bpftool and readable kernel BTF at
`/sys/kernel/btf/vmlinux`. Install the libbpf, libmnl and libnftnl development
files. The Windows observer build expects Wine headers under `/usr/include/wine`
and import libraries under `/usr/lib/wine/x86_64-windows`. The first build needs
Node ≥22.12, npm and network access for the locked dependencies, Electron runtime
and Go modules.

The installation host needs systemd, sudo, iproute2, nftables, runuser and the
dynamically linked daemon and desktop libraries. The graphical session must
support Electron's sandbox. FlowGate checks kernel and runtime capabilities
for BPF, traffic collection and Wine individually.

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

## Install or update from source

As the intended desktop administrator, run this command from a clean checkout of the desired revision.

```sh
make update
```

Make builds the current checkout, checks the archive against its local receipt,
then runs preflight and install with sudo. In a graphical session it reloads
the installed desktop, starting it even if it was closed. From a headless shell,
launch `flowgate-ui` at the next graphical login. For an upgrade, obtain the
desired source revision before invoking Make. Install refuses a release ID
already installed (same version and source revision).

## Build and inspect a package

Run these commands in a clean Git checkout with the FlowGate tags available.

```sh
make package
bundle="$(make -s archive-path)"
(cd "$(dirname "$bundle")" && /usr/bin/sha256sum -c "$(basename "$bundle").sha256" flowgate-release.py.sha256)
make identity
```

An exact `flowgate-vX.Y.Z-rc.N` or `flowgate-vX.Y.Z` tag supplies the displayed
version. An untagged commit uses the most recent FlowGate tag on its
first-parent history, or the Electron package's numeric baseline before the
first release tag. It has a development version such as
`0.1.0-rc.8.dev-0123456789ab` or `0.1.0-dev-0123456789ab`. Ordinary commits
derive a fresh identity from their Git SHA. A source tarball without Git
metadata is refused. Clone the repository, fetch its tags and check out the
intended commit, or install the verified binary package.

The archive is `build/dist/<release-id>/flowgate-<release-id>-linux-x86_64.tar.gz`.
A tagged release ID appends the first 12 characters of the source SHA to the
version. A development version already contains those characters and doubles
as its release ID. The manifest records the complete source SHA. Each output
directory contains its own installer and both byte-for-byte SHA-256 receipts.
Rebuilding an identity verifies and reuses its existing package. Existing
packages stored elsewhere keep their original names and receipts.

### Prepare an RC or stable release

Choose a clean, reviewed commit, then prepare the next candidate locally.

```sh
git tag -a flowgate-v0.1.0-rc.9 -m 'FlowGate 0.1.0-rc.9'
make package
```

For the stable release, check out its reviewed commit and run:

```sh
git tag -a flowgate-v0.1.0 -m 'FlowGate 0.1.0'
make package
```

Use a single FlowGate release tag per commit. When promoting an already tagged
candidate, make a separate stable release commit before tagging. These commands
create local tags and local packages. `VERSION` and `ARTIFACT` overrides are
replaced by the tag or commit and `make -s archive-path`.

### Inspect or install the selected build

```sh
(
  set -eu
  bundle="$(make -s archive-path)"
  digest=$(cut -d ' ' -f 1 "$bundle.sha256")
  make preflight BUNDLE="$bundle" SHA256="$digest"
  make install BUNDLE="$bundle" SHA256="$digest"
)
/usr/local/lib/flowgate/current/flowgate version
readlink -f /usr/local/lib/flowgate/current
```

The installer uses the privately verified archive and the release ID becomes
the directory under `/usr/local/lib/flowgate/releases/`. Help → About shows
the verified desktop manifest's version and source. It also shows the linked
daemon's version and source when supplied by that daemon. Older binaries that
predate the version field still report their source SHA. The installer and
rollback output identify the selected package, including legacy RC8 releases.

## Install a downloaded package offline

Copy all four assets into one directory. Obtain the archive filename and the
**archive and installer SHA-256 values** from the trusted release record.
In that directory, set `BUNDLE` to the published archive basename,
`ARCHIVE_SHA256` and `INSTALLER_SHA256` to the corresponding hex digests.
Run the block as the intended desktop administrator. It verifies both files
before invoking the downloaded installer as root.

```sh
(
  set -eu
  : "${BUNDLE:?Set the release archive filename}"
  : "${ARCHIVE_SHA256:?Set the trusted archive digest}"
  : "${INSTALLER_SHA256:?Set the trusted installer digest}"
  /usr/bin/sha256sum -c "$BUNDLE.sha256" flowgate-release.py.sha256
  printf '%s  %s\n' "$ARCHIVE_SHA256" "$BUNDLE" "$INSTALLER_SHA256" flowgate-release.py | /usr/bin/sha256sum -c -
  sudo /usr/bin/python3 -I -B ./flowgate-release.py preflight --bundle "./$BUNDLE" --sha256 "$ARCHIVE_SHA256"
  sudo /usr/bin/python3 -I -B ./flowgate-release.py install --bundle "./$BUNDLE" --sha256 "$ARCHIVE_SHA256"
)
```

The receipts check each file against its accompanying checksum. The trusted digests
identify the approved bytes. The installer checks a private copy of the archive
before parsing its manifest or executing packaged code.

Fresh installation starts monitoring. Upgrades authenticate and verify the candidate, check existing policy schema, preserve configuration, snapshot the stopped writer's state, and verify monitoring before restoring the previously active mode. A retained shaping journal or configured shaping requires a verified transition before upgrade. Installation preserves the disabled host-trial interface of a legacy installation when one is reported and verified.

### Debian upgrade with `/run` mounted `noexec`

The managed RC8 predecessor `13e3029a` can report `permission_required`
when starting its UDP collector from `/run/flowgate-api`. Run the verified
replacement's offline `preflight` and `install` commands above with the
existing service running and `/run` mounted as usual. Preflight verifies the
known predecessor, the failed helper's checksum, and the mount's `noexec`
flag. The replacement requires an active collector before restoring the
previous protection mode.

If you run `flowgate-recover --rollback` back to that predecessor, the
installation returns to monitoring with the latest saved rules and settings.
The predecessor's UDP collector fails again on the stock mount, and recovery
reports that limitation. Use the usual protection controls to reactivate
interception if needed.

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
the old installation. The following command uses the replacement digests from
the [Fedora upgrade regression](../scripts/acceptance/fedora-collector-upgrade/run.py).

```sh
bundle=flowgate-0.1.0-rc.8-linux-x86_64.tar.gz
digest=55f522e7f12f87f91bbcc5ab7c170c846abeed3f26ee8975b9b579b5b0fb01af
installer_digest=94a2956bf3477875aa63eafc3f2abd555160837d220f8449b3dfe3cbc349124c
/usr/bin/sha256sum -c "$bundle.sha256" flowgate-release.py.sha256 &&
printf '%s  %s\n' "$digest" "$bundle" "$installer_digest" flowgate-release.py | /usr/bin/sha256sum -c - &&
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

## Desktop preferences

Launch the new UI from the application menu or with `flowgate-ui`. Close any older desktop session copy before launching it. The installed GUI stores preferences in XDG_CONFIG_HOME/flowgate and transient state in XDG_RUNTIME_DIR/flowgate. The installer updates the enrolled user's managed login entry while preserving its opt-out flags. It saves the original entry for migration rollback. It does not enable an absent login entry. For a non-default config root pass --desktop-config during install. For a legacy preference import, compare the saved files from the old GUI releases and pass --import-preferences with the selected absolute path using INSTALL_FLAGS. The import refuses to overwrite different installed preferences.

```sh
make desktop DESKTOP_FLAGS='--enable-autostart'
make desktop DESKTOP_FLAGS='--import-preferences /absolute/path/to/electron-preferences.json'
```

## Recovery and removal

If installation fails after cutover, it tries to restore the verified previous build and its database in monitoring. The independently installed rescue entry point can remove owned interception even when the API, desktop or selected release pointer is broken. Consult the local report when it refuses an ownership mismatch.

| Desired outcome | Command |
| --- | --- |
| Restore monitoring | `make recover` |
| Stop FlowGate and clear owned interception | `make recover RECOVER_FLAGS=--stop-only` |
| Return to a compatible predecessor | `make recover RECOVER_FLAGS=--rollback` |
| Remove the installation and retain data | `make uninstall` |
| Also purge system configuration and state, keeping per-user preferences | `make uninstall UNINSTALL_FLAGS=--purge` |

Without Make, run sudo /usr/local/sbin/flowgate-recover or sudo /usr/local/sbin/flowgate-uninstall with the same options. If the normal recovery wrapper is missing during a partial install, use sudo /usr/local/libexec/flowgate/rescue. Recovery persists monitoring and verifies interception cleanup. Explicit rollback switches to the previous compatible executable using the latest rules and settings. It checks the state contract and rule schema before stopping protection. If a predecessor is incompatible or has no compatibility declaration, rollback refuses. An interrupted installation uses its own transaction snapshot. An older archive is a separate recovery decision because restoring it can discard later edits. If the current executable is damaged, use local rescue to remove interception. Inspect the kept backup and reinstall a verified compatible package before selecting a different build.

Uninstall stops the managed daemon and desktop, verifies cleanup, and removes managed units and the registered login and application entries. The normal operation preserves policy, preferences and recovery data. The purge option removes the system configuration and machine state after verified cleanup. It leaves per-user preferences with the user. Legacy development releases and the optional old passwordless update configuration require separate ownership review. Keep their copies until a standalone migration has been verified.

## Maintainer release handoff

1. Build from the clean checkout of the chosen local release tag using
   `make package`. Retain all four files. Record `git rev-parse HEAD` and both
   digests. In the asset directory, set `BUNDLE` to the archive basename.
   Check both receipts and use `tar -xOzf "$BUNDLE" release.json`
   to match the manifest's full `source` and `version` to the intended release.
2. Supply that archive, installer and both recorded digests to the external
   `flowgate-lab/lab.py run` command using `--profile`, `--archive`,
   `--archive-sha256`, `--installer` and `--installer-sha256`. Match the
   passing guest result's installed source and executable digest to the
   manifest and both artifact digests to the build record. Record fresh install,
   upgrade and rollback results on disposable guests before approving those
   lifecycle paths. With `LAB` set to the runner checkout and the recorded
   digests in `ARCHIVE_SHA256` and `INSTALLER_SHA256`, a Debian run is:

   ```sh
   python3 -B "$LAB/lab.py" run --profile "$LAB/profiles/debian-13.json" \
     --archive "$PWD/$BUNDLE" --archive-sha256 "$ARCHIVE_SHA256" \
     --installer "$PWD/flowgate-release.py" --installer-sha256 "$INSTALLER_SHA256"
   ```
3. Publication to GitHub Releases is manual. After guest approval, verify the
   release tag resolves to the tested commit, attach the **retained four files**
   to a draft and put the source SHA and both digests in the release notes.
   Download and compare the draft assets to the originals before publishing.
   Recreating a package in a fresh checkout can change the archive digest even
   at the same commit and version. Use the tested, retained files.
   With `TAG` set to the verified remote tag and `NOTES` to the release notes
   file, run these commands from the retained asset directory:

   ```sh
   (
     set -eu
     repo=OzoneH3/flowgate
     case "$TAG" in *-rc.*) set -- --prerelease ;; *) set -- ;; esac
     gh release create "$TAG" --repo "$repo" --verify-tag --draft "$@" \
       --title "FlowGate ${TAG#flowgate-v}" --notes-file "$NOTES" \
       "$BUNDLE" "$BUNDLE.sha256" flowgate-release.py flowgate-release.py.sha256
     downloaded=$(mktemp -d ./draft-assets.XXXXXX)
     gh release download "$TAG" --repo "$repo" --dir "$downloaded"
     for asset in "$BUNDLE" "$BUNDLE.sha256" flowgate-release.py flowgate-release.py.sha256; do
       cmp "$asset" "$downloaded/$asset"
     done
   )
   ```

   After all four comparisons succeed, publish the verified draft with
   `gh release edit "$TAG" --repo OzoneH3/flowgate --draft=false`.

## Verification record

The public-clone audit at `7511ac1764c8a922c1ad259747338973adf197f2` ran
the read-only preview, built RC7 and RC8, passed the 24 standalone checks for
each, and verified both receipts, the archive contents and packaged daemon
identity. The exact RC8 archive was subsequently installed for the headless
and desktop scenarios in the [compatibility record](COMPATIBILITY.md#rc8-and-subsequent-checks).
The documented Debian upgrade and rollback used a separate build. Guest
lifecycle coverage for the exact audited RC7 and RC8 archives is still
incomplete.

| Version | Audited archive SHA-256 |
| --- | --- |
| 0.1.0-rc.7 (historical) | `0358a862f84aa60db55cbf5803a24984e9d736eda81979a37228c24bef37b9ae` |
| 0.1.0-rc.8 (historical) | `112995add59425a674ce7f25e9af220f5e96188e39d08f64aa7044cfcd33041d` |

Both builds produced installer SHA-256
`94a2956bf3477875aa63eafc3f2abd555160837d220f8449b3dfe3cbc349124c`.
The public repository advertised no tags or published releases at the time of
the audit. Earlier RC8 guest results refer to their own source and digests.

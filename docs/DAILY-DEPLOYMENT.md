# Deployment and release preparation

For a standalone installation from your current checkout, use `make update`.
See the [standalone release guide](STANDALONE-RELEASE.md) for that workflow.
The commands below are for the pinned checkout updater.

```sh
scripts/prepare-release.sh                 # matched backend and Electron
scripts/prepare-release.sh --backend-only  # backend only
scripts/update-and-start.sh --update --dry-run  # preview the pinned update
scripts/update-and-start.sh --update           # install prepared pinned bundles
```

Running the script with no arguments opens the installed GUI. For an update,
the default profile restores the live mode observed during update. Fresh installs stay
monitoring. Explicit `--profile both --acknowledge-outgoing-blocking` acknowledges
that DNS/DHCP/VPN may be blocked and continuous protection has no automatic
countdown. No essential service permission is added by an update. If the GUI/API
is unavailable, root-local recovery is `sudo /usr/local/sbin/flowgate-recover`.

To start the desktop user's GUI automatically at login, use:

```sh
scripts/update-and-start.sh --update --local --profile preserve --autostart
```

After the matched GUI reports it loaded, this writes the current user's
`$XDG_CONFIG_HOME/autostart/flowgate.desktop` (normally
`~/.config/autostart/flowgate.desktop`). It launches the GUI in its existing tray
mode using the new login's desktop environment. It does not start protection or
change permissions. Future GUI updates refresh this managed entry to the matched
release; disabling it in desktop settings is preserved unless `--autostart` is
explicitly used again. An unrelated existing entry is never overwritten. Remove
the entry or disable it in desktop startup settings to stop login startup.
The release directory must remain available at login.

Upstream updates are noninteractive and have a 60-second timeout (with up to five
seconds for forced cleanup). Failure stops before preparation, authentication or
protection changes. Use `scripts/update-and-start.sh --update --local` to skip
upstream access. It still requires a clean `master` and the prepared bundles for
the exact revision in [deployment/default-release](../deployment/default-release).
The updater installs that pinned revision. Interrupting the fetch leaves the
installed daemon running.

Preparation requires clean master, builds collectors from current source, and
records current race/vet evidence. It never installs or activates protection.
Preparation builds the checked-out commit. Use the pinned commit when preparing
bundles for the updater. It expects a backend manifest in
`build/daily-releases/<revision>/` and a matched manifest in
`build/automatic-zone-releases/<revision>/`. Existing bundles are hash-checked
before reuse. The old installer that combined installation with host acceptance
is retired and no longer shipped.

For a deliberate monitoring-only install use
`python3 scripts/install-prepared.py --bundle PATH`. It snapshots selected bytes
before authentication and uses isolated system Python with root-owned staging.
It refuses active protection or foreign units, quiesces the old writer, backs up
state, and verifies the new build in monitoring. Startup migrations are checked
against exact allowed rule transitions. If replacement fails, a verified previous
release and its matching database snapshots are restored together. Only a verified
rollback allows the updater to restore the previously active protection mode.
A failed rollback leaves explicit recovery instructions and retained evidence.

See [scripts/README.md](../scripts/README.md) for current command options, trust,
rollback limits, and test coverage. Monitoring/rollback tests exercise real SQLite
and files with mocked service/API boundaries. They do not claim a live host
rollback or reboot test. Live acceptance remains a separate explicit action.

Earlier implementation/incident notes are retained in
[DAILY-DEPLOYMENT-HISTORY.md](DAILY-DEPLOYMENT-HISTORY.md).

## Passwordless local updates

The checkout updater normally uses sudo. To authorize the current desktop
account to install local builds without an interactive password prompt, run
this once from a trusted checkout.

```sh
sudo /usr/bin/python3 -I scripts/setup-passwordless-update.py
```

This grants that account the ability to install local code that runs as root.
The root-owned helper restricts commands to supported updater operations.
Use trusted local source and builds. Bundle hashes check consistency, and the
updater verifies the bundle and checks compatibility before stopping protection.
The standalone `make update` workflow invokes sudo directly.

Remove the authorization and helper to return the checkout updater to ordinary
sudo.

```sh
sudo rm /etc/sudoers.d/flowgate-local-update /usr/local/libexec/flowgate-update-helper
```

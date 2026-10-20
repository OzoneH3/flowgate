# Applications on a shared Electron runtime

A system Electron runtime (`/usr/bin/electron`, `/usr/lib/electron43/electron`, any
`electron[0-9]*`) runs many applications; the executable alone never identifies one.
Heroic Games Launcher, for example, runs as `electron43 /usr/lib/heroic-games-launcher/app.asar`,
and its sockets belong to the runtime's `--type=utility` network-service process.

## Identification (`internal/identity/electron.go`)

`Inspect` resolves every process of a runtime named like that (`ResolveElectronApp`):

1. From the socket owner up the parent chain (at most 6 steps) to the process without
   `--type=` (the Electron main process). Every step must run the same runtime file, belong to
   the same UID and mount namespace. Chromium's space-joined argv is split only when its first
   token is exactly the process's executable path.
2. The main process must not run in Node mode (`ELECTRON_RUN_AS_NODE`) or with inspector,
   remote-debugging, `--require` or `--js-flags` options (other code could run inside it).
3. Its first non-option argument is the bundle, resolved in the main process's own mount
   namespace and cwd: an `.asar` archive or an app directory with `package.json` (`name`
   required). An `.asar` `package.json` must match the archive's SHA-256 integrity when given.
4. Every PID of the chain is re-read at the end: same start time and runtime, so a reused PID
   can never attach a process to the wrong app.

Verified: `application.kind = "electron"`, `executable` = the bundle, `runtime` = the runtime,
`revision` = the bundle's file stamp, `hosted` = the evidence (chain with PIDs/start ticks,
package, integrity). The rule key is `uid + electron + bundle path`: Allow Heroic never allows
other programs run by the same runtime. Applications that ship their own (renamed) Electron
binary keep their ordinary executable identity.

Unverified (chain broken or gone, missing/ambiguous bundle, unsafe options, integrity
mismatch): the process keeps the runtime identity (`kind = "native"`, the runtime's key, so
existing rules on the runtime still match it) with `hosted.state = "unverified"` and a reason.
No application-wide rule can be created for it: Remember previews, legacy Remember decisions,
rule-editor bases, Activity quick rules and future rules from ended requests are refused with
`identity_unverifiable` (`identity.RuntimeRuleBlocked`). Once and For a while (process-scoped)
stay available. `permission_target.kind = "runtime-unverified"`.

Existing rules keyed on a runtime executable keep matching unverified processes of it, but no
longer match processes verified as a specific Electron app (those have the bundle's key).

## Presentation (`electron/src`)

The permission window shows the app (e.g. **Heroic Games Launcher**, `socket owner electron`)
and, in Details › Electron app, the state, runtime, bundle, package, integrity, chain and
reason. Unverified: `electron` with `application unverified`; Remember is disabled with the
backend's reason. The desktop name and icon come from the desktop entry whose launcher script
names exactly that bundle (`/usr/bin/heroic`), or else a unique `StartupWMClass` equal to the
package name — display only, never identity.

## Launched by (general reverse chain)

Every socket owner's provenance records its start-time-verified ancestry
(`provenance.ancestry`). `provenance.parent` names the nearest ancestor that is another
program: same UID (an ancestor of another user ends the search), not the owner's own
executable, and not session, shell, terminal or sandbox infrastructure (systemd, shells,
sudo, bwrap, Plasma/KWin, portals, tmux, Konsole, …). An Electron runtime ancestor is named by
the app it verifiably runs (`parent.application`, kind `electron`). Example: Heroic's
`nile` (its own binary in `app.asar.unpacked`) reads **nile · launched by Heroic Games
Launcher**; Details › Launch › Launched by shows PID, start ticks and depth. Display only —
rules for nile bind nile's own executable, never Heroic. A verified game launch (Proton/umu)
keeps the game as the context instead.

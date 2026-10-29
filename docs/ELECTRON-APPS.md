# Applications on a shared Electron runtime

A system Electron runtime (`/usr/bin/electron`, `/usr/lib/electron43/electron`, any
`electron[0-9]*`) runs many applications; the executable alone never identifies one.
Heroic Games Launcher, for example, runs as `electron43 /usr/lib/heroic-games-launcher/app.asar`,
and its sockets belong to the runtime's `--type=utility` network-service process.

## Identity and permission scope

Bundle arguments, package metadata and parent chains are display evidence, not
proof that the bundle is executing. Since `de2c90b4`, FlowGate does not create or
match application-wide permissions from these hints, including legacy entries
labelled verified. The prompt keeps “application unverified”.

Remember can instead bind the exact verified native socket-owning process. The
backend requires complete single-owner visibility, executable identity and stamp,
UID, boot/start identity, namespaces and a thread-group leader; a pidfd pins the
process lifetime. The Process checkbox is mandatory for this case. Rules retain
direction and selected protocol/peer constraints. They stop matching on exit,
identity change or daemon restart, even when the saved rule has no expiry. Another
process, child, sibling or relaunch is not covered. Existing application rules are
not converted, and no Allow is created without a user decision.

For a while similarly covers only the verified native process for the selected
duration. Unknown, worker-only, merged-owner and legacy bundle identity evidence
remains unavailable. Old backends do not advertise the new `process-remember`
scope offer, so the UI keeps Remember disabled with them. Ended unverified-runtime
requests do not offer remembered application rules; use a current request.

## Presentation (`electron/src`)

The permission window shows the app (e.g. **Heroic Games Launcher**, `socket owner electron`)
and, in Details › Electron app, the state, runtime, bundle, package, integrity, chain and
reason. Unverified: `electron` with `application unverified`; Remember offers only the verified native process scope described above, or is disabled
with the backend's reason when that scope is unavailable. The desktop name and icon come from the desktop entry whose launcher script
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

## Activity grouping (display only)

Verified Electron processes are one application entry (the bundle identity). An application
whose every visible process has `provenance.parent.application` = the same verified Electron
application (same UID) is shown beneath that application's row, e.g. **Heroic Games
Launcher › gogdl, legendary, nile** (`nestLaunchedApplications` in `electron/src/model.ts`).
Each child keeps its own row id, sockets, totals, Rule Status, Info View and Allow/Deny
prompts; the parent's totals and rule context are its own sockets only. Nothing is inherited:
allowing Heroic creates a rule for Heroic's bundle identity only, and its helpers and the
games it launches stay uncovered. If any process of the helper lacks the verified
relationship, the relationships differ, the parent is unverified, or the parent has no row,
the helper is shown separately rather than guessed. Info View shows "Launched by … Display
only".

Legacy bundle-based process bindings are not revived. The current prompt binds the
native executable and process generation. Activity application-wide rules remain
unavailable for unverified bundles.

## Rule Status display details

- Not-running applications that stored rules name are listed after all running applications
  (dimmed, "not running"; `inactiveApplications` in `electron/src/model.ts`), one entry per
  application key/revision/UID, in every sort order. An entry for an earlier revision of a
  running program is marked "earlier version". Their Rule Status comes from the stored rule
  inventory. Clicking an In/Out cell opens that direction's stored rules
  (`electron/src/inactive-rules.ts`): enable/disable, Ask/Allow/Deny, Advanced, Delete. Each
  change is reviewed by the backend (draft → preview → save, pinned to the listed version)
  and saved only when the reviewed rule is exactly the requested change; delete uses the
  confirmed conditional delete. When the last rule is deleted the entry disappears. No new
  rule can be created there: that needs the running, verified program. Active/Listening
  filters show sockets only and omit them.
- A process row without its own rule shows its application's rule as inherited: muted grey,
  disabled (no hover, tooltip or click). A process with its own rule keeps a normal cell.

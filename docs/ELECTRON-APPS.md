# Applications on a shared Electron runtime

FlowGate supports **best-effort application matching** on supported shared Electron
runtimes. This is an explicit convenience/security tradeoff: launch information,
package metadata and open-file evidence do not attest which application code is
executing. Manipulated evidence can impersonate another application. The prompt
shows a short “Best-effort application match” label; Details explains the scope.

## Matching and permission scope

A match uses the user ID, canonical runtime executable path and canonical application
entry. ASAR entries require the main process to hold the corresponding archive inode
open. Script entries (`.js`, `.mjs`, `.cjs`) require adjacent package metadata;
unpacked package directories are also understood. Dependency archives are not
substituted for the application entry. Missing or ambiguous evidence stays unverified.

The resolver checks process generations, same-user/runtime/mount ancestry and a
bounded runtime capability probe (64-bit ELF, Node execution symbol and Electron
fuse-v1 structure). The existing shared-runtime entry point recognizes
`electron`/`electron[0-9]*`; differently named packaged binaries retain native
executable identity. Runtime capability is a hint, not a signature. Real-runtime
qualification covers Electron 42 and 43, not every build or platform.

Matching Chromium network-service processes use the application's identity.
Independent Node utilities, Node-mode scripts and other helpers do not inherit it.
Detected inspection/injection modes and nonempty NODE_OPTIONS are refused. No
application name, launcher path or server-specific exception is used.

Application-only **Remember** saves a rule for future matching connections in the
selected direction. With no expiry it survives application relaunch and daemon
restart. Selected protocol, address, port or zone constraints narrow the rule;
they do not transfer it to another application or user. The compact prompt keeps
its existing controls; explicit zone scopes remain available through the existing
backend/rule controls. Ordinary Allow/Deny retains its existing single-request
semantics. For a while and an explicitly selected Process field remain process
scopes, not reusable application permissions.

Different application entries, runtime paths and users have separate keys. Same-path
updates can continue to match; this is not a content-hash-pinned code permission.
Each future connection must pass the normal resolver. A backend-private resolver
receipt is never restored from serialized application JSON or client hints.
The `electron-best-effort-v1` key space does not migrate old blanket runtime rules
or revive legacy records labelled “verified”. No automatic Allow is created.

## Requests whose process has exited

For a successfully resolved application, the backend retains its own match with the
request (up to ten minutes after its deadline, with a bounded 256-request inventory).
Remember on the ended request can save a **future application rule** without the
original process still running. It neither revives nor claims delivery for the old
connection. Future connections are independently resolved before the rule applies.
The retained request receipt itself is in memory and does not survive daemon restart;
a rule already saved to disk does. Expiry/eviction removes this future-rule opportunity.

If no application match was established, there is no application receipt to retain.
The prompt reports the unresolved runtime limitation; a name or JSON claim cannot
create a future application permission. A still-running unverified runtime can use
an exact native process decision when its executable, UID, generation, namespaces
and single socket owner are verified. That process scope ends on exit/identity
change/backend restart and cannot cover a relaunch.

## Display and helpers

Names, artwork and launch provenance are presentation, not an additional permission
source. Matching application processes share their application identity; independent
helpers retain their own identities and prompts even when displayed under a launcher.
Incoming/outgoing and explicit rule scopes remain independent. Existing inactive-rule
editing and conditional deletion continue to operate on the saved rule inventory.

## Verification boundaries

Synthetic API windows prove rendering and preview wiring, not kernel enforcement.
Real-runtime identity fixtures prove matching and policy serialization, not packet
admission. The isolated native GUI/kernel receiver journey is recorded separately in
the release evidence. No zone/shaping benchmark is implied by Electron matching.

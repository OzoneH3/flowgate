# Continuation handoff

Continue in `/home/flowgate-user/Apps/flowgate`, branch `milestone/backend`. Verify actual
HEAD and preserve unrelated work; the final report names the commit. Read
applicable AGENTS.md, PLAN.md, STATUS.md, SEMANTICS.md, WINE.md and README.md; check
`.workspace/coordination`. Source `scripts/go-env.sh` before Go commands. No agents
without explicit authorization. `.workspace/CONTINUE.txt` is historical.

## Current result and reusable evidence

Result **B**: optional `internal/identity/table.go` and the PE helper query public
runtime TCP/UDP owner tables, corroborated with a pinned broker, reciprocal Unix
peer relationship, kernel cookies, process generations and mapped image revisions.
The target Windows application is unmodified. `FLOWGATE_WINE_BROKER` alone keeps its
older conditional behavior; the new adapter additionally requires explicit table
runner/helper/version configuration and is only wired into `serve-lab`.

Installed Wine 11.19 and dwproton-11.0-4 / Wine 11.0 both passed plain TCP (no
FIONREAD), one-shot UDP, alpha-Allow/beta-Block and reversal. Both see dormant
inherited TCP/UDP handles; after parent exit the child remains attributed and
receives after release. Shared dormant TCP is denied. Pending listener replacement
and observer death reject Allow without receiver delivery. Evidence and exact
commands are indexed in STATUS.md and WINE.md. Native incoming regression, race
tests and vet passed; reuse unchanged scope/retention/outgoing results.

The inspected Bash `lwp` has an absolute third-argument prefix override and selects
installed dwproton by directory mtime. Tests reproduce its Proton selection through
`scripts/proton-fixture.sh` with a workspace prefix/cache and disabled game fixes,
without UMU installation/update machinery. `runinprefix` preserves helper pipes;
`--init` prepares a fresh prefix using Proton getcompatpath/winepath. This is not real-game or
complete Steam/UMU container integration validation.

## Smallest next useful work

1. Add actual WSADuplicateSocket and numeric handle-close/reuse cases, including
   repeated ownership changes while UDP packets or TCP SYNs are retained.
2. Decide the accepted-TCP ownership contract. Current enforcement rechecks new
   TCP attempts and UDP, but established allowed TCP retains the baseline kernel
   fast path; subsequent accepted-socket transfer is not continuously observed.
3. Test helper/server restart and build mismatch explicitly; retain sticky failure
   until daemon restart. Do not broaden versions or enable by default prematurely.

The census observes current holders, not every event. No Wine object ID is exposed;
kernel cookies, Windows PID/creation time and observer generations prevent observed
reuse mistakes but not adversarial ABA races between snapshots and verdicts.
Late startup reconstructs current state. IPv6 Wine, hostile same-user transfers,
hidden external FD recipients and arbitrary builds remain unsupported. Do not
replace that limitation with blanket runtime permissions or mandatory wrappers.

Authorization remains local edits/builds/tests/commits, read-only host diagnostics,
source inspection and workspace-only fixtures/prefixes in disposable namespaces.
No host firewall/network/service/security changes, packages, installed runtime or
existing prefix edits, real games, pushes, publishing or deployment. No additional
privilege is currently needed. All generated output stays under `.workspace`.

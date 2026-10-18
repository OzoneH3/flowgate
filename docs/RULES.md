# Saved rule editor contract

## Process-instance extension (not deployed)

Primary capability `process-instance-rules-v1` adds explicit process targets with
pinned native/session identity, process-tier precedence and inactive lifecycle
metadata. Application rules remain unchanged. See [PROCESS-RULES.md](PROCESS-RULES.md)
for schema3 preview/save/edit/delete, inventory, authorization and exact limitations.
Earlier application-only scope/precedence descriptions below refer to legacy rules.


Create from a current pending request; Edit from a saved rule. Ordinary Allow/Block
stays quick. Once is ephemeral; one-hour remembers an absolute expiry; persistent
has no expiry. The editor defaults to keeping the original absolute expiry.
“One hour from now” is an explicit reset, never a side effect of Enable or editing.
Expired rules remain visible and ineffective unless expiry is deliberately changed.

Application key, executable revision, UID and direction are immutable. New rules
must match a current corroborated pending principal, never a display name/PID.
Supported scope: TCP or UDP, remote IP/CIDR or explicit `*`, exact local and remote
ports (zero means any), priority, enabled state and expiry. Local address/interface
are unrestricted and the preview says so. No port ranges or domain matching.
Incoming defaults to service port + remote address, unrestricted remote source
port. Outgoing defaults to destination address/service, unrestricted local source
port. Broadening requires an explicit visible scope edit. Persistent application
identity retains the existing revision policy; it does not grant a runtime/prefix.

Highest numeric priority wins; ties use lexicographically smallest rule ID.
Allow and Block have no special implicit precedence. Preview lists active overlaps;
identical normalized scopes are rejected even if action/state/expiry differ, naming
the existing rule to edit instead. This includes equivalent host and /32 or /128.
Rules are bounded to 256, priority -1000..1000. Newly selected expiry must be in the
future within 365 days or persistent; unchanged legacy/expired expiry is preserved.

Preview and Save share backend validation. Each edit includes backend generation
and expected rule version. Stale edits fail; reload before trying again. Enable/
Disable increments the version. No disconnected/read-only client can save, and
mutations are never replayed after reconnect. SQLite commits the full candidate
set transactionally before live policy changes: storage failure leaves old policy.
Pending state remains ephemeral. Saving from a pending request rechecks identity;
retained packet release still checks the original deadline and current fingerprint.
Edits invalidate decided userspace caches and reevaluate current pending requests.
Already admitted TCP connections continue: this editor does not disconnect them.

SQLite tables/schema version are unchanged. JSON rule documents add optional
`version`; old documents load at zero without changing direction or expiry.
Older strict-decoding binaries reject new documents rather than silently ignoring
edit versions. Back up the database before downgrading; rollback is not automatic.

## Deletion concurrency

Use `rule-delete` with the displayed backend generation and expected version;
check, transaction and publication are atomic relative to edits. A stale delete
cannot remove the edited rule. Fresh creation uses a new random ID; restart has a
new generation. See [API.md](API.md) for capability, errors, retries and CLI.
Legacy `rule`/`delete` is still unconditional for older third-party callers; a
frontend precheck does not close its race. The integrated Qt/Electron Delete
controls have migrated and require the conditional capability.
No storage schema/table migration is required.

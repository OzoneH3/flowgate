# Saved rule editor contract

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

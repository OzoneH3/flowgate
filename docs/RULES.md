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

Precedence (`policy.Precedes`, the same comparator the evaluator sorts with, and
the source of the sentence shown in previews and explanations): among matching
active rules (the newest saved setting of each program scope), higher target
weight wins (process 4 › application 3 › zone 2 › all programs 1); then higher
priority; then a matching Local or Internet rule over All networks; then Deny › Allow › Ask; then a user rule over a preset; then the
lexicographically smaller rule ID. No match asks.

Traffic to this machine itself (loopback or this exact host address) is allowed
by default (`default-localhost-allow`); only rules naming a loopback address or
this exact host address apply to it, so a rule for any address (`*`) or a LAN
prefix does not. Preview lists active overlaps with which rule wins and why;
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
Legacy `rule` mutations now also require generation and expected version.
Older clients omitting them are refused. Integrated Qt/Electron Delete controls
use the dedicated conditional operation; Qt legacy toggles require the new
`conditional-rule-mutation-v1` capability.
No storage schema/table migration is required.

## Rules for applications that are not running

In Electron, expand **Not running**, then select the saved application or its
**Local Network** / **Internet** child. Use the **In/Out** status cell or the
**Incoming rules… / Outgoing rules…** buttons in Info View to add, edit, disable
or delete rules. The application does not need to be running.

For LAN-only access, keep a Local Network Allow and change the Internet rule to
Deny. If the Internet rule does not exist, add Deny from the Internet child.
New rules use the exact application/revision/user identity of an existing saved
rule, and inherit its priority; no process or launcher identity is guessed.
At equal priority, Internet Deny wins over an application-wide Allow for Internet
traffic. Other explicit higher-priority rules still follow normal precedence.
Existing rule edits preserve their network scope; Advanced creation can select a
new scope. Apps with no saved identity still require a verified observed target.

`conditional-rule-mutation-v1` advertises stale-safe legacy actions. Qt disables
its legacy Enable/Disable controls without this capability. Legacy `rule`
enable/disable/delete requests also require the displayed daemon
generation and `expected_version`. Missing or stale conditions refuse before
persistence and leave policy unchanged. A lost acknowledgement requires inspection
of authoritative inventory; do not replay the mutation against a new generation
or guessed version. Endpoint rules retain dedicated conditional deletion.

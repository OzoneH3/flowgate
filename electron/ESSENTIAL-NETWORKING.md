# Authoritative Essential Networking consumer

Base `008418ce6d6574b256b56f3668f4e7d6bdc221c3`. Electron owns presentation and a
restricted main-process bridge; discovery, identity, matching, persistence, preset
ownership and host lifecycle remain in Go. No operation here starts/stops protection
or a collector. Host protection is currently off/uninstalled; this is not deployment.

## Workflow

Firewall → **Essential networking…** opens immediately. Status lists detected
components and unavailable reasons. Optional Tailscale outer transport, its incoming
port/HTTP permissions, and trusted-interface discovery start unchecked. Variable-peer
permissions explicitly say **Any destination**. Preview shows exact application/UID
or all-program/all-user/local-service targets, direction, protocol, local/remote
addresses/ports, interface, lifetime and preserved records before Apply. There is
no client DNS/route/service discovery and no application-ID workaround for aggregates.

`essential-system-networking-v1` gates the feature. Status supports an administrator
companion; preview/apply/removal require the primary machine-administrator grant.
Apply/Remove also require explicit actual stopped monitoring metadata; active or
unknown protection requires an explicit Stop through the existing controls. Preview
and Apply are distinct actions. Enter on the dialog container cannot submit. Opening
or refreshing never applies policy or activates interception.

Main retains one exact preview/token/generation/options. It validates full schema5
rules and acknowledges only the identical reviewed receipt. Intervening changes,
expired reviews, unavailable discovery and backend errors remain visible. Lost ACK
locks new mutations; **Check uncertain result** queries the original receipt without
replaying Apply/Remove. Daemon changes invalidate old reviews. The existing coherent
rule-mutation publication fences are reused. Local status IPC responses cannot roll
back a newer dialog interaction.

Removal is a separate authoritative preview listing only exact unedited preset
records and preserved edited/disabled records. Generic rule inventory shows preset
attribution and full peer-service/interface scope. Legacy Edit/Toggle refuses schema5
rather than dropping its constraints; existing exact conditional Delete is retained.
No frontend preset or policy matcher is implemented.

Essential operations use a fixed20s asynchronous idle/absolute transport budget for
bounded15s discovery; ordinary API polling retains3.5s. Main accepts only known
operations, four Boolean options and a validated interface-exclusion list, never
renderer-supplied peers/rules/paths.
Only the registered main window can invoke the bridge; detached/prompt windows
cannot mutate the preset.

## Interface exclusions (`essential-interface-exclusion-v1`)

The dialog lists interfaces carrying discovered upstream DNS/DHCP, derived only from
the backend review (DNS/DHCP preset rule `interface_name`, never `lo`, and the
"Excluded by review, not proposed: …" / "Excluded interface … has no discovered …"
issues), with an **Exclude … from this review** checkbox each. Excluded interfaces
stay listed so they can be re-included. Checkboxes start unchecked except the
persisted reviewed set, which main stores in `electron-preferences.json` as
`essential.excluded_interfaces` only after a confirmed Apply receipt (re-validated
on load; invalid content is ignored). The reviewed host choice is `ppp0` (work VPN)
excluded, as applied by `scripts/apply-essentials.py`; seed
`"essential":{"excluded_interfaces":["ppp0"]}` in an existing preferences file to
preselect it before the first UI Apply.

Main validates names like the daemon (1..15 printable ASCII, no whitespace, `/`,
`:`, `.`/`..`; `lo` rejected; at most 16) and canonicalizes (sorted, de-duplicated).
`essential_options.excluded_interfaces` is sent on preview and Apply exactly as
reviewed (omitted when empty; removal sends none) and the daemon echo/receipt must
match. Any change of choices disables Apply until a fresh Preview with equal options.
The review shows `Excluded: ppp0` (or `none`), also on the receipt line.

Daemons without the capability silently ignore the field, so main never sends it
to them: a preview with exclusions is refused, and while a reviewed exclusion is
persisted Apply stays disabled with an explicit message (no default Apply that
re-proposes the excluded DNS/DHCP). Removal is unaffected.

## Verification

Build/typecheck and32 focused rule/policy/decision/Essential checks pass; additional
Essential checks cover administrator-companion reads and active/unknown protection
refusal. Controlled replies cover exact apply/removal, preserved scope, malformed
metadata, generation change during a held response, expired/options-changed preview,
policy conflict and lost Apply/Remove ACK with one mutation and explicit receipt.
These are protocol/model checks, not enforcement proof.

Synthetic native Wayland UI evidence in this worktree:
`.workspace/essential-ui-ueKN2p/` and `.workspace/essential-ui-gdSFUw/` (normal and
860×600 captures). Optional defaults, exact aggregate/Any scopes, explicit Apply,
lost-ACK reconciliation, preserved edited record during removal and read-only
legacy editor passed. These are controlled responses, not native service proof.

Released backend `200a19ec7cfe71a414ee2412b5fd676c8dc56ef3`, fixture generation
`917b1887287667673f8ff0e4e39c7d2a`: real API, durable store, native identity and
stub listeners, **simulated** resolved/NM/time/Tailscale configuration; monitoring
throughout. `.workspace/essential-real-5wOL2R/` passed default/optional previews,
12-record Apply with a deliberately dropped ACK, original receipt reconciliation
with one Apply, exact full saved/list records and preset read-only inventory.
It then exposed a missing request field: removal operations require explicit
`essential_options` too. The backend refused before mutation. Main now sends frozen
options for removal as well, with a deterministic regression.

The bounded removal-only continuation `.workspace/essential-real-oUK5Qy/` asserted
the same generation and exact12 stored IDs before opening, reviewed and removed
those exact records through the corrected UI, and verified rules0/enforcement
stopped afterward. No Apply or decision was replayed; no receiver suite was rerun.
`default-review.png`, `optional-review.png` in the first run and
`narrow-removal.png` in the continuation are actual UI captures. This is explicitly
a two-stage real journey with a diagnosed/refused intermediate request, not an
unbroken passing run. The initial harness also treated an omitted empty rules
list as undefined; that harness-only assertion was corrected before the journey.

DHCP records are durable interface-name/client-port protocol exceptions shared with
the pre-daemon guard, retained until explicit reviewed removal. UI labels and the
DHCP component state that distinction; these are not application identities or
sampled lease claims. DNS/time/VPN permissions use backend component freshness and
identity/configuration binding. Unavailable discovery remains explicit; no RFC1918
trust or unsupported provider adapter is invented in Electron.

All UI windows/proxies were closed and explicit DONE returned to backend cleanup
ownership after stopped/rules0. Fixtures use owned cloned preferences; no host
endpoint was contacted, no host policy/protection/collector action was performed,
and host deployment/readiness is not claimed. Backend owns receiver proofs and
integration. Legacy Python DNS proposal parsing was left unchanged, superseded by
authoritative structured discovery.

# Application + zone rows

Activity shows Local Network and Internet filter children beneath exact application identities, before process/connection children. Each child has a funnel glyph and independent In/Out Rule Status. Application-wide controls remain on the parent; global all-program zone rows remain separate.

Child controls list only their exact application/revision/UID, zone and classifier model. Multiple rules require choosing a specific record. Existing edits preserve protocol, endpoints, expiry, version and zone. A new rule previews the selected application zone; the disabled zone selector prevents an accidental switch to Any network. Detached Info uses the same scope-bound bridge, with additional main-side target checks.

Legacy-prefix rules get distinct children when the current classifier is automatic. They can be edited or explicitly migrated; creating a new automatic rule from a legacy child is refused. Process-only rules and shared/display-only ownership are not treated as application policy.

Rates/totals and socket counts are **unavailable**, shown as “—”. The backend does not provide zone-attributed accounting intervals; whole-application lifetime counters are not relabelled. These rows show stored configuration, not a frontend calculation of which rule wins. NetLimiter-style weights and a machine-wide Any-network baseline require a separate backend contract; existing precedence and host rules are unchanged.

## Focused evidence

Build/typecheck passed. Actual sandboxed Wayland inspection against the isolated real monitor backend (`flowgate-auto-ui-reviewed`, source808bc5e): `.workspace/app-zone-rows-view-9yHJIO/`. Parent Out Allow, Local Out Deny and Internet In Deny saved as three distinct exact rules; Local quick setter listed only the Local rule, including detached Info. Actual 1200×800 and 860×600 screenshots captured. All three records conditionally deleted; rules0/enforcementstopped, owned fixture supervisor CLEANED. No host endpoint, enforcement or collector operations; backend receiver proof reused.

Minimal integration check: `npm --prefix electron run build`. This focused request added no test suite; the isolated UI inspection exercised creation, selection, exact inventory, detached setter and cleanup.

# Experimental upload-limit workflow

The Activity Rule Status **UL Limit** slot and Info View **Limit / Out** cell
open the same compact dialog for a verified native application/UID. The limit
aggregates that target's bound sockets; it does not follow launcher or runtime
identities. The toolbar **Upload limits** list keeps removal reachable after an
application exits. Download, priorities and quota cells remain unavailable.

Set a decimal rate from 1–1000 Mbit/s and choose **Enable / save**. A successful
receipt displays **Pending**: it acknowledges desired configuration only. Choose
**Refresh status / review** to observe reconciliation and confirmed/requested
bindings. A configured rate remains distinct from receiver throughput. Even a
kernel Active subset displays **Partial**, never an application-wide enforced
cap. Missing per-binding confirmation or expired coverage counts as zero
confirmed. Unsupported capability/topology/ownership faults remain explicit.

Editing replaces only the selected UID/application in the current full cap set.
Disabling its last configured limit submits `enabled:false,caps:[]`, requesting
verified owned cleanup. The UI does not delete TC objects itself. An Unsupported disabled/empty state
offers **Retry owned cleanup** with a fresh configuration CAS. Removal does
not require the application to remain running; adding/editing requires a current
native observation, which is only a hint for the controller's fresh proof.

All mutations use the authenticated administrator connection, daemon generation
and captured configuration version. A stale draft or lost receipt disables
submission until explicit refresh/review. Status/coverage refresh independently without overwriting
the draft; local monotonic lease expiry clears confirmed counts. There is no automatic write replay.
Firewall Allow/Deny requests and stored rules are never touched. Closing the GUI
does not disable the independent controller. Configurations are session-scoped
and do not survive daemon restart.

Coverage limitations remain visible: first traffic can escape before binding,
shared/runtime identities and unsupported interfaces are not broadened, socket
assignment persists through exec/transfer until closure or fresh rebinding, and
UDP GSO remains unsupported. TCP cap evidence is not a UDP claim. Performance
limitations are accepted only for this experimental integration.

Focused checks: `test/upload-shaping.test.cjs`. Real isolated Electron journey
uses `[data-upload-limit]`, `#uploadRate`, `#uploadSave`, `#uploadRefresh`,
`#uploadCoverage`, `#uploadRemove`, and `#uploadLimits`. Fixture API acknowledgements
must be followed by receiver measurements; these Node tests do not prove delivery.

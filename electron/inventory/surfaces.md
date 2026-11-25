# GUI surfaces from source

The expected list is maintained alongside the keyboard journeys. A surface can be a native window, a dialog in the main renderer, or a meaningful selected view. The capture plan gives all three the same per-state file contract.

| Source | Expected surfaces and states |
| --- | --- |
| `main.ts`, `renderer.ts` | Main dashboard; Activity, Pending requests, Rules, Decision log, Observed usage; disconnected and read-only authority; settings, File, Window, Help, Firewall and UDP menus; toolbar indicators; queue diagnostics; About with matching package/daemon identity or unavailable daemon, and icons guide. Permission timeout loaded, edited with Save enabled, and saved. |
| `renderer.ts`, `activity-policy.ts`, `connection-analysis-view.ts` | Empty and populated census, expanded groups, selected application, process, socket, network and Unidentified; Info view and its menu; quick rule setter, optional floating status, delete-all-app-rules confirmation; analyzer closed/open, recheck, watch, shared holders expanded. |
| `main.ts`, `pane-renderer.ts`, `graph.ts` | Detached Info View and Traffic Chart; dock, close, units and source; chart live, paused, sample and measurement explanation. |
| `main.ts`, `prompt.html`, `prompt-card.ts` | Independent permission window, pinned to request + generation; actionable outgoing TCP, incoming TCP, UDP, local pair, rule scope checked, details/back, queue advance affordance, temporary duration, ended and failed review. The warm hidden shell is not a user window. |
| `renderer.ts`, `permission-results.ts` | Pending requests empty, grouped and selected; inline controls, expanded request details and submitted decision results. Temporary process leases come from a separate daemon state. |
| `workflows.ts`, `endpoint-view.ts`, `zone-migration-view.ts` | Saved-rule list empty, populated and selected; enabled, disabled, read-only, full and compact editors, identity, preview, minimize/resume, enable draft, unresolved save and delete confirmation. Endpoint editor unreviewed/invalid/reviewed and legacy zone migration review, preview, unknown outcome and reconciliation. |
| `decision-log-view.ts` | Empty, disconnected, populated, filtered and paused; historical pending, linked final, aggregation and gap details. Load older through the last page, and use the paused new-record indicator to load the latest page. |
| `observed-usage-view.ts`, `usage-history-view.ts` | Empty and populated observations; live versus history and history recording/retention controls. |
| `upload-shaping-view.ts` | Bandwidth-limit inventory and budgets; upload, download and priority editors, detailed coverage, cleanup and unavailable controls. |
| `background.ts` | Native tray menu and its Open, Pending and Quit routes; native quit confirmation when requests remain. The desktop Notification implementation is explicitly disabled by the background constructor since permission popups handle notifications. |
| `workflows.ts`, `protection-view.ts`, `daemon-evaluation.ts` | Protection controls and readiness details, evaluation/recovery, daemon startup and Stop, readiness details, UDP start and stop confirmations. Checkout-only legacy startup exposes Cancel authentication and the external terminal. No real system authorization is sent by the normal plan. |

## Open coverage

The plan records which individual states are blocked with the current package and desktop. In particular, AT-SPI exposure of the actual system tray trigger/menu and native quit confirmation must be verified on each supported shell. The installed entry point selects daemon evaluation, so external legacy authentication and its startup Cancel are explicitly blocked as checkout-only states. Geometry-dependent floating Rule Status is listed even when the stock 1920×1080 layout does not enter it.

The present seed does not attempt a real protection or collector transition, real packet delivery, a persisted history database, or external platform dialogs. The plan includes an active process lease and a lost decision acknowledgement. Receipt reconciliation after that acknowledgement and additional backend readiness/failure variants remain outside these recipes.

### Branches beyond the current seed set

The source-literal index used in review includes generated inspector tab IDs, Decision Log record fragment IDs, and the pane-specific chart-source/window controls. The semantic inventory covers those families through their rendered labels and roles. Alternate branch coverage still includes observed-rule creation and a new network rule from a scoped rule, endpoint save reconciliation, Decision Log rule comparison and app-filter navigation, old-rule return navigation, conditional runtime and queue health warnings, and controller-specific shaping errors. The captured unknown rule-save state does not exercise receipt-backed reconciliation. See the pinned expected-state list for the exact seeded states and assertions.

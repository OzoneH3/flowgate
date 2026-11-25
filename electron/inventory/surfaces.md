# GUI surfaces from source

The expected list is maintained alongside the keyboard journeys. A surface can be a native window, a dialog in the main renderer, or a meaningful selected view. The capture plan gives all three the same per-state file contract.

| Source | Expected surfaces and states |
| --- | --- |
| `main.ts`, `renderer.ts` | Main dashboard; Activity, Pending requests, Rules, Decision log, Observed usage; disconnected and read-only authority; settings, File, Window, Help, Firewall and UDP menus; toolbar indicators; queue diagnostics; About and icons guide. |
| `renderer.ts`, `activity-policy.ts`, `connection-analysis-view.ts` | Empty and populated census, expanded groups, selected application, process, socket, network and Unidentified; Info view and its menu; quick rule setter, optional floating status, delete-all-app-rules confirmation; analyzer closed/open, recheck, watch, shared holders expanded. |
| `main.ts`, `pane-renderer.ts`, `graph.ts` | Detached Info View and Traffic Chart; dock, close, units and source; chart live, paused, sample and measurement explanation. |
| `main.ts`, `prompt.html`, `prompt-card.ts` | Independent permission window, pinned to request + generation; outgoing TCP, incoming TCP, UDP, local pair, rule scope checked, details/back, queue advance affordance, temporary duration, ended and failed review. The warm hidden shell is not a user window. |
| `renderer.ts`, `permission-results.ts` | Pending requests empty, grouped and selected; inline controls, expanded request details and submitted decision results. Temporary process leases come from a separate daemon state. |
| `workflows.ts`, `endpoint-view.ts`, `zone-migration-view.ts` | Saved-rule list empty, populated and selected; enabled, disabled, read-only, full and compact editors, identity, preview, minimize/resume, enable draft, unresolved save and delete confirmation. Endpoint editor unreviewed/invalid/reviewed and legacy zone migration review/preview. |
| `decision-log-view.ts` | Empty, disconnected, populated, filtered and paused; historical pending, linked final, aggregation and gap details. |
| `observed-usage-view.ts`, `usage-history-view.ts` | Empty and populated observations; live versus history and history recording/retention controls. |
| `upload-shaping-view.ts` | Bandwidth-limit inventory and budgets; upload, download and priority editors, detailed coverage, cleanup and unavailable controls. |
| `background.ts` | Native tray menu and its Open, Pending and Quit routes; native quit confirmation when requests remain. The desktop Notification implementation is explicitly disabled by the background constructor since permission popups handle notifications. |
| `workflows.ts`, `protection-view.ts`, `daemon-evaluation.ts` | Protection controls and readiness details, evaluation/recovery, UDP start and stop confirmations. Legacy authorization opens an external terminal. No real system authorization is sent by the normal plan. |

## Open coverage

The plan records which individual states are blocked with the current package and desktop. In particular, AT-SPI exposure of the actual system tray trigger/menu and native quit confirmation must be verified on each supported shell. External legacy authentication needs a separately prepared isolated authorization fixture. Geometry-dependent floating Rule Status is listed even when the stock 1920×1080 layout does not enter it.

The present seed does not attempt a real protection or collector transition, real packet delivery, a persisted history database, or external platform dialogs. Presentation of process leases, uncertain request verdict reconciliation, and all backend readiness/failure variants needs more seed recipes. These are separate from the integrated package baseline.

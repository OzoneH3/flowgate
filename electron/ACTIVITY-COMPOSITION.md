# Activity composition and ordinary launch review

Reviewed on 2026-10-18 from integrated `7020db002fb8c2d0d5db7d788e4a09e626156297`.
Includes agreed bridge support `29436689afdaf86a8021558c27284e2c7c4bb3e7`.
This is rendered evidence, with no numerical resemblance rating.

## Five largest differences and corrections

| Before | Implemented | Classification |
|---|---|---|
| No initial selection; empty Info and chart despite populated applications | Selected All applications overview; source-separated bounded history over actual unique sockets; root is observation-only, never a policy target | Frontend, existing observations |
| Search consumed most of Activity's control row | Search moved into main toolbar; explicit TCP/UDP source and socket filter in compact Activity row | Frontend |
| Repeated long absent-policy labels, dark policy boxes on selected row | Compact `Not set` (means no explicit rule), narrower In/Out columns, white selection text; full scope/coverage remains in policy panel/tooltips | Frontend, authoritative summaries retained |
| Unstructured sidebar text with hidden executable | Visible selectable executable, bordered properties, In/Out Rules matrix and actual navigation links | Frontend, existing identity and rules |
| Large chart control row, prose, dead initial chart and solid rate-column fills | Docked126px chart, selectors in heading, expandable measurement details, small rate highlights; all source/gap semantics retained | Frontend |

## Semantics and verification

- Table rate/total source is explicit: TCP transport payload or UDP socket API-reported payload. Sorting uses the selected source, numerically; unavailable stays last. Definitions are never summed together. Denominators include unavailable sockets of that protocol. Shared IDs count once.
- Overview/graph includes all observed sockets regardless of table search/filter. It is labeled All applications; it is not inactive-app inventory, a unique-internet total, a permission identity or a default firewall verdict. Loopback/local perspectives and VPN transport are not deduplicated internet usage.
- In/Out remains connection-initiation direction. `Not set` means no explicit rule, not Allow/Ask. Existing backend uniform/scoped/mixed/inactive/unavailable interpretation and editor/preview/delete protections are retained. Overall enforcement remains visible separately from UDP collection.
- Build/typecheck,21focused model/history/icon/bridge checks and4shared bridge checks passed. Sandboxed Wayland fixture runner passed normal/narrow, root/source controls, rate descending-first/toggle, IPv6 search, policy keyboard access, column/sidebar resizing, scroll stability, editor text/focus retention and prompt accessibility. Fixture prompt/rules/rates are not enforcement evidence.
- Ordinary launcher rendered actual read-only host Activity and resized to matched/narrow dimensions, then cleanly quit with exit0. Existing feature/enforcement/UDP evidence reused. Host peer/generation/permissions, collector generation and active state remained unchanged; enforcement stopped.

## Backend agreement and remaining differences

Backend owner confirmed existing observations, batch policy summaries and native identity suffice for the five changes. No policy/accounting addition was required. A narrow shared launcher option was implemented by that owner: `--backend {flowgate,electron-backend}`. Electron passes the fixed latter value internally; no renderer-supplied paths. This prevents frontend builds replacing the approved backend executable. Authentication and pinned-controller preference are unchanged.

Remaining visible differences/next steps:

1. NetLimiter's Filters/Tags/zones, inactive inventory, shaping/priority/quota families and status glyph strip are real features. FlowGate keeps actual supported In/Out cells. Larger parity work requires a separate bounded product/backend proposal and acceptance scenario before implementation.
2. Linux service/runtime rows often lack trustworthy desktop metadata; neutral icons remain. A friendly installed desktop name could later use the same unique executable association in the existing narrow asset bridge, as display-only metadata. Do not invent publishers/version/trust fields.
3. Source selectors and partial-coverage indicators remain visible because TCP and UDP definitions differ. They cannot be replaced with a combined NetLimiter-like number without changing accounting meaning.
4. FlowGate has fewer functional menus/tabs and no unsupported rule-family rows. Current policy, events and bounded live history remain distinct from persistent traffic statistics.
5. Font family is approximate, selected screenshot contents differ, and Linux decorations vary. Main-window sidebar properties represent verified Linux identity rather than Windows version/publisher metadata.

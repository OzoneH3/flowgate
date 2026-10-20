# To do

Open items reported by the user, not yet implemented. Remove an item when it ships.

## Activity › Rule Status: icons only on the hovered row (NetLimiter parity)

- **Observed in NetLimiter (user screenshot, 2026-10-20):** only the row under the mouse
  pointer shows the full Rule Status icon strip (Priority, DL/UL Limit, In/Out Blocker, In/Out
  Quota icons). The *selected* row (blue highlight) shows the dots, unless it is also hovered.
- **FlowGate today:** both the hovered and the selected row show the icons
  (`electron/src/style.css`: `#tree tbody tr:hover … , #tree tbody tr[aria-selected='true'] …`
  rules around `.status-slot .slot-icon` / `.slot-dot`, ~line 1236).
- **To do:** show icons on hover only; the selected row keeps dots (and its configured
  Blocker glyphs) when not hovered. Keyboard focus still needs a visible way to reach the cells.

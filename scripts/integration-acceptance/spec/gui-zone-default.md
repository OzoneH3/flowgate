# GUI zone default: actual request and stored result (exact 93eaa868 bundle, synthetic API)

Fixture: spec/gui-zone-default.mjs (copy of electron/test/zone-popup-ui.mjs harness; slot selector updated
because 93eaa868 relabels slots "<kind> for <row>"). Bundle: automatic-zone-releases/93eaa868/{runtime/electron,
electron/dist}, hash-verified. Ran in `systemd-run --user --scope MemoryMax=1G CPUQuota=100% TasksMax=96`,
visible Wayland window, sandboxed. No daemon, TC or traffic. Evidence:
.workspace/acceptance-gui-zone-default/run-Vybvn6/evidence.json (all requests captured).

Setup: All networks priority High saved through the popup.
| Case | Request / stored | Verdict |
|---|---|---|
| Local UL rate 4 Mbit/s saved | local entry `{scope:local, bits_per_second:4000000}`, no traffic_priority; All stays high | PASS: rate save preserves inheritance |
| Internet Priority popup opened, untouched, OK | preselected **normal** (the Options default), hint "All applies"; Save enabled; stored `{scope:internet, traffic_priority:"normal"}` | **FAIL (D1)**: silent override High→Normal |
| Local Priority popup opened, untouched, OK | preselected normal; stored local traffic_priority "normal" | **FAIL (D1)** |
| Local DL rate saved afterwards | keeps the stored priority | PASS |
| all writes schema 3 | yes | PASS |
Cause (source): upload-shaping-view.ts:189 `level.value = c?.traffic_priority ?? defaults.priority` for a zone
without its own priority. Save is enabled for any zone level (line 180), and replacePriority (upload-shaping.ts:97)
stores explicit zone Normal. Intended: show the inherited value / an "Inherited" state, and do not write
unless changed. Not fixed here (no feature work in this task).

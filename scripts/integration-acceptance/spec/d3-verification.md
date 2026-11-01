# D3 correction verification (harness copy only; candidate unchanged)

`spec/d3-zone-popup-ui.mjs` = the release's electron/test/zone-popup-ui.mjs with only these changes: slot names
`<kind> for <row>` (paintAvailability labels in 93eaa868), Info-view names `download for …`, the exact
93eaa868 bundle (runtime/electron + electron/dist, hash-verified), and the run dir .workspace/acceptance-d3.
Run: capped user scope (MemoryMax=1G, CPUQuota=100%, TasksMax=96), sandboxed visible Wayland window,
synthetic Unix API, no daemon/TC/traffic. Result: **pass=true, 6/6 steps, 0 page errors, 15 upload-configure
writes**. Each step asserts the stored caps and the dialog's scope/rate fields, which proves the selectors reached the
intended slots (main row, zone rows, inline and detached Info). Evidence: .workspace/acceptance-d3/run-64ForL/
(evidence.json + screenshots). internet-priority-popup.png visibly shows D1 (Internet "All applies" with
selector "Normal").
Observation D3b (minor a11y regression, product): upload-shaping-view.ts:87/97 set descriptive names ("Upload limit
for …", "Traffic priority for …"), but paintAvailability (line 23) overwrites them with "upload for …"/"priority for …".

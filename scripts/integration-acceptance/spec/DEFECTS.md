# Confirmed / open defects for candidate 93eaa868 (candidate unchanged; corrections prepared separately)

| ID | Status | Area | Summary | Evidence |
|---|---|---|---|---|
| D1 | **CONFIRMED** GUI defect | electron upload-shaping-view.ts:189/180, upload-shaping.ts:97 | In a zone without its own priority, the Priority popup preselects the Options default (Normal) instead of the inherited All priority. An untouched OK writes an explicit zone override (High→Normal). Rate saves preserve inheritance. | gui-zone-default.md; .workspace/acceptance-gui-zone-default/run-Vybvn6/evidence.json; independent-review.md item 6 |
| D2 | OPEN (needs §3 run evidence) | daemon socket_session.go:42 | The production fast-path start has no shaping guard; the lab path refuses shaping. The installed launcher enables both. | provenance.md; independent-review.md item 5 |
| D3 | CONFIRMED test defect | electron/test/zone-popup-ui.mjs | Frozen fixture selectors ("Upload limit for …") do not match 93eaa868 slot labels ("upload for …"). The release's own GUI test cannot reach the controls. | gui-zone-default.md; d3-zone-popup-ui.mjs verification |

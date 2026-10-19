# Automatic network-zone consumer

Electron accepts `automatic-network-zones-v1` metadata without classifying addresses itself. Registry/network state, revision and reasons come from the daemon. Prefix lists on this model are explicit overrides, not exhaustive Internet coverage. Rule Status and the rule list distinguish automatic from legacy configured scope.

New zone permissions use schema 6 and `filter.zone_model=automatic-peer-v1`. Ordinary edits preserve legacy schema 4 without a model; Essential schema 5 stays read-only. Changed network revision invalidates a reviewed save while keeping the draft.

## Explicit migration

With `zone-migration-v1`, select a legacy rule in Rules → **Review automatic scope…**, or use its Activity rule details. Review exact added/removed CIDRs for the current snapshot, backend examples and full scope. A separate checkbox acknowledges future automatic network/registry updates; Confirm is disabled until authority and token are valid. This does not start protection.

Main owns one restricted migration context. Preview/save are bound to controller, generation, ID/version, network revision, exact rule and absolute expiry. Only schema/model/version change; legacy empty Any peer may canonicalize to explicit `*`. Narrow endpoint widening is rejected. Detached Info links remain unavailable for migration: review it in the main window.

Lost or inconsistent acknowledgement stays unknown. **Check migration result…** reads authoritative inventory for the exact migrated record; it never replays a write. An external edit/delete cannot be reported as successful reconciliation. Older daemons do not expose this action.

## Focused evidence

Build/typecheck and controlled-order tests: `test/zone-migration.test.cjs`, plus existing zone/editor/process/Essential/Remember checks. Native acceptance and final source pairing are recorded in the integration handoff, separately from backend receiver proof. No host protection, rule or collector action is part of this consumer work.

Accepted UI journey: `.workspace/auto-zone-ui-NwZdWf/` contains real sandboxed Wayland migration review captures (actual 800×550; requested larger bounds were not settled at capture). Explicit checkbox/Enter guard and exact migration acknowledgement passed. A harness-only invalid expiry/scope choice stopped subsequent creation; it did not undo or repeat the migration. `.workspace/auto-zone-ui-qDOANo/result.json` resumes new observed Local schema 6 creation and conditional removal of both records, finishing with zero rules and enforcement stopped. Backend candidate: `808bc5e` (`flowgate-auto-ui-reviewed`); native identities and API/storage real, seeded disabled legacy rule synthetic. No receiver or host-protection claim is made by this UI journey.

Final focused checks: build/typecheck and 71 tests passed. Backend retains fixture shutdown ownership after explicit DONE. Existing receiver proof is reused.

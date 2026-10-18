# Activity rules and connection initiation

## FlowGate behavior

- Both directions' complete authoritative refs are listed directly in Activity,
  including scoped, disabled and expired rules. Partial batches are labeled;
  older backend list-derived inventory is explicitly a compatibility view.
- Matrix labels retain absent/inactive/scoped/mixed/uniform/unavailable distinctions.
  Stored rules and enforcement coverage remain separate. No first-match evaluator.
- Quick setter chooses **one existing rule** or **New separate rule**. It never
  collapses overlapping/scoped rules into a broad replacement. Existing edits retain
  scope and expiry; expired rules require explicit Advanced renewal.
- New protocol-wide scope is an explicit checkbox and covers that protocol only.
  The existing identity-bound authoritative Preview/Save and30second expiry apply.
  No rule saves merely by choosing an action. This deliberate difference from
  NetLimiter preserves the reviewed-scope contract. Compact editor can expand.
- Acknowledged saves remain in Activity and highlight their exact rule. Unfinished
  drafts are brought forward, not overwritten by another quick selection. Polls
  preserve input/focus and quick-choice values. Existing ambiguous-save reconciliation,
  uint64/version refusal and conditional-delete acknowledgements remain intact.
- Single-holder display metadata is allowed only alongside the authoritative native
  association; shared/display-only groups cannot become creation targets.

### Backend support and remaining differences

Base/released backend **b9840d01096d156d92ce515bd69a07fef443eef6** adds
`activity-initiation-v1`. Validated bridge projection retains state/direction,
source, reason and observation time. Incoming evidence is sampled request-socket
SYN-received; outgoing is sampled SYN-sent, then retained only for the same current
kernel cookie and validated identity. Existing sockets may remain unknown. No port,
byte-flow or tuple inference, new collector, enforcement authority or accounting change.
See [API](../docs/API.md). Older daemons show honest unknown/listening fallback.

Backend owner agreed process-instance rules are a separate scoped next increment:
PID/start/UID/netns/application revision **plus boot/session binding**, live exclusive
ownership validation, preview/save binding, explicit exit/restart inactive semantics,
no application-wide fallback. Precedence against application rules and persistence /
delete semantics must be agreed before implementation. Acceptance: two same-executable
instances, a process-only rule affects only the selected instance, including PID reuse.
No new schema was guessed in this increment. Limits/priorities/quotas remain separate
features, not inert controls. NetLimiter's compact combined status strip also differs
from FlowGate's explicit In/Out text columns and full relevant-rule list.

## Focused evidence

Main repository local evidence (not committed media):
`.workspace/netlimiter-reference/rules-study/`:

- `activity-rules-comparison.png`: full native-scale NetLimiter/FlowGate content.
- `sidebar-comparison.png`: selected-context detail at native scale.
- `cleanup-audit.json`, `change-ledger.md`: fixture cleanup and settings ledger.

Raw NetLimiter captures in `.workspace/netlimiter-reference/`:
`rules-reference-process-quick-menu.png`, `rules-reference-process-allow.png`,
`rules-reference-app-after-process-rule.png`, `rules-reference-app-quick-menu.png`,
`rules-reference-app-advanced.png`, `rules-reference-rule-list-cleanup-final.png`.
The comparison includes actual dedicated Windows and Linux fixtures, not host traffic.
No policy was applied to existing Windows applications. Both temporary rules deleted;
guest fixture directory/process removed, audit0fixture/0ping processes. Only owned
shared staging files removed. Search cleared/root selected; theme/global toggles unchanged.

UI-worktree evidence: `.workspace/activity-rules-real-28BVUv/`:
`rules-and-expanded-directions-normal.png`, `rules-directions-narrow.png`,
`first-incoming-preview.png`, `read-only.png`, `result.json`.
Actual sandboxed Wayland against the released isolated daemon: first incoming Allow,
second scoped Block, outgoing Block; app/process/connection inventory; exact quick edit,
disable/re-enable, conditional delete preserving sibling; input/focus through polling;
read-only denial; GUI exit preserves daemon generation/stopped state. Real TCP4/6
2incoming+2outgoing directions observed. No intercepted packet verdicts claimed here.
Reuse settled enforcement/receiver evidence; no host lifecycle or rule changes.

Build/typecheck and18focused model/bridge checks passed. Synthetic presentation runner
also passed disabled/expired/multiple scopes, control-only refresh, prompt icon,
read-only, disconnect, normal/narrow. Synthetic states are not receiver evidence.
Existing measured presentation runner covers rate sorting/filtering/resize behavior.

```sh
npm --prefix electron run build
node --test electron/test/activity-selection.test.cjs electron/test/policy.test.cjs electron/test/presentation.test.cjs electron/test/observed-rules.test.cjs electron/test/delete.test.cjs
node electron/test/presentation.mjs
# Externally owned disposable direction fixture ONLY, never the host:
FLOWGATE_TEST_ENDPOINT=/absolute/workspace/fixture/api/daemon.sock FLOWGATE_TEST_BACKEND_SHA=b9840d01096d156d92ce515bd69a07fef443eef6 node electron/test/activity-rules-workflow.mjs
# Normal read-only host connection (no automatic mutations/lifecycle):
scripts/run-electron.sh --daemon /run/flowgate-api/daemon.sock
```

import type { Rule, RuleAction, RuleEdit } from './protocol';

// Everything an action/enabled change must leave untouched. `opt` marks fields the
// daemon omits when zero (policy.Rule/Filter omitempty/omitzero), so absent equals
// that zero; all other fields compare exactly. remote_address "" and "*" both mean
// any address (policy.CanonicalFilter). The daemon itself derives root_application
// and keeps the stored invocation on an edit; follows_updates is read-only display.
const opt = <T,>(v: T | undefined | null, zero: T) => v ?? zero;
function scopeKey(r: Rule) {
  const f = r.filter;
  return JSON.stringify([
    r.id, opt(r.executable, ''), opt(r.root_application, ''), opt(r.share_with_root, false),
    r.invocation ?? null, r.preset ?? null, r.priority, r.expires,
    f.application, f.revision, f.uid, f.direction, f.protocol,
    f.remote_address || '*', opt(f.local_port, 0), opt(f.remote_port, 0), opt(f.remote, ''),
    opt(f.all_programs, false), opt(f.all_uids, false), opt(f.network_zone, ''), opt(f.zone_model, ''),
    opt(f.interface_index, 0), opt(f.interface_name, ''), opt(f.local_address, ''),
    f.peer_service ?? null, f.process ?? null,
  ]);
}
// Schema the preview may legitimately assign (legacy 1 → 2; see Rules.preview).
const editedSchema = (d: Rule) => ([4, 6].includes(d.schema) ? d.schema : d.filter.process ? 3 : 2);

export function matchesStoredRuleEdit(reviewed: Rule, draft: Rule, action: RuleAction, disabled: boolean) {
  return reviewed.action === action && reviewed.disabled === disabled &&
    reviewed.schema === editedSchema(draft) && scopeKey(reviewed) === scopeKey(draft);
}

export function storedRuleEdit(token: string, draft: Rule, action: RuleAction, disabled: boolean): RuleEdit {
  return {
    token,
    action,
    disabled,
    protocol: draft.filter.protocol,
    remote_address: draft.filter.remote_address || '*',
    local_port: draft.filter.local_port || 0,
    remote_port: draft.filter.remote_port || 0,
    priority: draft.priority,
    expiry: 'preserve',
  };
}

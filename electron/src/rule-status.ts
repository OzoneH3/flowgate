import { matchesApplicationZone } from './application-zones';
import { zoneRuleLabel } from './network-zones';
import type { ClientState, Rule } from './protocol';
import type { Row } from './model';
export interface RuleStatus {
  available: boolean;
  reason: string;
  incoming: Rule[];
  outgoing: Rule[];
  now: number;
}
// Inventory only: never evaluate scopes, priority, flow matching, or permissions here.
export function ruleStatus(row: Row, state: ClientState): RuleStatus {
  const result: RuleStatus = {
    available: false,
    reason: '',
    incoming: [],
    outgoing: [],
    now: state.control.serverNow ?? NaN,
  };
  if (!state.control.connected || !state.control.rules || !Number.isFinite(result.now)) {
    result.reason =
      'Rule inventory unavailable: controller disconnected or no authoritative snapshot.';
    return result;
  }
  if (row.displayApplication || (row.socket?.display_application && row.socket.owners.length > 1)) {
    result.reason = 'Observation-only display association; no permission identity inferred.';
    return result;
  }
  const process = row.runtimeApplication ? {uid:row.runtimeApplication.uid,application:row.runtimeApplication.application} : row.inactive
    ? { uid: row.inactive.uid, application: { key: row.inactive.key, revision: row.inactive.revision } }
    : row.process ||
      (row.socket?.owners.length === 1
        ? state.observation.activity?.processes[row.socket.owners[0]]
        : undefined);
  if (!process?.application.key || !process.application.revision) {
    result.reason = 'No unambiguous application/revision/UID identity for rule inventory.';
    return result;
  }
  result.available = true;
  for (const rule of state.control.rules) {
    const f = rule.filter;
    if (
      (row.applicationZone && !matchesApplicationZone(f,row.applicationZone)) ||
      f.process ||
      f.application !== process.application.key ||
      f.revision !== process.application.revision ||
      f.uid !== process.uid
    )
      continue;
    if (f.direction === 'incoming') result.incoming.push(rule);
    if (f.direction === 'outgoing') result.outgoing.push(rule);
  }
  result.reason =
    'Listed scoped rules for this exact application/revision/UID; not a verdict for any connection. Policy precedence remains in Go.';
  return result;
}
export function ruleState(rule: Rule, now: number) {
  const expiry = rule.expires && !rule.expires.startsWith('0001-') ? Date.parse(rule.expires) : NaN;
  if (Number.isFinite(expiry) && expiry <= now) return 'expired';
  if (rule.disabled) return 'disabled';
  return rule.action === 'allow'
    ? 'allow'
    : rule.action === 'block'
      ? 'block'
      : rule.action === 'ask'
        ? 'ask'
        : 'unknown';
}
export function ruleDescription(rule: Rule, now: number) {
  const f = rule.filter;
  const preset = rule.preset
    ? `Essential · ${rule.preset.component} · local ${f.local_address || '*'} · interface ${f.interface_name || '*'}/${f.interface_index || '*'}${f.peer_service ? ` · local service ${f.peer_service.application} UID ${f.peer_service.uid}` : ''} · `
    : '';
  return `${preset}${zoneRuleLabel(rule)} · ${ruleState(rule, now)} ${rule.action} · ${f.direction} ${f.protocol} · remote ${f.remote_address || f.remote || 'any'} · local port ${f.local_port || 'any'} · remote port ${f.remote_port || 'any'} · expires ${rule.expires && !rule.expires.startsWith('0001-') ? rule.expires : 'never'} · ${rule.id}`;
}

// Describe stored filter constraints; this does not evaluate a connection or precedence.
export function configuredPolicy(rules: Rule[], now: number) {
  if (!rules.length) return 'No rule';
  const active = rules.filter((r) => ['allow', 'block', 'ask'].includes(ruleState(r, now)));
  if (!active.length)
    return rules.every((r) => ruleState(r, now) === 'expired')
      ? 'Expired'
      : rules.every((r) => ruleState(r, now) === 'disabled')
        ? 'Disabled'
        : 'Inactive · mixed';
  if (rules.length > 1)
    return new Set(active.map((r) => r.action)).size > 1
      ? `Mixed · ${rules.length}`
      : `Scoped · ${rules.length}`;
  const r = active[0],
    f = r.filter,
    broad = !f.remote && (!f.remote_address || f.remote_address === '*') && !f.local_port && !f.remote_port;
  const scope =
    broad && f.protocol === '*' ? 'app-wide' : broad ? f.protocol.toUpperCase() : 'scoped';
  return `${r.action === 'allow' ? 'Allow' : r.action === 'ask' ? 'Ask' : 'Block'} · ${scope}`;
}
// Compatibility inventory (no backend summary): only whole-target rules (any endpoint, all
// zones) form the node's own state; narrower rules are counted as "+N scoped", never its state.
export const wholeTarget = (r: Rule) => {
  const f = r.filter;
  return (
    !f.process &&
    !f.remote &&
    (!f.remote_address || f.remote_address === '*') &&
    !f.local_port &&
    !f.remote_port &&
    !f.network_zone &&
    !f.all_programs &&
    !f.interface_name &&
    !f.local_address
  );
};
export function ownConfigured(rules: Rule[], now: number) {
  const own = rules.filter(wholeTarget),
    scoped = rules.length - own.length,
    hint = scoped ? ` +${scoped} scoped` : '';
  if (!own.length) return { text: 'Not set' + hint, tone: 'none' as const, scoped };
  const states = new Set(own.map((r) => ruleState(r, now)));
  const s = states.size === 1 ? [...states][0] : 'mixed';
  const tone: 'allow' | 'block' | 'ask' | 'mixed' | 'unavailable' | 'off' =
    s === 'allow' || s === 'block' || s === 'ask' || s === 'mixed'
      ? s
      : s === 'unknown'
        ? 'unavailable'
        : 'off';
  return { text: configuredPolicy(own, now) + hint, tone, scoped };
}

// Exact stored configuration of a displayed app/zone filter, never an effective
// verdict. More than one rule always stays an explicit choice.
export function zoneConfigured(rules: Rule[], now: number) {
  if (!rules.length) return {text:'Not set',tone:'none' as const};
  if (rules.length>1) return {text:`Multiple · ${rules.length}`,tone:'mixed' as const};
  const state=ruleState(rules[0],now);
  return {text:state==='allow'?'Allow':state==='block'?'Deny':state==='ask'?'Ask':state==='disabled'?'Disabled':state==='expired'?'Expired':'Inactive',tone:state==='allow'?'allow' as const:state==='block'?'block' as const:state==='ask'?'ask' as const:'off' as const};
}

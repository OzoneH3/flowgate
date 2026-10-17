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
  if (row.displayApplication || row.socket?.display_application) {
    result.reason = 'Observation-only display association; no permission identity inferred.';
    return result;
  }
  const process =
    row.process ||
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
  return rule.action === 'allow' ? 'allow' : rule.action === 'block' ? 'block' : 'unknown';
}
export function ruleDescription(rule: Rule, now: number) {
  const f = rule.filter;
  return `${ruleState(rule, now)} ${rule.action} · ${f.direction} ${f.protocol} · remote ${f.remote_address || f.remote || 'any'} · local port ${f.local_port || 'any'} · remote port ${f.remote_port || 'any'} · expires ${rule.expires && !rule.expires.startsWith('0001-') ? rule.expires : 'never'} · ${rule.id}`;
}

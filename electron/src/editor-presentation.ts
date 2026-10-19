import { zoneLabel, zoneRuleLabel } from './network-zones';
import { targetLabel } from './process-rules';
import type { Rule } from './protocol';
// Display only, based on structured fields in the reviewed backend rule.
export function reviewedScope(rule: Rule): string {
  const f = rule.filter;
  const address = f.remote_address || f.remote || '*';
  return `${f.all_programs ? 'All programs · ' + (f.all_uids ? 'all users' : 'UID ' + f.uid) : targetLabel(f.process)} · ${zoneRuleLabel(rule)} · ${rule.action === 'allow' ? 'Allow' : 'Deny'} ${f.direction} ${f.protocol.toUpperCase()} connections · ${address === '*' ? 'any remote address' : 'remote ' + address} · ${f.local_port ? 'local port ' + f.local_port : 'any local port'} · ${f.remote_port ? 'remote port ' + f.remote_port : 'any remote port'}${rule.disabled ? ' · saved disabled' : ''}.`;
}
export function previewSeconds(expiry: number, now: number) {
  return Number.isFinite(expiry) && Number.isFinite(now)
    ? Math.max(0, Math.ceil((expiry - now) / 1000))
    : 0;
}

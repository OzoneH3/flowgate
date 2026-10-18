import type { Reply } from './protocol';
// Equality of complete authorized snapshots; never interprets per-rule versions as a global order.
export function inventoryStamp(
  r: Pick<
    Reply,
    | 'generation'
    | 'rules'
    | 'rule_states'
    | 'permissions'
    | 'enforcement'
    | 'capabilities'
    | 'network_zones'
    | 'read_only'
    | 'mode'
  >,
) {
  return JSON.stringify([
    r.generation,
    [...r.rules].sort((a, b) => a.id.localeCompare(b.id)),
    Object.entries(r.rule_states || {}).sort(([a], [b]) => a.localeCompare(b)),
    r.permissions,
    r.enforcement,
    r.capabilities,
    r.network_zones,
    r.read_only,
    r.mode,
  ]);
}

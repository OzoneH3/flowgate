import type { DirectionPolicy, PolicyRuleRef } from './policy';
// Presentation of a backend direction summary. Inventory only: no matching or precedence.
export type ChipTone = 'none' | 'allow' | 'block' | 'mixed' | 'off' | 'unavailable';
export interface RuleChip {
  glyph: string;
  text: string;
  tone: ChipTone;
  detail: string;
}
const protocolLabel = (r: PolicyRuleRef) =>
  r.scope.protocol === '*' ? 'TCP+UDP' : r.scope.protocol.toUpperCase();
export const endpointWide = (r: PolicyRuleRef) =>
  (!r.scope.remote_address || r.scope.remote_address === '*') &&
  !r.scope.remote &&
  !r.scope.local_port &&
  !r.scope.remote_port;
export const refState = (r: PolicyRuleRef) =>
  r.expired ? 'Expired' : r.disabled ? 'Disabled' : r.active ? 'Enabled' : 'Inactive';
export function shortScope(r: PolicyRuleRef) {
  const f = r.scope;
  const parts = [protocolLabel(r)];
  const address = f.remote_address && f.remote_address !== '*' ? f.remote_address : f.remote;
  parts.push(address ? address : 'any address');
  if (f.local_port) parts.push('local ' + f.local_port);
  if (f.remote_port) parts.push('remote port ' + f.remote_port);
  if (!f.local_port && !f.remote_port) parts.push('any port');
  return parts.join(' · ');
}
// compact: short table wording ("Block UDP"); full: sidebar wording ("Block · UDP +1 off").
export function ruleChip(
  d: DirectionPolicy | undefined,
  targetEnded = false,
  compact = false,
): RuleChip {
  const sep = compact ? ' ' : ' · ';
  if (!d) return { glyph: '', text: 'Unavailable', tone: 'unavailable', detail: '' };
  const detail = d.rules
    .map((r) => `${refState(r)} ${r.action === 'allow' ? 'Allow' : 'Block'} · ${shortScope(r)}`)
    .join('\n');
  if (d.configured === 'absent' || !d.rules.length)
    return { glyph: '', text: 'Not set', tone: 'none', detail: 'No explicit rule.' };
  const count = d.rules.length > 1 && !compact ? ` · ${d.rules.length}` : '';
  if (targetEnded)
    return {
      glyph: '○',
      text: (compact ? 'Ended' : 'Inactive · ended') + count,
      tone: 'off',
      detail,
    };
  const active = d.rules.filter((r) => r.active);
  if (d.configured === 'inactive_only' || !active.length) {
    const text = d.rules.every((r) => r.expired)
      ? 'Expired'
      : d.rules.every((r) => r.disabled)
        ? 'Disabled'
        : 'Inactive';
    return { glyph: '○', text: text + count, tone: 'off', detail };
  }
  const actions = new Set(active.map((r) => r.action));
  if (d.configured === 'mixed' || actions.size > 1) {
    const allow = active.filter((r) => r.action === 'allow').length;
    return {
      glyph: '±',
      text: compact ? 'Mixed' : `Mixed · ${allow} allow, ${active.length - allow} block`,
      tone: 'mixed',
      detail,
    };
  }
  const action = active[0].action === 'allow' ? 'allow' : 'block';
  const qualifier =
    d.configured === 'uniform'
      ? 'all'
      : active.length === 1
        ? endpointWide(active[0])
          ? protocolLabel(active[0])
          : 'scoped'
        : compact
          ? `×${active.length}`
          : `${active.length} rules`;
  const off = d.rules.length - active.length;
  return {
    glyph: action === 'allow' ? '✓' : '✕',
    text: `${action === 'allow' ? 'Allow' : 'Block'}${sep}${qualifier}${off && !compact ? ` +${off} off` : ''}`,
    tone: action,
    detail,
  };
}
export function renderChip(chip: RuleChip, prefix = '') {
  const frag = document.createDocumentFragment();
  if (prefix) {
    const p = document.createElement('span');
    p.className = 'chip-prefix';
    p.textContent = prefix;
    frag.append(p);
  }
  if (chip.glyph) {
    const g = document.createElement('span');
    g.className = 'chip-glyph chip-' + chip.tone;
    g.textContent = chip.glyph;
    g.setAttribute('aria-hidden', 'true');
    frag.append(g);
  }
  const t = document.createElement('span');
  t.className = 'chip-text';
  t.textContent = chip.text;
  frag.append(t);
  return frag;
}

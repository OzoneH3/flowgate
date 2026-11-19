import { accountLabel } from './accounts';
import { zoneLabel } from './network-zones';
import type { DirectionPolicy, PolicyRuleRef } from './policy';
// Presentation of a backend direction summary. Inventory only: no matching or precedence.
export type ChipTone = 'none' | 'allow' | 'block' | 'ask' | 'mixed' | 'off' | 'unavailable';
// NetLimiter Ask: a stored Blocker action with its own indicator (never Deny/disabled/unknown).
export const ASK_TOOLTIP = 'Ask: prompt for each new connection';
export const actionGlyph = (action: string) =>
  action === 'allow' ? '✓' : action === 'block' ? '✕' : '?';
export interface RuleChip {
  glyph: string;
  text: string;
  tone: ChipTone;
  detail: string;
  // Rules restricted by endpoint, protocol or zone: listed separately, never the cell state.
  scoped?: number;
}
const protocolLabel = (r: PolicyRuleRef) =>
  r.scope.protocol === '*' ? 'TCP+UDP' : r.scope.protocol.toUpperCase();
export const endpointWide = (r: PolicyRuleRef) =>
  (!r.scope.remote_address || r.scope.remote_address === '*') &&
  !r.scope.remote &&
  !r.scope.local_port &&
  !r.scope.remote_port;
// Presentation only: the API action stays 'block'; the reference calls it Deny.
export const actionWord = (action: string) =>
  action === 'allow'
    ? 'Allow'
    : action === 'block'
      ? 'Deny'
      : action
        ? action.charAt(0).toUpperCase() + action.slice(1)
        : 'Unknown';
export const knownAction = (action: string) => action === 'allow' || action === 'block';
// Presentable stored actions (Ask is shown as Ask even when this daemon cannot write it).
export const storedAction = (action: string) => knownAction(action) || action === 'ask';
export const refState = (r: PolicyRuleRef) =>
  r.expired ? 'Expired' : r.disabled ? 'Disabled' : r.stored_only ? 'Enabled (stored)' : r.active ? 'Enabled' : 'Inactive';
export function shortScope(r: PolicyRuleRef) {
  const f = r.scope;
  const parts = [
    protocolLabel(r),
    zoneLabel(f.network_zone),
    ...(f.all_programs
      ? [f.all_uids ? 'all programs / all users' : 'all programs / ' + accountLabel(f.uid)]
      : []),
  ];
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
    .map((r) => `${refState(r)} ${actionWord(r.action)} · ${shortScope(r)}`)
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
    const allow = active.filter((r) => r.action === 'allow').length,
      deny = active.filter((r) => r.action === 'block').length,
      ask = active.filter((r) => r.action === 'ask').length,
      other = active.length - allow - deny - ask;
    return {
      glyph: '±',
      text: compact
        ? 'Mixed'
        : `Mixed · ${allow} allow, ${deny} deny${ask ? `, ${ask} ask` : ''}${other ? `, ${other} other` : ''}`,
      tone: 'mixed',
      detail,
    };
  }
  // Only explicit allow/block are presented as Allow/Deny; Ask has its own indicator; anything
  // else stays neutral and read-only rather than being mislabelled.
  if (!knownAction(active[0].action))
    return active[0].action === 'ask'
      ? {
          glyph: '?',
          text: `Ask${active.length === 1 && !endpointWide(active[0]) ? sep + 'scoped' : ''}`,
          tone: 'ask',
          detail: ASK_TOOLTIP + '\n' + detail,
        }
      : {
          glyph: '?',
          text: `${actionWord(active[0].action)}${compact ? '' : ' · unsupported here'}`,
          tone: 'unavailable',
          detail,
        };
  const action = active[0].action;
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
    text: `${actionWord(action)}${sep}${qualifier}${off && !compact ? ` +${off} off` : ''}`,
    tone: action,
    detail,
  };
}
// Whole-target shape: backends with application-policy-v1 classify it (kind application = TCP+UDP,
// any address/ports, all zones); older ones by shape only (any endpoint, all zones, any protocol
// choice, since they stored one protocol per rule).
export const ownShape = (r: PolicyRuleRef) =>
  r.kind
    ? r.kind === 'application'
    : endpointWide(r) && !r.scope.network_zone && !r.scope.all_programs;
// NetLimiter Rule Status: the node's OWN configured rule, not the effective result for traffic.
// Scoped rules only add a "+N scoped" hint; one narrow Allow never shows as a green application Allow.
export function ownRuleChip(
  d: DirectionPolicy | undefined,
  targetEnded = false,
  compact = false,
): RuleChip {
  if (!d) return { glyph: '', text: 'Unavailable', tone: 'unavailable', detail: '' };
  const sep = compact ? ' ' : ' · ';
  const line = (r: PolicyRuleRef) => `${refState(r)} ${actionWord(r.action)} · ${shortScope(r)}`;
  const legacy = d.application_rule === undefined;
  const scopedRefs = d.rules.filter((r) => !ownShape(r) && r.id !== d.application_rule?.id);
  const scoped = legacy ? scopedRefs.length : (d.scoped_rules ?? scopedRefs.length);
  const hint = scoped ? `${sep}+${scoped} scoped` : '';
  const scopedDetail = scopedRefs.length
    ? ['Scoped rules (listed separately, not this cell):', ...scopedRefs.map(line)]
    : [];
  if (legacy) {
    // Older daemon summary: only whole-target rules (per-protocol allowed) form the state.
    const wide = d.rules.filter(ownShape);
    const base = ruleChip(
      {
        ...d,
        rules: wide,
        configured: !wide.length
          ? 'absent'
          : !wide.some((r) => r.active)
            ? 'inactive_only'
            : d.configured === 'uniform' && !scoped
              ? 'uniform'
              : 'scoped',
      },
      targetEnded,
      compact,
    );
    return {
      ...base,
      text: base.text + hint,
      detail: [...wide.map(line), ...scopedDetail].join('\n') || base.detail,
      scoped,
    };
  }
  const ref = d.application_rule;
  const own = ref ? d.rules.find((r) => r.id === ref.id) || ref : undefined;
  const detail = [...(own ? ['Own rule: ' + line(own)] : ['No own rule.']), ...scopedDetail].join(
    '\n',
  );
  if (!own) return { glyph: '', text: 'Not set' + hint, tone: 'none', detail, scoped };
  const off = (text: string): RuleChip => ({
    glyph: '○',
    text: text + hint,
    tone: 'off',
    detail,
    scoped,
  });
  if (targetEnded) return off(compact ? 'Ended' : 'Inactive · ended');
  if (own.expired) return off('Expired');
  if (own.disabled) return off('Disabled');
  if (own.action === 'ask')
    return {
      glyph: '?',
      text: 'Ask' + hint,
      tone: 'ask',
      detail: ASK_TOOLTIP + '\n' + detail,
      scoped,
    };
  if (!knownAction(own.action))
    return {
      glyph: '?',
      text: `${actionWord(own.action)}${compact ? '' : ' · unsupported here'}${hint}`,
      tone: 'unavailable',
      detail,
      scoped,
    };
  if (!own.active) return off('Inactive');
  return {
    glyph: own.action === 'allow' ? '✓' : '✕',
    text: actionWord(own.action) + hint,
    tone: own.action as ChipTone,
    detail,
    scoped,
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

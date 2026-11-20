import type { Rule } from './protocol';
import { ruleState } from './rule-status';
import { confirmRuleDelete, openRule } from './workflows';

// Rules of an application that is not running (Activity › not running). Editing
// a stored rule needs no live process: each change is reviewed by the backend
// (draft → preview → save, pinned to the rule's version) exactly like the quick
// setter's in-place edit. New rules reuse a stored application's exact identity.

export interface InactiveRulesOptions {
  label: string;
  presenceLabel?: string;
  direction: 'incoming' | 'outgoing';
  rules: Rule[];
  generation: string;
  now: number;
  canManage: boolean;
  canDelete: boolean;
  askWritable: boolean;
  message: (text: string) => void;
  // rule-from-basis-v1: any stored rule of this application identity; a new
  // rule reuses exactly its identity (application, revision, UID).
  basisRuleId?: string;
  networkZone?: 'local' | 'internet';
}

type Action = 'allow' | 'block' | 'ask';
const word = (a: string) => (a === 'allow' ? 'Allow' : a === 'block' ? 'Deny' : a === 'ask' ? 'Ask' : a);
const glyph = (a: string) => (a === 'allow' ? '✓' : a === 'block' ? '✕' : '?');

function el<K extends keyof HTMLElementTagNameMap>(tag: K, text = '', className = '') {
  const x = document.createElement(tag);
  if (text) x.textContent = text;
  if (className) x.className = className;
  return x;
}

function scopeText(r: Rule) {
  const f = r.filter;
  const parts = [
    f.protocol === '*' ? 'TCP + UDP' : f.protocol.toUpperCase(),
    f.remote_address && f.remote_address !== '*' ? 'remote ' + f.remote_address : f.remote ? 'remote ' + f.remote : 'any endpoint',
    f.local_port ? 'local port ' + f.local_port : '',
    f.remote_port ? 'remote port ' + f.remote_port : '',
    f.network_zone ? f.network_zone + ' network' : '',
    f.process ? 'one process instance' : '',
    r.expires && !r.expires.startsWith('0001-') ? 'until ' + new Date(r.expires).toLocaleString() : '',
  ];
  return parts.filter(Boolean).join(' · ');
}

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

/** Reviewed in-place change of one stored rule (action and/or enabled). */
export async function changeStoredRule(rule: Rule, action: Action, disabled: boolean): Promise<string> {
  const draft = await window.flowgate.ruleDraft({ id: rule.id });
  if (draft.rule.id !== rule.id || draft.rule.version !== rule.version)
    throw Error('This rule changed since it was listed; nothing was saved.');
  // The draft is the authoritative, normalized scope; the listed rule may be in a legacy format.
  const d = draft.rule;
  const preview = await window.flowgate.rulePreview({
    token: draft.token,
    action,
    protocol: d.filter.protocol,
    remote_address: d.filter.remote_address || '*',
    local_port: d.filter.local_port || 0,
    remote_port: d.filter.remote_port || 0,
    priority: d.priority,
    disabled,
    expiry: 'preserve',
  });
  const v = preview.verifiedRule;
  if (!v || v.action !== action || v.disabled !== disabled || v.schema !== editedSchema(d) || scopeKey(v) !== scopeKey(d))
    throw Error('The backend reviewed a different change than requested; nothing was saved.');
  const result = await window.flowgate.ruleSave(preview.receipt);
  if (result.phase === 'acknowledged') return `${word(action)}${disabled ? ' (disabled)' : ''} saved for this rule.`;
  if (result.phase === 'unknown') return 'Save result unknown; check Rules before changing it again.';
  throw Error(result.message || 'Not saved.');
}

/** Reviewed creation of a new application rule for the basis rule's identity. */
export async function addStoredRule(basisId: string, direction: 'incoming' | 'outgoing', action: Action, networkZone?: 'local' | 'internet'): Promise<string> {
  const draft = await window.flowgate.ruleDraft({ basis: { rule: basisId, direction, ...(networkZone ? { networkZone } : {}) } });
  const preview = await window.flowgate.rulePreview({
    token: draft.token,
    action,
    protocol: '*',
    remote_address: '*',
    local_port: 0,
    remote_port: 0,
    priority: draft.rule.priority,
    disabled: false,
    expiry: 'permanent',
    network_zone: networkZone || '',
  });
  const v = preview.verifiedRule;
  const f = draft.rule.filter;
  if (
    !v || v.action !== action || v.disabled || v.filter.direction !== direction || v.filter.process ||
    v.filter.application !== f.application || v.filter.revision !== f.revision || v.filter.uid !== f.uid || v.filter.network_zone !== f.network_zone || v.filter.zone_model !== f.zone_model
  )
    throw Error('The backend reviewed a different rule than requested; nothing was saved.');
  const result = await window.flowgate.ruleSave(preview.receipt);
  if (result.phase === 'acknowledged') return `${word(action)} rule added (${direction === 'incoming' ? 'In' : 'Out'}, TCP + UDP, ${networkZone || 'all networks'}).`;
  if (result.phase === 'unknown') return 'Save result unknown; check Rules before adding it again.';
  throw Error(result.message || 'Not saved.');
}

let open: { root: HTMLElement; close: () => void } | undefined;

export function closeInactiveRules() {
  open?.close();
}

/** Popup beneath an In/Out cell of a not-running application. */
export function openInactiveRules(anchor: HTMLElement, o: InactiveRulesOptions) {
  closeInactiveRules();
  const root = el('div', '', 'quick-popup inactive-rules');
  root.setAttribute('role', 'dialog');
  root.setAttribute('aria-label', `${o.label} · ${o.direction} rules`);
  root.tabIndex = -1;
  root.append(el('div', `${o.label} · ${o.direction === 'incoming' ? 'In' : 'Out'} · ${o.presenceLabel || 'not running'}`, 'inactive-rules-title'));
  const status = el('p', '', 'inactive-rules-status');
  status.setAttribute('role', 'status');
  let busy = false;
  const run = async (what: () => Promise<string>) => {
    if (busy) return;
    busy = true;
    root.classList.add('busy');
    status.textContent = 'Saving…';
    try {
      const text = await what();
      o.message(text);
      close();
    } catch (e) {
      status.textContent = String((e as Error)?.message ?? e).replace(/^Error invoking remote method '[^']*': /, '').replace(/^Error: /, '');
    } finally {
      busy = false;
      root.classList.remove('busy');
    }
  };
  if (!o.rules.length) root.append(el('p', 'No rule in this direction yet.', 'inactive-rules-empty'));
  for (const rule of o.rules) {
    const line = el('div', '', 'qs-row inactive-rule');
    const state = ruleState(rule, o.now);
    const expired = state === 'expired';
    const editable = o.canManage && !expired && ['allow', 'block', 'ask'].includes(rule.action) && !rule.preset;
    const enabled = el('input');
    enabled.type = 'checkbox';
    enabled.checked = !rule.disabled;
    enabled.disabled = !editable;
    enabled.title = rule.disabled ? 'Enable this rule' : 'Disable this rule';
    enabled.setAttribute('aria-label', 'Rule enabled');
    enabled.onchange = () => void run(() => changeStoredRule(rule, rule.action as Action, !enabled.checked));
    line.append(enabled);
    const actions: Action[] = rule.action === 'ask' || o.askWritable ? ['ask', 'allow', 'block'] : ['allow', 'block'];
    for (const action of actions) {
      const b = el('button', '', `qs-action qs-${action}`);
      b.type = 'button';
      b.append(el('span', glyph(action), 'blocker-glyph tone-' + action), ' ' + word(action));
      const current = rule.action === action;
      if (current) b.classList.add('current');
      b.setAttribute('aria-pressed', String(current));
      b.disabled = !editable || current;
      b.title = current ? `Current action: ${word(action)}.` : `Set ${word(action)}. Keep scope and expiry.`;
      b.onclick = () => void run(() => changeStoredRule(rule, action, rule.disabled));
      line.append(b);
    }
    const links = el('span', '', 'qs-row-links');
    const advanced = el('button', 'Advanced', 'link-button');
    advanced.type = 'button';
    advanced.disabled = !o.canManage;
    advanced.onclick = () => {
      close();
      void openRule({ id: rule.id }, { activity: true });
    };
    const remove = el('button', 'Delete', 'link-button');
    remove.type = 'button';
    remove.disabled = !o.canManage || !o.canDelete;
    remove.onclick = () => {
      close();
      confirmRuleDelete(rule, o.generation);
    };
    links.append(advanced, remove);
    line.append(links);
    const scope = el('div', `${scopeText(rule)}${expired ? ' · expired' : rule.disabled ? ' · disabled' : ''}`, 'inactive-rule-scope');
    const wrap = el('div', '', 'inactive-rule-wrap');
    wrap.append(line, scope);
    root.append(wrap);
  }
  if (o.basisRuleId) {
    // Add a new rule for exactly this program's identity (same file version and user).
    const add = el('div', '', 'qs-row inactive-rule-add');
    add.append(el('span', 'Add a rule:', 'inactive-rule-add-label'));
    const actions: Action[] = o.askWritable ? ['ask', 'allow', 'block'] : ['allow', 'block'];
    for (const action of actions) {
      const b = el('button', '', `qs-action qs-${action}`);
      b.type = 'button';
      b.append(el('span', glyph(action), 'blocker-glyph tone-' + action), ' ' + word(action));
      b.disabled = !o.canManage;
      b.title = `${word(action)} · this app · ${o.direction} TCP/UDP · ${o.networkZone || 'all networks'}`;
      b.onclick = () => void run(() => addStoredRule(o.basisRuleId!, o.direction, action, o.networkZone));
      add.append(b);
    }
    const advanced = el('button', 'Advanced…', 'link-button');
    advanced.type = 'button';
    advanced.disabled = !o.canManage;
    advanced.title = 'New rule with protocol, address, port and lifetime';
    advanced.onclick = () => {
      close();
      void openRule({ basis: { rule: o.basisRuleId!, direction: o.direction, ...(o.networkZone ? { networkZone: o.networkZone } : {}) } }, { activity: true, networkZone: o.networkZone });
    };
    const links = el('span', '', 'qs-row-links');
    links.append(advanced);
    add.append(links);
    root.append(add);
  }
  root.append(status);
  document.body.append(root);
  const a = anchor.getBoundingClientRect();
  const w = root.getBoundingClientRect();
  root.style.left = Math.max(4, Math.min(a.left, innerWidth - w.width - 4)) + 'px';
  root.style.top = (a.bottom + 4 + w.height > innerHeight ? Math.max(4, a.top - w.height - 4) : a.bottom + 4) + 'px';
  const outside = (e: PointerEvent) => {
    if (!root.contains(e.target as Node) && e.target !== anchor) close();
  };
  const key = (e: KeyboardEvent) => {
    if (e.key === 'Escape') close();
  };
  const close = () => {
    document.removeEventListener('pointerdown', outside, true);
    document.removeEventListener('keydown', key, true);
    root.remove();
    if (open?.root === root) open = undefined;
  };
  document.addEventListener('pointerdown', outside, true);
  document.addEventListener('keydown', key, true);
  open = { root, close };
  root.focus({ preventScroll: true });
}

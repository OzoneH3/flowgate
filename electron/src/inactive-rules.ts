import type { Rule } from './protocol';
import { ruleState } from './rule-status';
import { confirmRuleDelete, openRule } from './workflows';

// Rules of an application that is no observed sockets (Activity › no observed sockets). Editing
// a stored rule needs no live process: each change is reviewed by the backend
// (draft → preview → save, pinned to the rule's version) exactly like the quick
// setter's in-place edit. New rules still need the running, verified program.

export interface InactiveRulesOptions {
  label: string;
  direction: 'incoming' | 'outgoing';
  rules: Rule[];
  generation: string;
  now: number;
  canManage: boolean;
  canDelete: boolean;
  askWritable: boolean;
  message: (text: string) => void;
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

/** Reviewed in-place change of one stored rule (action and/or enabled). */
export async function changeStoredRule(rule: Rule, action: Action, disabled: boolean): Promise<string> {
  const draft = await window.flowgate.ruleDraft({ id: rule.id });
  if (draft.rule.id !== rule.id || draft.rule.version !== rule.version)
    throw Error('This rule changed since it was listed; nothing was saved.');
  const preview = await window.flowgate.rulePreview({
    token: draft.token,
    action,
    protocol: rule.filter.protocol,
    remote_address: rule.filter.remote_address || '*',
    local_port: rule.filter.local_port || 0,
    remote_port: rule.filter.remote_port || 0,
    priority: rule.priority,
    disabled,
    expiry: 'preserve',
  });
  const v = preview.verifiedRule;
  if (!v || v.id !== rule.id || v.action !== action || v.disabled !== disabled || v.filter.direction !== rule.filter.direction)
    throw Error('The backend reviewed a different change than requested; nothing was saved.');
  const result = await window.flowgate.ruleSave(preview.receipt);
  if (result.phase === 'acknowledged') return `${word(action)}${disabled ? ' (disabled)' : ''} saved for this rule.`;
  if (result.phase === 'unknown') return 'Save result unknown; check Rules before changing it again.';
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
  root.append(el('div', `${o.label} · ${o.direction === 'incoming' ? 'In' : 'Out'} · no observed sockets`, 'inactive-rules-title'));
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
  if (!o.rules.length) root.append(el('p', 'No rule in this direction. New rules need the running program.', 'inactive-rules-empty'));
  for (const rule of o.rules) {
    const line = el('div', '', 'qs-row inactive-rule');
    const state = ruleState(rule, o.now);
    const expired = state === 'expired';
    const editable = o.canManage && !expired && ['allow', 'block', 'ask'].includes(rule.action) && !rule.preset;
    const enabled = el('input');
    enabled.type = 'checkbox';
    enabled.checked = !rule.disabled;
    enabled.disabled = !editable;
    enabled.title = rule.disabled ? 'Enable this rule' : 'Disable this rule (kept, not deleted)';
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
      b.title = current ? `Current action: ${word(action)}.` : `Change this rule to ${word(action)}; scope and lifetime stay the same.`;
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

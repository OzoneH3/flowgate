import { PROCESS_CAPABILITY } from './process-rules';
import type { Attempt, ClientState, ObservedSource, Rule, RuleEdit, RuleSource } from './protocol';
import { canManageRules } from './protocol';
import type { Row } from './model';
import {
  POLICY_CAPABILITY,
  authoritativePolicy,
  authoritativeProcessPolicy,
  type PolicyRuleRef,
  type DirectionPolicy,
} from './policy';
import { ruleStatus, ruleState } from './rule-status';
import { ruleChip, renderChip, refState, shortScope } from './rule-chip';
import { reviewedScope, previewSeconds } from './editor-presentation';
import { initiationPresentation } from './initiation';
import { openRule, confirmRuleDelete, type EditorOptions } from './workflows';
type Direction = 'incoming' | 'outgoing';
type Tier = 'process' | 'application';
const directions: Direction[] = ['incoming', 'outgoing'];
const el = <K extends keyof HTMLElementTagNameMap>(tag: K, text = '', cls = '') => {
  const n = document.createElement(tag);
  n.textContent = text;
  n.className = cls;
  return n;
};
const button = (text: string, focus: string, cls = '') => {
  const b = el('button', text, cls);
  b.type = 'button';
  b.dataset.focus = focus;
  return b;
};
const short = (d: Direction) => (d === 'incoming' ? 'In' : 'Out');
export function scopeLabel(ref: PolicyRuleRef) {
  const f = ref.scope;
  const protocol = f.protocol === '*' ? 'TCP + UDP' : f.protocol.toUpperCase();
  return `${protocol} · remote ${f.remote_address && f.remote_address !== '*' ? f.remote_address : f.remote || 'any address'} · local port ${f.local_port || 'any'} · remote port ${f.remote_port || 'any'}`;
}
export function selectionInventory(row: Row, state: ClientState) {
  const authoritative = !!state.control.capabilities?.includes(POLICY_CAPABILITY);
  const result = authoritativePolicy(row, state),
    app = result.application;
  const processPolicy = state.control.capabilities?.includes(PROCESS_CAPABILITY)
    ? authoritativeProcessPolicy(row, state)
    : undefined;
  const fallback = ruleStatus(row, state);
  const rules: PolicyRuleRef[] = authoritative
    ? directions.flatMap((d) => [
        ...(processPolicy?.[d].rules || []),
        ...(processPolicy
          ? processPolicy[d === 'incoming' ? 'application_incoming' : 'application_outgoing'].rules
          : app?.[d].rules || []),
      ])
    : directions.flatMap((d) =>
        fallback[d].map((r) => ({
          id: r.id,
          version: String(r.version),
          action: r.action,
          priority: r.priority,
          scope: r.filter,
          disabled: r.disabled,
          expired: ruleState(r, fallback.now) === 'expired',
          active: ['allow', 'block'].includes(ruleState(r, fallback.now)),
          expires: r.expires,
        })),
      );
  const candidate =
    (app || processPolicy) &&
    row.rows.find(
      (s) =>
        s.owners.length === 1 &&
        s.ownership_category === 'visible-holder' &&
        (app?.process_ids.includes(s.owners[0]) || processPolicy?.process_id === s.owners[0]) &&
        (!row.process || row.kind === 'application' || row.process.id === s.owners[0]),
    );
  return {
    authoritative,
    app,
    processPolicy,
    rules,
    available: authoritative ? !!app || !!processPolicy : fallback.available,
    complete: authoritative && !!state.control.policy?.complete,
    reason: authoritative
      ? result.reason
      : 'Compatibility inventory: listed exact-identity rules; no backend summary.',
    candidate,
    fallback,
  };
}
type Inventory = ReturnType<typeof selectionInventory>;
// One inline backend review at a time. Preview persists nothing; Save is the acknowledgement.
interface Pending {
  seq: number;
  rowId: string;
  rowLabel: string;
  anchor: string;
  title: string;
  phase: 'previewing' | 'review' | 'expired' | 'saving' | 'unknown' | 'error';
  receipt?: string;
  scope?: string;
  lifetime?: string;
  enforcement?: string;
  expiresAt?: number;
  message?: string;
  reconcile?: string;
  retry?: () => void;
  advanced?: () => void;
}
interface Setter {
  direction: Direction;
  tier: Tier;
  mode: 'auto' | 'new';
}
export class ActivityPolicy {
  private row?: Row;
  private state?: ClientState;
  private signature = '';
  private setter?: Setter;
  private saved = '';
  private pending?: Pending;
  private seq = 0;
  private timer?: ReturnType<typeof setInterval>;
  private skew = 0;
  private newValues = new Map<string, { protocol: string; expiry: 'hour' | 'permanent' }>();
  constructor(private host: HTMLElement) {
    host.addEventListener('keydown', (event) => {
      if (event.key !== 'Escape') return;
      if (this.pending && ['review', 'expired', 'error'].includes(this.pending.phase)) {
        event.stopPropagation();
        this.discard();
      } else if (this.setter && !this.pending) {
        event.stopPropagation();
        const { direction, tier } = this.setter;
        this.setter = undefined;
        this.refresh();
        host.querySelector<HTMLElement>(`[data-focus="cell:${tier}:${direction}"]`)?.focus();
      }
    });
    window.addEventListener('activity-rule-saved', (e) => {
      this.saved = (e as CustomEvent<string>).detail;
      this.refresh();
    });
  }
  private refresh() {
    this.signature = '';
    if (this.state) this.update(this.row, this.state);
  }
  private defaultTier(): Tier {
    return this.row &&
      this.row.kind !== 'application' &&
      this.state?.control.capabilities?.includes(PROCESS_CAPABILITY)
      ? 'process'
      : 'application';
  }
  activate(direction: Direction, tier = this.defaultTier()) {
    if (!this.row || !this.state) return;
    if (this.pending && this.pending.phase !== 'error') {
      this.host.querySelector<HTMLElement>('.inline-review')?.focus();
      return;
    }
    this.pending = undefined;
    this.setter = { direction, tier, mode: 'auto' };
    this.refresh();
    // Focus the group, not an action: the key that opened the setter must not also trigger it.
    this.host.querySelector<HTMLElement>('.activity-quick')?.focus({ preventScroll: true });
    this.host.querySelector('.activity-quick')?.scrollIntoView({ block: 'nearest' });
  }
  update(row: Row | undefined, state: ClientState) {
    if (this.row?.id !== row?.id) {
      this.setter = undefined;
      if (this.pending && !['saving', 'unknown'].includes(this.pending.phase))
        this.pending = undefined;
    }
    this.row = row;
    this.state = state;
    if (Number.isFinite(state.control.serverNow)) this.skew = state.control.serverNow! - Date.now();
    this.host.hidden = !row || row.kind === 'overview';
    if (this.host.hidden || !row) return;
    const inv = selectionInventory(row, state),
      c = state.control;
    const signature = JSON.stringify([
      row.id,
      row.process?.id,
      row.socket?.initiation,
      inv.rules,
      inv.available,
      inv.complete,
      inv.reason,
      inv.processPolicy,
      inv.app?.incoming,
      inv.app?.outgoing,
      inv.candidate?.id,
      canManageRules(c),
      c.generation,
      c.connected,
      c.enforcement,
      c.rule_states,
      c.capabilities,
      this.setter,
      this.saved,
      this.pending && { ...this.pending, retry: 0, advanced: 0 },
    ]);
    if (signature === this.signature) return;
    this.signature = signature;
    const active = document.activeElement as HTMLElement | null;
    const focusKey = active && this.host.contains(active) ? active.dataset.focus : undefined;
    const oldScroll = this.host.querySelector('.activity-rule-list')?.scrollTop || 0;
    const fragment = document.createDocumentFragment();
    fragment.append(this.header());
    if (this.pending && this.pending.rowId !== row.id)
      fragment.append(this.review(`Unresolved save · ${this.pending.rowLabel}`));
    fragment.append(this.context(row, inv), this.matrix(row, inv));
    if (!inv.available) {
      fragment.append(el('p', inv.reason, 'activity-policy-note'));
      // Keep an open setter/draft through transient association gaps; actions stay disabled.
      if (this.setter) fragment.append(this.quickSetter(inv));
      else if (this.pending?.rowId === row.id) fragment.append(this.review());
    } else {
      if (!inv.complete)
        fragment.append(
          el(
            'p',
            inv.authoritative
              ? 'Partial policy batch · some rules may be unavailable.'
              : inv.reason,
            'activity-policy-note',
          ),
        );
      if (this.setter) fragment.append(this.quickSetter(inv));
      fragment.append(this.ruleList(row, inv));
      if (!canManageRules(c))
        fragment.append(el('p', 'Read-only rule access.', 'activity-policy-note'));
      fragment.append(this.details(inv));
    }
    this.host.replaceChildren(fragment);
    const list = this.host.querySelector('.activity-rule-list');
    if (list) list.scrollTop = oldScroll;
    if (focusKey)
      this.host
        .querySelector<HTMLElement>(`[data-focus="${CSS.escape(focusKey)}"]`)
        ?.focus({ preventScroll: true });
    this.tick();
  }
  private header() {
    const c = this.state!.control;
    const head = el('div', '', 'rule-status-head');
    head.append(el('h3', 'Rules', 'info-section-title'));
    const covered = c.enforcement?.state === 'active';
    const badge = el(
      'span',
      !c.connected
        ? 'Controller disconnected'
        : c.enforcement?.state === 'stopped'
          ? 'Stored only · firewall stopped'
          : covered
            ? 'Firewall active'
            : `Firewall ${c.enforcement?.state || 'state unknown'}`,
      'enforcement-badge ' + (covered ? 'enforced' : 'stored'),
    );
    badge.title = covered
      ? 'Enforcement is active; per-direction coverage is listed in details.'
      : 'Rules are stored and editable but do not currently protect connections.';
    head.append(badge);
    return head;
  }
  private context(row: Row, inv: Inventory) {
    const box = el('div', '', 'rule-status-context');
    const p = inv.processPolicy;
    if (row.kind === 'socket' && row.socket) {
      const d = initiationPresentation(row.socket);
      const line = el('p', '', 'rule-connection-line');
      const g = el('span', d.glyph, 'connection-direction ' + d.className);
      g.setAttribute('aria-hidden', 'true');
      line.append(
        g,
        document.createTextNode(
          `This connection · ${d.label} · ${row.socket.socket.protocol.toUpperCase()}${row.socket.owners.length === 1 ? '' : ' · shared holder'}`,
        ),
      );
      line.title = d.title;
      box.append(line);
    }
    if (p)
      box.append(
        el(
          'p',
          p.state === 'inactive'
            ? `PID ${p.target.pid} · process ended — its rules are inactive and never move to another process`
            : `PID ${p.target.pid} · live instance · process rules last until it exits`,
          'activity-policy-note' + (p.state === 'inactive' ? ' inactive-target' : ''),
        ),
      );
    return box;
  }
  private tierSummary(inv: Inventory, tier: Tier, d: Direction): DirectionPolicy | undefined {
    if (tier === 'process') return inv.processPolicy?.[d];
    return inv.processPolicy
      ? inv.processPolicy[d === 'incoming' ? 'application_incoming' : 'application_outgoing']
      : inv.app?.[d];
  }
  private matrix(row: Row, inv: Inventory) {
    const c = this.state!.control;
    const table = el('table', '', 'info-rule-matrix');
    table.setAttribute('aria-label', 'Rule status by target and initiation direction');
    const connection =
      row.kind === 'socket' && row.socket ? initiationPresentation(row.socket).direction : '';
    const head = el('tr');
    head.append(el('th', 'Target'));
    for (const d of directions) {
      const th = el('th', d === 'incoming' ? 'In' : 'Out');
      th.title = `${d === 'incoming' ? 'Incoming' : 'Outgoing'}: who initiated the connection, not upload/download.`;
      if (connection === d) th.classList.add('connection-column');
      head.append(th);
    }
    table.append(head);
    const tiers: Tier[] =
      c.capabilities?.includes(PROCESS_CAPABILITY) &&
      (row.kind === 'process' || (row.kind === 'socket' && row.socket?.owners.length === 1))
        ? ['process', 'application']
        : ['application'];
    for (const tier of tiers) {
      const tr = el('tr', '', 'tier-' + tier);
      const label = el(
        'th',
        tier === 'process'
          ? 'This process'
          : row.kind === 'application'
            ? 'Application'
            : tiers.length > 1
              ? 'App fallback'
              : 'Application',
      );
      label.scope = 'row';
      label.title =
        tier === 'process'
          ? 'Rules bound to this one backend-verified process instance. They are checked before application rules.'
          : 'Rules for this executable revision and user, covering all its processes. Used when no process rule matches.';
      tr.append(label);
      for (const d of directions) {
        const summary =
          inv.available || tier === 'process' ? this.tierSummary(inv, tier, d) : undefined;
        const chip =
          !summary && tier === 'application' && inv.available && !inv.authoritative
            ? undefined
            : ruleChip(summary, tier === 'process' && inv.processPolicy?.state === 'inactive');
        const td = el('td');
        const b = button('', `cell:${tier}:${d}`, 'rule-cell');
        if (chip) {
          b.append(renderChip(chip));
          b.classList.add('tone-' + chip.tone);
          b.title = `${short(d)} · ${label.textContent}\n${chip.detail}${summary ? '\n' + summary.reason : ''}`;
        } else {
          const count = inv.fallback[d].length;
          b.textContent = count ? `${count} listed` : 'Not set';
          b.title = 'Compatibility inventory; no backend summary.';
        }
        const open = this.setter?.direction === d && this.setter.tier === tier;
        b.setAttribute('aria-expanded', String(open));
        if (open) b.classList.add('open');
        b.setAttribute(
          'aria-label',
          `${label.textContent} ${d}: ${b.textContent}. Open quick setter.`,
        );
        b.disabled = !inv.available && tier === 'application';
        b.onclick = () => (open ? this.close() : this.activate(d, tier));
        if (tier === 'process') b.classList.add('sidebar-process-policy');
        else b.classList.add('sidebar-policy');
        b.dataset.direction = d;
        td.append(b);
        tr.append(td);
      }
      table.append(tr);
    }
    return table;
  }
  private close() {
    if (this.pending && this.pending.phase !== 'error') return;
    this.pending = undefined;
    this.setter = undefined;
    this.refresh();
  }
  private applicable(inv: Inventory, d: Direction, tier: Tier) {
    return inv.rules.filter(
      (r) => r.scope.direction === d && (tier === 'process') === !!r.scope.process,
    );
  }
  private blockReason(inv: Inventory, tier: Tier): string {
    const c = this.state!.control;
    if (!canManageRules(c)) return 'Read-only: this connection cannot change rules.';
    if (!inv.available) return inv.reason;
    if (tier === 'process' && (!inv.processPolicy || inv.processPolicy.state !== 'active'))
      return (
        inv.processPolicy?.reason ||
        'This process identity is unsupported or unavailable; no application-wide substitute is made.'
      );
    return '';
  }
  private quickSetter(inv: Inventory) {
    const { direction, tier, mode } = this.setter!,
      row = this.row!;
    const box = el('section', '', `activity-quick caret-${direction}`);
    box.tabIndex = -1;
    box.dataset.focus = 'quick';
    box.setAttribute('role', 'group');
    box.setAttribute(
      'aria-label',
      `${direction} quick setter · ${tier === 'process' ? 'this process' : 'application'}`,
    );
    const heading = el('div', '', 'activity-quick-heading');
    heading.append(
      el(
        'strong',
        `${short(direction)} · ${tier === 'process' ? `This process${inv.processPolicy ? ' · PID ' + inv.processPolicy.target.pid : ''}` : 'Application · all instances'}`,
      ),
    );
    const close = button('×', 'quick-close', 'quick-close');
    close.setAttribute('aria-label', 'Close quick setter');
    close.onclick = () => this.close();
    heading.append(close);
    box.append(heading);
    const reason = this.blockReason(inv, tier);
    const busy = !!this.pending && this.pending.phase !== 'error';
    const rules = this.applicable(inv, direction, tier);
    if (reason) box.append(el('p', reason, 'activity-policy-note'));
    if (rules.length && mode === 'auto') {
      box.append(
        el(
          'p',
          rules.length === 1
            ? 'Change the existing rule (its scope and lifetime stay the same):'
            : `${rules.length} rules apply here. Choose which one to change:`,
          'quick-hint',
        ),
      );
      for (const ref of rules) box.append(this.quickRule(ref, !!reason || busy));
      const addNew = button('New separate rule…', 'quick-new', 'link-button');
      addNew.disabled = !!reason || busy;
      addNew.onclick = () => {
        this.setter = { direction, tier, mode: 'new' };
        this.refresh();
        this.host.querySelector<HTMLElement>('[data-focus^="quick-protocol"]')?.focus();
      };
      box.append(addNew);
    } else box.append(this.newRule(inv, direction, tier, !!reason || busy));
    if (this.pending?.anchor === 'setter' && this.pending.rowId === row.id)
      box.append(this.review());
    return box;
  }
  private newRule(inv: Inventory, direction: Direction, tier: Tier, blocked: boolean) {
    const c = this.state!.control,
      row = this.row!;
    const wrap = el('div', '', 'quick-new');
    const key = `${row.id}|${direction}|${tier}`;
    const values = this.newValues.get(key) || {
      protocol:
        (row.kind === 'socket' ? row.socket?.socket.protocol : inv.candidate?.socket.protocol) ===
        'udp'
          ? 'udp'
          : 'tcp',
      expiry: tier === 'process' ? 'permanent' : 'hour',
    };
    this.newValues.set(key, values);
    const candidate = inv.candidate;
    const supported = !!c.capabilities?.includes('observed-rule-create-v1');
    const reason = blocked
      ? ''
      : !supported
        ? 'Backend update required to create rules from Activity.'
        : !candidate
          ? 'No live, uniquely owned native socket to verify this target.'
          : '';
    if (reason) wrap.append(el('p', reason, 'activity-policy-note'));
    const proto = el('div', '', 'segmented');
    proto.setAttribute('role', 'radiogroup');
    proto.setAttribute('aria-label', 'Quick rule protocol');
    for (const p of ['tcp', 'udp']) {
      const b = button(p.toUpperCase(), `quick-protocol:${p}`);
      b.setAttribute('role', 'radio');
      b.setAttribute('aria-checked', String(values.protocol === p));
      b.onclick = () => {
        values.protocol = p;
        this.refresh();
      };
      proto.append(b);
    }
    const line = el('div', '', 'quick-row');
    line.append(proto);
    if (tier === 'application') {
      const expiry = el('select');
      expiry.dataset.focus = 'quick-expiry';
      expiry.setAttribute('aria-label', 'Quick rule expiry');
      expiry.append(new Option('For 1 hour', 'hour'), new Option('Persistent', 'permanent'));
      expiry.value = values.expiry;
      expiry.onchange = () => {
        values.expiry = expiry.value as 'hour' | 'permanent';
      };
      line.append(expiry);
    }
    wrap.append(line);
    const actions = el('div', '', 'activity-quick-actions');
    const protocol = values.protocol.toUpperCase();
    for (const action of ['allow', 'block'] as const) {
      const b = button(
        `${action === 'allow' ? '✓ Allow' : '✕ Block'} ${protocol}`,
        `quick-${action}`,
        `quick-${action}`,
      );
      b.disabled = blocked || !!reason;
      b.title = `Create a new ${action} rule for ${direction} ${protocol}, any remote address and any port. The backend reviews it before you save.`;
      b.onclick = () => {
        if (!candidate) return;
        const source: RuleSource = {
          observed: {
            ...(c.capabilities?.includes(PROCESS_CAPABILITY) ? { target_scope: tier } : {}),
            generation: c.generation,
            row_id: candidate.id,
            process_id: candidate.owners[0],
            direction,
          } satisfies ObservedSource,
        };
        const expiry = tier === 'process' ? 'permanent' : values.expiry;
        this.review_new(source, 'setter', `New ${action} rule`, {
          action,
          protocol: values.protocol,
          expiry,
        });
      };
      actions.append(b);
    }
    const advanced = button('Advanced…', 'quick-advanced', 'link-button');
    advanced.disabled = blocked || !!reason;
    advanced.title = 'Open the full editor for address, port and expiry scope.';
    advanced.onclick = () => {
      if (!candidate) return;
      void openRule(
        {
          observed: {
            ...(c.capabilities?.includes(PROCESS_CAPABILITY) ? { target_scope: tier } : {}),
            generation: c.generation,
            row_id: candidate.id,
            process_id: candidate.owners[0],
            direction,
          },
        },
        { activity: true },
      );
    };
    actions.append(advanced);
    wrap.append(
      actions,
      el(
        'p',
        `New rule · ${protocol} · any address · any port · ${tier === 'process' ? 'until this process exits' : values.expiry === 'hour' ? 'for 1 hour' : 'persistent'}`,
        'quick-scope-line',
      ),
    );
    return wrap;
  }
  // One rule with its actions beside it. Used in the setter and in the full list.
  private ruleLine(ref: PolicyRuleRef, inv: Inventory, anchorBase: string, blocked: boolean) {
    const c = this.state!.control;
    const card = el('section', '', 'activity-rule');
    card.dataset.ruleId = ref.id;
    if (ref.id === this.saved) card.classList.add('recently-saved');
    const inactiveTarget =
      ref.target_state === 'inactive' || c.rule_states?.[ref.id]?.state === 'inactive';
    const state = inactiveTarget ? 'Inactive' : refState(ref);
    if (state !== 'Enabled') card.classList.add('rule-off');
    const title = el('div', '', 'activity-rule-title');
    title.append(
      el('span', short(ref.scope.direction as Direction), 'rule-direction-chip'),
      el(
        'strong',
        `${ref.action === 'allow' ? '✓ Allow' : '✕ Block'}`,
        `rule-action-${ref.action}`,
      ),
      el('span', shortScope(ref), 'activity-rule-scope'),
      el('span', state, 'rule-enabled-state state-' + state.toLowerCase()),
    );
    card.append(title);
    const meta = el(
      'p',
      inactiveTarget
        ? ref.target_reason || c.rule_states?.[ref.id]?.reason || 'Process ended; inactive'
        : ref.expires.startsWith('0001-')
          ? ref.scope.process
            ? 'Until this process exits (this daemon session)'
            : 'No expiry'
          : `Expires ${new Date(ref.expires).toLocaleString()}`,
      'activity-rule-expiry',
    );
    meta.title = `${scopeLabel(ref)}\n${ref.id} · version ${ref.version} · ${ref.expires}`;
    card.append(meta);
    const rule = this.editable(ref);
    const anchor = `${anchorBase}:${ref.id}`;
    if (canManageRules(c) && rule) {
      const actions = el('div', '', 'activity-rule-actions');
      const editBlocked = blocked || ref.expired || inactiveTarget;
      const other = ref.action === 'allow' ? 'block' : 'allow';
      const flip = button(
        other === 'allow' ? 'Set ✓ Allow' : 'Set ✕ Block',
        `${anchor}:flip`,
        `quick-${other}`,
      );
      flip.disabled = editBlocked;
      flip.title = ref.expired
        ? 'Expired rule: use Advanced to review a new expiry.'
        : 'Change only the action of this rule; scope and lifetime stay the same.';
      flip.onclick = () =>
        this.review_edit(ref, anchor, `Change to ${other === 'allow' ? 'Allow' : 'Block'}`, {
          action: other,
          disabled: ref.disabled,
        });
      const toggle = button(ref.disabled ? 'Enable' : 'Disable', `${anchor}:toggle`);
      toggle.disabled = editBlocked;
      toggle.onclick = () =>
        this.review_edit(ref, anchor, ref.disabled ? 'Enable rule' : 'Disable rule', {
          action: ref.action === 'allow' ? 'allow' : 'block',
          disabled: !ref.disabled,
        });
      const remove = button('Delete…', `${anchor}:delete`);
      remove.disabled = blocked || !c.capabilities?.includes('conditional-rule-delete-v1');
      const generation = c.generation;
      remove.onclick = () => confirmRuleDelete(rule, generation);
      const advanced = button('Advanced…', `${anchor}:advanced`);
      advanced.disabled = blocked || inactiveTarget;
      advanced.onclick = () => void openRule({ id: ref.id }, { activity: true });
      actions.append(flip, toggle, remove, advanced);
      card.append(actions);
    } else if (canManageRules(c))
      card.append(
        el('p', 'Refresh required before editing this exact version.', 'activity-policy-note'),
      );
    if (this.pending?.anchor === anchor && this.pending.rowId === this.row?.id)
      card.append(this.review());
    return card;
  }
  // Compact pick row inside the setter: the action change sits beside the rule it affects.
  private quickRule(ref: PolicyRuleRef, blocked: boolean) {
    const c = this.state!.control;
    const line = el('div', '', 'quick-rule');
    line.dataset.ruleId = ref.id;
    const inactiveTarget =
      ref.target_state === 'inactive' || c.rule_states?.[ref.id]?.state === 'inactive';
    const state = inactiveTarget ? 'Inactive' : refState(ref);
    const title = el('div', '', 'activity-rule-title');
    title.append(
      el('strong', ref.action === 'allow' ? '✓ Allow' : '✕ Block', `rule-action-${ref.action}`),
      el('span', shortScope(ref), 'activity-rule-scope'),
      el('span', state, 'rule-enabled-state state-' + state.toLowerCase()),
    );
    const anchor = `setter:${ref.id}`;
    const other = ref.action === 'allow' ? 'block' : 'allow';
    const flip = button(
      other === 'allow' ? 'Set ✓ Allow' : 'Set ✕ Block',
      `${anchor}:flip`,
      `quick-${other}`,
    );
    flip.disabled =
      blocked || ref.expired || inactiveTarget || !canManageRules(c) || !this.editable(ref);
    flip.title = ref.expired
      ? 'Expired rule: use Advanced in the list below to review a new expiry.'
      : 'Change only the action of this rule; scope and lifetime stay the same.';
    flip.onclick = () =>
      this.review_edit(ref, anchor, `Change to ${other === 'allow' ? 'Allow' : 'Block'}`, {
        action: other,
        disabled: ref.disabled,
      });
    title.append(flip);
    line.append(title);
    if (this.pending?.anchor === anchor && this.pending.rowId === this.row?.id)
      line.append(this.review());
    return line;
  }
  private ruleList(row: Row, inv: Inventory) {
    const list = el('div', '', 'activity-rule-list');
    list.setAttribute('aria-label', 'Relevant configured firewall rules');
    if (!inv.rules.length) {
      list.append(
        el(
          'p',
          'No explicit rules for this target. Click an In or Out cell above to set one.',
          'activity-policy-note',
        ),
      );
      return list;
    }
    const busy = !!this.pending && this.pending.phase !== 'error';
    const groups: [string, string, PolicyRuleRef[]][] = [
      [
        inv.processPolicy ? `This process · PID ${inv.processPolicy.target.pid}` : 'This process',
        'Checked first: matching rules for this exact process instance take precedence over application rules.',
        inv.rules.filter((r) => !!r.scope.process),
      ],
      [
        row.kind === 'application' || !inv.processPolicy
          ? 'Application · all instances'
          : 'Application fallback · all instances',
        'Used when no enabled process rule matches. Covers every process of this executable revision and user.',
        inv.rules.filter((r) => !r.scope.process),
      ],
    ];
    for (const [name, help, refs] of groups) {
      if (!refs.length) continue;
      const h = el('h4', `${name} · ${refs.length}`, 'activity-rule-group');
      h.title = help;
      list.append(h);
      for (const d of directions)
        for (const ref of refs.filter((r) => r.scope.direction === d))
          list.append(this.ruleLine(ref, inv, 'list', busy || !!this.blockReasonFor(ref, inv)));
    }
    return list;
  }
  private blockReasonFor(ref: PolicyRuleRef, inv: Inventory) {
    return ref.scope.process
      ? canManageRules(this.state!.control)
        ? ''
        : 'read-only'
      : this.blockReason(inv, 'application');
  }
  private details(inv: Inventory) {
    const details = el('details', '', 'activity-policy-details');
    details.append(el('summary', 'Precedence, defaults and enforcement'));
    if (inv.processPolicy)
      details.append(
        el(
          'p',
          'Matching process rules take precedence; application rules are the fallback when no active process rule matches. Evaluation happens in the backend.',
        ),
        el('p', inv.processPolicy.reason),
      );
    for (const d of directions) {
      const s = this.tierSummary(inv, 'application', d);
      if (s)
        details.append(
          el('p', `${d}: ${s.reason} ${s.enforcement.reason}`),
          el(
            'p',
            `Configured default: ${s.configured_default.known ? s.configured_default.action : 'unknown'}. ${s.configured_default.reason}`,
          ),
        );
    }
    details.append(
      el(
        'p',
        '“Not set” means no explicit rule; it is not Allow. Incoming/outgoing means connection initiation, not upload/download. Editing rules may not disconnect already-approved TCP sessions.',
      ),
    );
    return details;
  }
  private editable(ref: PolicyRuleRef): Rule | undefined {
    return this.state?.control.rules?.find(
      (r) =>
        r.id === ref.id && Number.isSafeInteger(r.version) && String(r.version) === ref.version,
    );
  }
  // ---- inline backend review -------------------------------------------------------------
  private begin(anchor: string, title: string): Pending {
    const p: Pending = {
      seq: ++this.seq,
      rowId: this.row!.id,
      rowLabel: this.row!.label,
      anchor,
      title,
      phase: 'previewing',
    };
    this.pending = p;
    this.refresh();
    return p;
  }
  private current(p: Pending) {
    return this.pending?.seq === p.seq;
  }
  private review_new(
    source: RuleSource,
    anchor: string,
    title: string,
    o: { action: 'allow' | 'block'; protocol: string; expiry: 'hour' | 'permanent' },
  ) {
    const run = async () => {
      const p = this.begin(anchor, title);
      p.advanced = () =>
        void openRule(source, {
          activity: true,
          quick: true,
          action: o.action,
          protocol: o.protocol,
          expiry: o.expiry,
          applicationScope: true,
        });
      try {
        const draft = await window.flowgate.ruleDraft(source);
        if (!this.current(p)) return;
        await this.preview(p, {
          token: draft.token,
          action: o.action,
          protocol: o.protocol,
          remote_address: '*',
          local_port: 0,
          remote_port: 0,
          priority: 100,
          disabled: false,
          expiry: o.expiry,
          creation_scope: 'application',
        });
      } catch (e) {
        this.fail(p, e);
      }
      p.retry = run;
    };
    void run();
  }
  private review_edit(
    ref: PolicyRuleRef,
    anchor: string,
    title: string,
    o: { action: 'allow' | 'block'; disabled: boolean },
  ) {
    const options: EditorOptions = { activity: true, quick: true, ...o };
    const run = async () => {
      const p = this.begin(anchor, title);
      p.advanced = () => void openRule({ id: ref.id }, options);
      try {
        const draft = await window.flowgate.ruleDraft({ id: ref.id });
        if (!this.current(p)) return;
        const r = draft.rule;
        if (String(r.version) !== ref.version || r.id !== ref.id)
          throw Error('This rule changed since it was listed; review the current version.');
        await this.preview(p, {
          token: draft.token,
          action: o.action,
          protocol: r.filter.protocol,
          remote_address: r.filter.remote_address || '*',
          local_port: r.filter.local_port || 0,
          remote_port: r.filter.remote_port || 0,
          priority: r.priority,
          disabled: o.disabled,
          expiry: 'preserve',
        });
      } catch (e) {
        this.fail(p, e);
      }
      p.retry = run;
    };
    void run();
  }
  private async preview(p: Pending, edit: RuleEdit) {
    const r = await window.flowgate.rulePreview(edit);
    if (!this.current(p)) return;
    const rule = r.verifiedRule;
    p.receipt = r.receipt;
    p.scope = rule ? reviewedScope(rule) : r.preview;
    p.lifetime = rule
      ? rule.expires.startsWith('0001-')
        ? rule.filter.process
          ? 'Lifetime: until this process exits (this daemon session).'
          : 'Lifetime: persistent, no expiry.'
        : `Lifetime: expires ${new Date(rule.expires).toLocaleString()}.`
      : '';
    p.enforcement = /Enforcement: ([^\n]*)/.exec(r.preview)?.[1] || '';
    p.expiresAt = r.expiresAt ? Date.parse(r.expiresAt) : undefined;
    p.phase = 'review';
    this.refresh();
    // Save stays a deliberate Tab/click; never pre-focus the acknowledgement.
    this.host.querySelector<HTMLElement>('.inline-review')?.focus({ preventScroll: true });
  }
  private fail(p: Pending, e: unknown) {
    if (!this.current(p)) return;
    p.phase = 'error';
    p.receipt = undefined;
    const text = String(e).replace(/^Error: /, '');
    p.message = /stale_target|unsupported|target_inactive|immutable_target|changed/.test(text)
      ? `${text} Nothing was saved; select the target again to review.`
      : `${text} Nothing was saved.`;
    this.refresh();
  }
  private discard() {
    if (!this.pending || ['saving', 'previewing'].includes(this.pending.phase)) return;
    const anchor = this.pending.anchor;
    this.pending = undefined;
    this.refresh();
    this.host.querySelector<HTMLElement>(`[data-focus^="${CSS.escape(anchor)}"]`)?.focus();
  }
  private async save() {
    const p = this.pending;
    if (!p || p.phase !== 'review' || !p.receipt) return;
    const receipt = p.receipt;
    p.receipt = undefined;
    p.phase = 'saving';
    this.refresh();
    let result: Attempt;
    try {
      result = await window.flowgate.ruleSave(receipt);
    } catch (e) {
      this.fail(p, e);
      return;
    }
    this.settle(p, result);
  }
  private async reconcile() {
    const p = this.pending;
    if (!p || p.phase !== 'unknown' || !p.reconcile) return;
    p.phase = 'saving';
    this.refresh();
    try {
      this.settle(p, await window.flowgate.ruleReconcile(p.reconcile));
    } catch (e) {
      p.phase = 'unknown';
      p.message = String(e);
      this.refresh();
    }
  }
  private settle(p: Pending, result: Attempt) {
    if (!this.current(p)) return;
    if (result.phase === 'acknowledged') {
      this.pending = undefined;
      this.setter = undefined;
      this.saved = result.rule?.id || '';
      const feedback = document.getElementById('feedback');
      if (feedback) feedback.textContent = result.message;
      this.refresh();
      return;
    }
    if (result.phase === 'unknown') {
      p.phase = 'unknown';
      p.reconcile = result.reconcile;
      p.message = result.message;
    } else {
      p.phase = 'error';
      p.message = result.message;
    }
    this.refresh();
  }
  private review(label = '') {
    const p = this.pending!;
    const box = el('div', '', 'inline-review phase-' + p.phase);
    box.tabIndex = -1;
    box.dataset.focus = 'review';
    box.setAttribute('role', 'group');
    box.setAttribute('aria-label', 'Rule change review');
    const head = el('div', '', 'inline-review-head');
    head.append(
      el(
        'span',
        p.phase === 'saving'
          ? 'Saving…'
          : p.phase === 'unknown'
            ? 'Save result unknown'
            : p.phase === 'error'
              ? 'Not saved'
              : 'Draft · not saved',
        'draft-badge',
      ),
      el('strong', label || p.title),
    );
    box.append(head);
    if (p.phase === 'previewing')
      box.append(el('p', 'Asking the backend to verify this exact target and scope…'));
    if (p.scope) box.append(el('p', p.scope, 'inline-review-scope'));
    if (p.lifetime) box.append(el('p', p.lifetime, 'inline-review-meta'));
    if (p.enforcement && p.phase === 'review')
      box.append(el('p', 'Enforcement: ' + p.enforcement, 'inline-review-meta'));
    if (p.message) box.append(el('p', p.message, 'activity-policy-note'));
    const actions = el('div', '', 'inline-review-actions');
    if (p.phase === 'review') {
      const save = button('Save', 'review-save', 'primary');
      save.disabled = !canManageRules(this.state!.control);
      save.onclick = () => void this.save();
      const timer = el('span', '', 'review-timer');
      timer.setAttribute('role', 'timer');
      actions.append(save, this.discardButton(), timer);
    } else if (p.phase === 'expired') {
      box.append(el('p', 'Review expired — nothing was saved.', 'activity-policy-note'));
      const again = button('Review again', 'review-again', 'primary');
      again.onclick = () => p.retry?.();
      actions.append(again, this.discardButton());
    } else if (p.phase === 'unknown') {
      const check = button('Check save result', 'review-reconcile', 'primary');
      check.disabled = !p.reconcile;
      check.onclick = () => void this.reconcile();
      actions.append(check);
    } else if (p.phase === 'error') actions.append(this.discardButton('Dismiss'));
    if (['review', 'expired', 'error'].includes(p.phase) && p.advanced) {
      const advanced = button('Advanced…', 'review-advanced', 'link-button');
      advanced.title = 'Discard this inline draft and open the full editor with the same choice.';
      advanced.onclick = () => {
        const open = p.advanced!;
        this.pending = undefined;
        this.refresh();
        open();
      };
      actions.append(advanced);
    }
    box.append(actions);
    return box;
  }
  private discardButton(text = 'Discard') {
    const b = button(text, 'review-discard');
    b.onclick = () => this.discard();
    return b;
  }
  private tick() {
    const p = this.pending;
    if (!p || p.phase !== 'review' || !p.expiresAt) {
      if (this.timer) clearInterval(this.timer);
      this.timer = undefined;
      return;
    }
    const paint = () => {
      if (this.pending !== p || p.phase !== 'review') return;
      const s = previewSeconds(p.expiresAt!, Date.now() + this.skew);
      const t = this.host.querySelector('.review-timer');
      if (t) t.textContent = `Review valid ${s} s`;
      if (s <= 0) {
        // Never refresh the token silently; the user must explicitly review again.
        p.phase = 'expired';
        p.receipt = undefined;
        this.refresh();
      }
    };
    paint();
    if (!this.timer) this.timer = setInterval(paint, 1000);
  }
}

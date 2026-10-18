import { popupPosition } from './popup-position';
import type { PolicyEntry } from './pane-model';
import { ANY_PROTOCOL_CAPABILITY, PROCESS_CAPABILITY } from './process-rules';
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
import {
  ruleChip,
  actionWord,
  knownAction,
  refState,
  shortScope,
  type RuleChip,
  endpointWide,
} from './rule-chip';
import { reviewedScope, previewSeconds } from './editor-presentation';
import { initiationPresentation } from './initiation';
import { openRule, confirmRuleDelete } from './workflows';
// Backend capability letting one observed rule cover TCP and UDP (NetLimiter's Blocker cell is
// protocol-agnostic). Older daemons keep the explicit TCP | UDP choice.
export { ANY_PROTOCOL_CAPABILITY };
type Direction = 'incoming' | 'outgoing';
type Tier = 'process' | 'application';
type Protocol = 'tcp' | 'udp' | '*';
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
const protocolText = (p: Protocol) => (p === '*' ? 'TCP + UDP' : p.toUpperCase());
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
// One backend-reviewed change at a time. Preview persists nothing; the identical draft is saved
// only when the verified scope equals the scope that was shown before the click.
interface Pending {
  seq: number;
  rowId: string;
  rowLabel: string;
  title: string;
  phase: 'previewing' | 'confirm' | 'saving' | 'unknown' | 'error';
  receipt?: string;
  scope?: string;
  expiresAt?: number;
  message?: string;
  reconcile?: string;
  retry?: () => void;
}
interface Popup {
  direction: Direction;
  tier: Tier;
  mode: 'auto' | 'new';
  protocol: Protocol;
  lifetime: 'persistent' | 'hour';
  enabled: boolean;
}
const SLOTS: { key: string; label: string; glyph: string; direction?: Direction }[] = [
  { key: 'priority', label: 'Priority', glyph: '↑' },
  { key: 'dl-limit', label: 'DL Limit', glyph: '↓' },
  { key: 'ul-limit', label: 'UL Limit', glyph: '↑' },
  { key: 'in-blocker', label: 'In Blocker', glyph: '✓', direction: 'incoming' },
  { key: 'out-blocker', label: 'Out Blocker', glyph: '✓', direction: 'outgoing' },
  { key: 'in-quota', label: 'In Quota', glyph: '⬡' },
  { key: 'out-quota', label: 'Out Quota', glyph: '⬡' },
];
export const STATUS_SLOTS = SLOTS;
// Blocker cell: circular glyph + state word.
export function blockerGlyph(chip: RuleChip) {
  const g = el('span', '', 'blocker-glyph tone-' + chip.tone);
  g.textContent =
    chip.tone === 'allow'
      ? '✓'
      : chip.tone === 'block'
        ? '✕'
        : chip.tone === 'mixed'
          ? '±'
          : chip.tone === 'unavailable'
            ? '?'
            : '';
  g.setAttribute('aria-hidden', 'true');
  return g;
}
export class ActivityPolicy {
  private row?: Row;
  private state?: ClientState;
  private signature = '';
  private popup?: Popup;
  private saved = '';
  private pending?: Pending;
  private seq = 0;
  private timer?: ReturnType<typeof setInterval>;
  private skew = 0;
  private anchor?: HTMLElement;
  private returnFocus?: HTMLElement;
  private popupContext = '';

  constructor(
    private host: HTMLElement,
    private delegate?: (action: PolicyEntry) => void,
  ) {
    host.classList.add('rules-host');
    host.addEventListener('keydown', (event) => {
      if (event.key !== 'Escape') return;
      if (this.pending && ['confirm', 'error'].includes(this.pending.phase)) {
        event.stopPropagation();
        this.discard();
      } else if (this.popup && (!this.pending || this.pending.phase === 'error')) {
        event.stopPropagation();
        this.close(true);
      }
    });
    document.addEventListener('pointerdown', (event) => {
      if (!this.popup) return;
      const t = event.target as Node;
      if (host.querySelector('.quick-popup')?.contains(t)) return;
      if ((t as HTMLElement).closest?.('.rule-cell, .policy-cell')) return;
      if (this.pending && this.pending.phase !== 'error') return;
      this.close(false);
    });
    window.addEventListener('resize', () => this.place());
    document.addEventListener(
      'scroll',
      (event) => {
        if (this.popup && !this.host.querySelector('.quick-popup')?.contains(event.target as Node))
          this.place();
      },
      true,
    );
    window.addEventListener('activity-rule-saved', (e) => {
      this.saved = (e as CustomEvent<string>).detail;
      this.refresh();
    });
  }
  private refresh() {
    this.signature = '';
    if (this.state) this.update(this.row, this.state);
  }
  hasOutstandingAction() {
    return !!this.pending && this.pending.phase !== 'error';
  }
  private defaultTier(): Tier {
    return this.row &&
      this.row.kind !== 'application' &&
      this.state?.control.capabilities?.includes(PROCESS_CAPABILITY)
      ? 'process'
      : 'application';
  }
  private anyProtocol() {
    return !!this.state?.control.capabilities?.includes(ANY_PROTOCOL_CAPABILITY);
  }
  activate(direction: Direction, tier = this.defaultTier(), anchor?: HTMLElement) {
    if (!this.row || !this.state) return;
    if (this.pending && this.pending.phase !== 'error') {
      this.host.querySelector<HTMLElement>('.quick-popup')?.focus();
      return;
    }
    this.pending = undefined;
    this.anchor = anchor;
    this.returnFocus = anchor;
    this.popupContext = this.context();
    const row = this.row;
    const protocol: Protocol = this.anyProtocol()
      ? '*'
      : (row.kind === 'socket' ? row.socket?.socket.protocol : undefined) === 'udp'
        ? 'udp'
        : 'tcp';
    this.popup = { direction, tier, mode: 'auto', protocol, lifetime: 'persistent', enabled: true };
    this.refresh();
    // Focus the popup itself, never an action: the key that opened it must not also trigger it.
    this.host.querySelector<HTMLElement>('.quick-popup')?.focus({ preventScroll: true });
  }
  private context() {
    return JSON.stringify([
      this.row?.id,
      this.row?.process?.id,
      this.state?.control.generation,
      this.state?.control.policy?.snapshot.token,
      this.state?.control.connected,
    ]);
  }
  private close(restoreFocus: boolean) {
    const p = this.popup;
    this.popup = undefined;
    if (this.pending?.phase === 'error') this.pending = undefined;
    this.refresh();
    if (restoreFocus && this.anchor?.classList.contains('policy-cell') && this.row && p) {
      const control = document.querySelector<HTMLElement>(
        `tr[data-id="${CSS.escape(this.row.id)}"] [data-direction="${p.direction}"]`,
      );
      if (control) {
        control.focus({ preventScroll: true });
        return;
      }
    }
    if (restoreFocus && this.returnFocus?.isConnected) {
      this.returnFocus.focus({ preventScroll: true });
      return;
    }
    if (restoreFocus && p)
      this.host
        .querySelector<HTMLElement>(`[data-focus="cell:${p.tier}:${p.direction}"]`)
        ?.focus({ preventScroll: true });
  }
  update(row: Row | undefined, state: ClientState) {
    if (this.row?.id !== row?.id) {
      this.popup = undefined;
      if (this.pending && !['saving', 'unknown'].includes(this.pending.phase))
        this.pending = undefined;
    }
    this.row = row;
    this.state = state;
    if (this.popup && this.popupContext !== this.context() && !this.hasOutstandingAction())
      this.popup = undefined;
    if (Number.isFinite(state.control.serverNow)) this.skew = state.control.serverNow! - Date.now();
    this.host.hidden = !row || row.kind === 'overview' || row.kind === 'network';
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
      this.popup,
      this.saved,
      this.pending && { ...this.pending, retry: 0 },
    ]);
    if (signature === this.signature) return;
    this.signature = signature;
    const active = document.activeElement as HTMLElement | null;
    const focusKey = active && this.host.contains(active) ? active.dataset.focus : undefined;
    const details = this.host.querySelector<HTMLDetailsElement>('.rule-details');
    const detailsOpen = !!details?.open;
    const fragment = document.createDocumentFragment();
    fragment.append(el('h3', 'Rules', 'info-section-title'));
    fragment.append(this.matrix(row, inv));
    if (this.pending && this.pending.rowId !== row.id)
      fragment.append(this.reviewBox(`Unresolved save · ${this.pending.rowLabel}`));
    fragment.append(this.underMatrix(row, inv, detailsOpen));
    if (this.popup) fragment.append(this.popupBox(inv));
    this.host.replaceChildren(fragment);
    this.place();
    if (focusKey)
      this.host
        .querySelector<HTMLElement>(`[data-focus="${CSS.escape(focusKey)}"]`)
        ?.focus({ preventScroll: true });
    this.tick();
  }
  private tierSummary(inv: Inventory, tier: Tier, d: Direction): DirectionPolicy | undefined {
    if (tier === 'process') return inv.processPolicy?.[d];
    return inv.processPolicy
      ? inv.processPolicy[d === 'incoming' ? 'application_incoming' : 'application_outgoing']
      : inv.app?.[d];
  }
  private tiers(row: Row): Tier[] {
    const c = this.state!.control;
    return c.capabilities?.includes(PROCESS_CAPABILITY) &&
      (row.kind === 'process' || (row.kind === 'socket' && row.socket?.owners.length === 1))
      ? ['process', 'application']
      : ['application'];
  }
  // Type × In/Out matrix in the Info View. Only Blocker is a FlowGate feature;
  // Limit, Priority and Quota rows are shown as explicitly unavailable, never as controls.
  private matrix(row: Row, inv: Inventory) {
    const table = el('table', '', 'info-rule-matrix');
    table.setAttribute('aria-label', 'Rules by type and initiation direction');
    const connection =
      row.kind === 'socket' && row.socket ? initiationPresentation(row.socket).direction : '';
    const head = el('tr');
    head.append(el('th', 'Type'));
    for (const d of directions) {
      const th = el('th', short(d));
      th.title = `${short(d) === 'In' ? 'Incoming' : 'Outgoing'}: who initiated the connection, not upload/download.`;
      if (connection === d) th.classList.add('connection-column');
      head.append(th);
    }
    head.append(el('th', '', 'matrix-filler'));
    table.append(head);
    const tiers = this.tiers(row);
    for (const tier of tiers) {
      const tr = el(
        'tr',
        '',
        'tier-' + tier + (tier === 'application' && tiers.length > 1 ? ' fallback-tier' : ''),
      );
      const label = el('th', tier === 'process' || tiers.length === 1 ? 'Blocker' : '↳ App');
      label.scope = 'row';
      label.title =
        tier === 'process'
          ? 'Blocker rule bound to this one backend-verified process instance; checked before application rules.'
          : tiers.length > 1
            ? 'Application fallback: Blocker rules for this executable revision and user, used when no process rule matches.'
            : 'Blocker rules for this executable revision and user, covering all its processes.';
      tr.append(label);
      for (const d of directions) {
        const summary =
          inv.available || tier === 'process' ? this.tierSummary(inv, tier, d) : undefined;
        const td = el('td');
        const b = button('', `cell:${tier}:${d}`, 'rule-cell');
        if (!inv.authoritative && inv.available && tier === 'application') {
          const n = inv.fallback[d].length;
          b.append(blockerGlyph({ glyph: '', text: '', tone: n ? 'mixed' : 'none', detail: '' }));
          b.append(el('span', n ? `${n} listed` : 'Not set', 'cell-text'));
          b.title = 'Compatibility inventory; no backend summary.';
        } else {
          const chip = ruleChip(
            summary,
            tier === 'process' && inv.processPolicy?.state === 'inactive',
          );
          const [word, ...rest] = chip.text.split(' · ');
          b.append(blockerGlyph(chip), el('span', word, 'cell-text'));
          if (rest.length && !['all', 'ended'].includes(rest.join('')))
            b.append(el('small', rest.join(' · '), 'cell-qualifier'));
          b.classList.add('tone-' + chip.tone);
          b.title = `${short(d)} Blocker · ${tier === 'process' ? 'this process' : 'application'}\n${chip.detail}${summary ? '\n' + summary.reason : ''}`;
        }
        const open = this.popup?.direction === d && this.popup.tier === tier;
        b.setAttribute('aria-expanded', String(open));
        b.setAttribute('aria-haspopup', 'dialog');
        if (open) b.classList.add('open');
        b.setAttribute(
          'aria-label',
          `${label.textContent} ${short(d)}: ${b.textContent}. Open quick setter.`,
        );
        // Never disabled: a transient association gap must not steal keyboard focus.
        const activate = (event: Event) => {
          event.stopPropagation();
          open ? this.close(true) : this.activate(d, tier, b);
        };
        b.onclick = activate;
        td.onclick = (event) => {
          if (event.target === td) activate(event);
        };
        td.classList.add('rule-cell-target');
        td.ondblclick = (event) => event.stopPropagation();
        b.classList.add(tier === 'process' ? 'sidebar-process-policy' : 'sidebar-policy');
        b.dataset.direction = d;
        td.append(b);
        tr.append(td);
      }
      tr.append(el('td', '', 'matrix-filler'));
      table.append(tr);
    }
    for (const [name, glyph] of [
      ['Limit', '□'],
      ['Priority', '⊖'],
      ['Quota', '⬡'],
    ]) {
      const tr = el('tr', '', 'unsupported-family');
      const label = el('th', name);
      label.scope = 'row';
      tr.append(label);
      // Priority is direction-less in the reference: one cell spanning In and Out.
      for (const d of name === 'Priority' ? ['both'] : directions) {
        const td = el('td');
        if (d === 'both') td.colSpan = 2;
        const cell = el('span', '', 'rule-cell static' + (d === 'both' ? ' wide' : ''));
        cell.append(
          el('span', glyph, 'blocker-glyph tone-none family-' + name.toLowerCase()),
          el('span', 'n/a', 'cell-text'),
        );
        cell.title = `${name} rules are not a FlowGate feature (no traffic shaping backend). Shown only to mirror the reference layout.`;
        cell.setAttribute(
          'aria-label',
          `${name}${d === 'both' ? '' : ' ' + short(d as Direction)}: not available in FlowGate`,
        );
        td.append(cell);
        tr.append(td);
      }
      tr.append(el('td', '', 'matrix-filler'));
      table.append(tr);
    }
    return table;
  }
  private underMatrix(row: Row, inv: Inventory, detailsOpen: boolean) {
    const c = this.state!.control;
    const wrap = el('div', '', 'under-matrix');
    const links = el('div', '', 'rule-links');
    const add = button('Add rule', 'add-rule', 'link-button');
    add.title =
      'Open the full rule editor for this target (address, port, protocol and expiry scope).';
    const tier = this.defaultTier();
    add.disabled =
      !canManageRules(c) ||
      !inv.candidate ||
      !c.capabilities?.includes('observed-rule-create-v1') ||
      (tier === 'process' && inv.processPolicy?.state !== 'active');
    add.onclick = () => {
      if (this.delegate) {
        this.delegate({ kind: 'new' });
        return;
      }
      const source = this.newSource('incoming', tier, inv);
      if (source) void openRule(source, { activity: true });
    };
    links.append(add);
    wrap.append(links);
    const p = inv.processPolicy;
    const notes: string[] = [];
    if (!c.connected) notes.push('Controller disconnected');
    else if (c.enforcement?.state === 'stopped') notes.push('Stored only · firewall stopped');
    else if (c.enforcement?.state !== 'active')
      notes.push(`Firewall ${c.enforcement?.state || 'state unknown'}`);
    if (p?.state === 'inactive')
      notes.push(
        `PID ${p.target.pid} ended — its rules are inactive and never move to another process`,
      );
    if (!inv.available) notes.push(inv.reason);
    else if (!inv.complete && inv.authoritative)
      notes.push('Partial policy batch · some rules may be unavailable');
    if (!canManageRules(c)) notes.push('Read-only rule access');
    if (notes.length) {
      const note = el(
        'p',
        notes.join(' · '),
        'rule-note' + (p?.state === 'inactive' ? ' inactive-target' : ''),
      );
      wrap.append(note);
    }
    if (inv.rules.length) {
      const details = el('details', '', 'rule-details');
      details.open = detailsOpen;
      details.append(
        el(
          'summary',
          `${inv.rules.length} rule${inv.rules.length === 1 ? '' : 's'} for this target`,
        ),
      );
      const busy = !!this.pending && this.pending.phase !== 'error';
      const groups: [string, PolicyRuleRef[]][] = [
        [
          p ? `This process · PID ${p.target.pid}` : 'This process',
          inv.rules.filter((r) => !!r.scope.process),
        ],
        [
          row.kind === 'application' || !p
            ? 'Application · all instances'
            : 'Application fallback · all instances',
          inv.rules.filter((r) => !r.scope.process),
        ],
      ];
      for (const [name, refs] of groups) {
        if (!refs.length) continue;
        details.append(el('h4', name, 'activity-rule-group'));
        for (const d of directions)
          for (const ref of refs.filter((r) => r.scope.direction === d))
            details.append(this.ruleLine(ref, inv, busy));
      }
      details.append(
        el(
          'p',
          'Matching process rules take precedence; application rules are the fallback. “Not set” is no explicit rule, not Allow. In/Out means connection initiation.',
          'rule-note',
        ),
      );
      wrap.append(details);
    }
    return wrap;
  }
  private ruleLine(ref: PolicyRuleRef, inv: Inventory, blocked: boolean) {
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
        `${ref.action === 'allow' ? '✓' : '✕'} ${actionWord(ref.action)}`,
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
    if (canManageRules(c) && rule) {
      const actions = el('div', '', 'activity-rule-actions');
      const advanced = button('Advanced…', `list:${ref.id}:advanced`);
      advanced.disabled = blocked || inactiveTarget;
      advanced.onclick = () =>
        this.delegate
          ? this.delegate({ kind: 'edit', id: ref.id })
          : void openRule({ id: ref.id }, { activity: true });
      const remove = button('Delete…', `list:${ref.id}:delete`);
      remove.disabled = blocked || !c.capabilities?.includes('conditional-rule-delete-v1');
      const generation = c.generation;
      remove.onclick = () =>
        this.delegate
          ? this.delegate({ kind: 'delete', id: ref.id })
          : confirmRuleDelete(rule, generation);
      actions.append(advanced, remove);
      card.append(actions);
    }
    void inv;
    return card;
  }
  private editable(ref: PolicyRuleRef): Rule | undefined {
    return this.state?.control.rules?.find(
      (r) =>
        r.id === ref.id && Number.isSafeInteger(r.version) && String(r.version) === ref.version,
    );
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
  private newSource(direction: Direction, tier: Tier, inv: Inventory): RuleSource | undefined {
    const c = this.state!.control,
      candidate = inv.candidate;
    if (!candidate) return;
    return {
      observed: {
        ...(c.capabilities?.includes(PROCESS_CAPABILITY) ? { target_scope: tier } : {}),
        generation: c.generation,
        row_id: candidate.id,
        process_id: candidate.owners[0],
        direction,
      } satisfies ObservedSource,
    };
  }
  // ---- floating quick setter ------------------------------------------------------------
  private popupBox(inv: Inventory) {
    const pop = this.popup!,
      c = this.state!.control,
      { direction, tier } = pop;
    const box = el('div', '', 'quick-popup');
    box.tabIndex = -1;
    box.dataset.focus = 'quick';
    box.setAttribute('role', 'dialog');
    box.setAttribute(
      'aria-label',
      `${short(direction)} Blocker quick setter · ${tier === 'process' ? 'this process' : 'application'}`,
    );
    const reason = this.blockReason(inv, tier);
    const busy = !!this.pending && this.pending.phase !== 'error';
    const rules = this.applicable(inv, direction, tier);
    const target =
      tier === 'process'
        ? `This process${inv.processPolicy ? ' · PID ' + inv.processPolicy.target.pid : ''}`
        : 'Application · all instances';
    const targetShort =
      tier === 'process'
        ? `Process${inv.processPolicy ? ' ' + inv.processPolicy.target.pid : ''}`
        : 'Application';
    const lifetimeShort = (expires: string) =>
      expires.startsWith('0001-')
        ? tier === 'process'
          ? 'session'
          : 'persistent'
        : `until ${new Date(expires).toLocaleTimeString()}`;
    if (rules.length && pop.mode === 'auto') {
      if (rules.length > 1)
        box.append(
          el('p', `${rules.length} ${short(direction)} rules · ${targetShort}`, 'qs-scope'),
        );
      else {
        const only = rules[0];
        box.append(
          el(
            'p',
            `${short(direction)} · ${targetShort} · ${shortScope(only).split(' · ')[0]} · ${lifetimeShort(only.expires)}`,
            'qs-scope',
          ),
        );
        // Endpoint scope stays visible before the click: compact marker, or full details when scoped.
        box.append(
          endpointWide(only)
            ? el('span', 'Any endpoint', 'qs-endpoint')
            : el('p', `Scoped: ${shortScope(only)}`, 'qs-scope-detail'),
        );
      }
      for (const ref of rules) box.append(this.actionRow(ref, inv, !!reason || busy));
      const links = el('div', '', 'qs-links');
      if (rules.length === 1) {
        const only = rules[0],
          rule = this.editable(only);
        const advanced = button('Advanced', 'qs-advanced', 'link-button');
        advanced.disabled = !!reason || busy || only.target_state === 'inactive';
        advanced.onclick = () =>
          this.delegate
            ? this.delegate({ kind: 'edit', id: only.id })
            : void openRule({ id: only.id }, { activity: true });
        // Delete stays available for an inactive (exited) target; only edits are blocked.
        const remove = button('Delete', 'qs-delete', 'link-button');
        remove.disabled =
          !canManageRules(c) ||
          busy ||
          !rule ||
          !c.capabilities?.includes('conditional-rule-delete-v1');
        const generation = c.generation;
        remove.onclick = () => {
          if (rule)
            this.delegate
              ? this.delegate({ kind: 'delete', id: rule.id })
              : confirmRuleDelete(rule, generation);
        };
        links.append(advanced, remove);
      }
      const addNew = button('New rule…', 'qs-new', 'link-button');
      addNew.disabled = !!reason || busy;
      addNew.onclick = () => {
        pop.mode = 'new';
        this.refresh();
        this.host.querySelector<HTMLElement>('.quick-popup')?.focus();
      };
      links.append(addNew);
      box.append(links);
    } else {
      const supported = !!c.capabilities?.includes('observed-rule-create-v1');
      const blocked =
        reason ||
        (!supported ? 'Backend update required to create rules from Activity.' : '') ||
        (!inv.candidate ? 'No live, uniquely owned native socket to verify this target.' : '');
      const lifetime =
        tier === 'process'
          ? 'until this process exits'
          : pop.lifetime === 'hour'
            ? 'for 1 hour'
            : 'persistent';
      box.append(
        el(
          'p',
          `${short(direction)} · ${targetShort} · ${protocolText(pop.protocol)} · ${tier === 'process' ? 'session' : lifetime}${pop.enabled ? '' : ' · stored disabled'}`,
          'qs-scope',
        ),
      );
      const anyEndpoint = el('span', 'Any endpoint', 'qs-endpoint');
      anyEndpoint.title = 'Any remote address · any local port · any remote port';
      box.append(anyEndpoint);
      box.append(this.actionRow(undefined, inv, !!blocked || busy));
      const links = el('div', '', 'qs-links');
      const advanced = button('Advanced', 'qs-advanced', 'link-button');
      advanced.disabled = !!blocked || busy;
      advanced.title = 'Open the full editor for address, port and expiry scope.';
      advanced.onclick = () => {
        const source = this.newSource(direction, tier, inv);
        if (source && this.delegate) this.delegate({ kind: 'new' });
        else if (source)
          void openRule(source, {
            activity: true,
            protocol: pop.protocol === '*' ? undefined : pop.protocol,
          });
      };
      links.append(advanced);
      const noDelete = button('Delete', 'qs-delete-none', 'link-button');
      noDelete.disabled = true;
      noDelete.title = 'No rule to delete here yet.';
      links.append(noDelete);
      if (!this.anyProtocol()) {
        const seg = el('span', '', 'segmented small');
        seg.setAttribute('role', 'radiogroup');
        seg.setAttribute('aria-label', 'Protocol for the new rule');
        seg.title =
          'This daemon stores one protocol per rule; choose which one this click creates.';
        for (const p of ['tcp', 'udp'] as const) {
          const b = button(p.toUpperCase(), `qs-protocol:${p}`);
          b.setAttribute('role', 'radio');
          b.setAttribute('aria-checked', String(pop.protocol === p));
          b.disabled = busy;
          b.onclick = () => {
            pop.protocol = p;
            this.refresh();
          };
          seg.append(b);
        }
        links.append(seg);
      }
      if (tier === 'application') {
        const life = button(
          pop.lifetime === 'hour' ? '1 hour' : 'Persistent',
          'qs-lifetime',
          'link-button',
        );
        life.title = 'Lifetime of the new rule. Click to switch between persistent and one hour.';
        life.disabled = busy;
        life.onclick = () => {
          pop.lifetime = pop.lifetime === 'hour' ? 'persistent' : 'hour';
          this.refresh();
        };
        links.append(life);
      }
      box.append(links);
      if (blocked) box.append(el('p', blocked, 'rule-note'));
    }
    if (this.pending && this.pending.rowId === this.row?.id) box.append(this.reviewBox());
    return box;
  }
  // [enabled] [✓ Allow] [✕ Block] — for an existing rule the current action is highlighted and a
  // click changes only that; for a new rule a click creates exactly the scope shown above.
  private actionRow(ref: PolicyRuleRef | undefined, inv: Inventory, blocked: boolean) {
    const c = this.state!.control;
    const row = el('div', '', 'qs-row');
    const inactiveTarget =
      !!ref && (ref.target_state === 'inactive' || c.rule_states?.[ref.id]?.state === 'inactive');
    const editable = !ref || !!this.editable(ref);
    // A rule whose action this UI does not support (e.g. stored ask) is shown but not changed here.
    const foreign = !!ref && !knownAction(ref.action);
    const disabled = blocked || foreign || (!!ref && (ref.expired || inactiveTarget || !editable));
    const key = ref ? `qs:${ref.id}` : 'qs:new';
    const enabled = el('input');
    enabled.type = 'checkbox';
    enabled.dataset.focus = `${key}:enabled`;
    enabled.checked = ref ? !ref.disabled : this.popup!.enabled;
    enabled.disabled = disabled;
    enabled.title = ref
      ? ref.disabled
        ? 'Enable this rule'
        : 'Disable this rule (kept, not deleted)'
      : 'Create the rule enabled (unchecked: stored disabled).';
    enabled.setAttribute('aria-label', ref ? 'Rule enabled' : 'New rule enabled');
    enabled.onchange = () => {
      if (!ref) {
        this.popup!.enabled = enabled.checked;
        return;
      }
      this.review_edit(ref, enabled.checked ? 'Enable rule' : 'Disable rule', {
        action: ref.action === 'allow' ? 'allow' : 'block',
        disabled: !enabled.checked,
      });
    };
    row.append(enabled);
    if (foreign)
      row.title = `Action "${ref!.action}" is not editable from this quick setter; use Advanced or the Rule list.`;
    for (const action of ['allow', 'block'] as const) {
      const b = button(actionWord(action), `${key}:${action}`, `qs-action qs-${action}`);
      b.prepend(el('span', action === 'allow' ? '✓' : '✕', 'blocker-glyph tone-' + action));
      const current = ref?.action === action;
      if (current) b.classList.add('current');
      b.setAttribute('aria-pressed', String(current));
      b.disabled = disabled || current;
      b.title = ref
        ? current
          ? `Current action: ${action}.`
          : `Change this rule to ${action}; scope and lifetime stay the same.`
        : `Create the ${action} rule shown above. The backend verifies the target before storing it.`;
      b.onclick = () => {
        if (ref)
          this.review_edit(ref, `Change to ${actionWord(action)}`, {
            action,
            disabled: ref.disabled,
          });
        else this.review_new(inv, action);
      };
      row.append(b);
    }
    if (ref) {
      const several =
        this.applicable(
          inv,
          ref.scope.direction as Direction,
          ref.scope.process ? 'process' : 'application',
        ).length > 1;
      const scope = el('span', several ? shortScope(ref) : '', 'qs-rule-scope');
      scope.hidden = !several;
      scope.title = scopeLabel(ref);
      row.append(scope);
      const rule = this.editable(ref);
      const links = el('span', '', 'qs-row-links');
      links.hidden = !several;
      const advanced = button('Advanced', `${key}:advanced`, 'link-button');
      advanced.disabled = blocked || inactiveTarget;
      advanced.onclick = () =>
        this.delegate
          ? this.delegate({ kind: 'edit', id: ref.id })
          : void openRule({ id: ref.id }, { activity: true });
      const remove = button('Delete', `${key}:delete`, 'link-button');
      remove.disabled =
        !canManageRules(c) || !rule || !c.capabilities?.includes('conditional-rule-delete-v1');
      const generation = c.generation;
      remove.onclick = () => {
        if (rule)
          this.delegate
            ? this.delegate({ kind: 'delete', id: rule.id })
            : confirmRuleDelete(rule, generation);
      };
      links.append(advanced, remove);
      row.append(links);
    }
    return row;
  }
  private place() {
    const pop = this.host.querySelector<HTMLElement>('.quick-popup');
    if (!pop || !this.popup) return;
    const external = this.anchor?.classList.contains('policy-cell');
    const liveExternal =
      external && this.row
        ? document.querySelector<HTMLElement>(
            `tr[data-id="${CSS.escape(this.row.id)}"] [data-direction="${this.popup.direction}"]`,
          )
        : undefined;
    const anchor =
      liveExternal ||
      (this.anchor?.isConnected
        ? this.anchor
        : this.host.querySelector<HTMLElement>(
            `[data-focus="cell:${this.popup.tier}:${this.popup.direction}"]`,
          ));
    if (!anchor) {
      this.close(false);
      return;
    }
    if (external && !liveExternal) {
      this.close(false);
      return;
    }
    const a = anchor.getBoundingClientRect();
    const margin = 6,
      width = Math.min(241, innerWidth - margin * 2);
    pop.style.position = 'fixed';
    pop.style.width = width + 'px';
    pop.style.maxWidth = width + 'px';
    pop.style.maxHeight = Math.max(60, innerHeight - margin * 2) + 'px';
    pop.style.overflowY = 'auto';
    const height = pop.getBoundingClientRect().height;
    const { left, top } = popupPosition(a, width, height, {
      width: innerWidth,
      height: innerHeight,
    });
    pop.style.left = Math.round(left) + 'px';
    pop.style.top = Math.round(top) + 'px';
  }

  // ---- backend review: preview, compare with the shown scope, then save the identical draft ----
  private begin(title: string): Pending {
    const p: Pending = {
      seq: ++this.seq,
      rowId: this.row!.id,
      rowLabel: this.row!.label,
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
  private review_new(inv: Inventory, action: 'allow' | 'block') {
    const pop = this.popup!;
    const { direction, tier, protocol, lifetime, enabled } = pop;
    const source = this.newSource(direction, tier, inv);
    if (!source) return;
    const expiry: 'hour' | 'permanent' =
      tier === 'process' ? 'permanent' : lifetime === 'hour' ? 'hour' : 'permanent';
    const run = async () => {
      const p = this.begin(`New ${actionWord(action).toLowerCase()} rule`);
      try {
        const draft = await window.flowgate.ruleDraft(source);
        if (!this.current(p)) return;
        await this.preview(
          p,
          {
            token: draft.token,
            action,
            protocol,
            remote_address: '*',
            local_port: 0,
            remote_port: 0,
            priority: 100,
            disabled: !enabled,
            expiry,
            creation_scope: 'application',
          },
          (rule) =>
            rule.action === action &&
            rule.filter.direction === direction &&
            rule.filter.protocol === protocol &&
            (rule.filter.remote_address || '*') === '*' &&
            !rule.filter.remote &&
            !rule.filter.local_port &&
            !rule.filter.remote_port &&
            rule.disabled === !enabled &&
            !!rule.filter.process === (tier === 'process') &&
            (expiry === 'permanent'
              ? rule.expires.startsWith('0001-')
              : Math.abs(Date.parse(rule.expires) - (Date.now() + this.skew + 3600000)) < 120000),
        );
      } catch (e) {
        this.fail(p, e);
      }
      p.retry = run;
    };
    void run();
  }
  private review_edit(
    ref: PolicyRuleRef,
    title: string,
    o: { action: 'allow' | 'block'; disabled: boolean },
  ) {
    const run = async () => {
      const p = this.begin(title);
      try {
        const draft = await window.flowgate.ruleDraft({ id: ref.id });
        if (!this.current(p)) return;
        const r = draft.rule;
        if (String(r.version) !== ref.version || r.id !== ref.id)
          throw Error('This rule changed since it was listed; review the current version.');
        await this.preview(
          p,
          {
            token: draft.token,
            action: o.action,
            protocol: r.filter.protocol,
            remote_address: r.filter.remote_address || '*',
            local_port: r.filter.local_port || 0,
            remote_port: r.filter.remote_port || 0,
            priority: r.priority,
            disabled: o.disabled,
            expiry: 'preserve',
          },
          (rule) =>
            rule.id === ref.id &&
            rule.action === o.action &&
            rule.disabled === o.disabled &&
            rule.expires === r.expires &&
            JSON.stringify(rule.filter) === JSON.stringify(r.filter),
        );
      } catch (e) {
        this.fail(p, e);
      }
      p.retry = run;
    };
    void run();
  }
  private async preview(p: Pending, edit: RuleEdit, matches: (rule: Rule) => boolean) {
    const r = await window.flowgate.rulePreview(edit);
    if (!this.current(p)) return;
    const rule = r.verifiedRule;
    p.receipt = r.receipt;
    p.scope = rule ? reviewedScope(rule) : r.preview;
    p.expiresAt = r.expiresAt ? Date.parse(r.expiresAt) : undefined;
    if (rule && matches(rule) && (!p.expiresAt || p.expiresAt > Date.now() + this.skew + 2000)) {
      await this.save(p);
      return;
    }
    // Verified scope differs from what was shown (or the token is nearly expired): explicit review.
    p.phase = 'confirm';
    p.message = rule
      ? 'The backend verified a different scope than shown. Save only if this is what you want.'
      : 'Review the backend preview before saving.';
    this.refresh();
    this.host.querySelector<HTMLElement>('.inline-review')?.focus({ preventScroll: true });
  }
  private fail(p: Pending, e: unknown) {
    if (!this.current(p)) return;
    p.phase = 'error';
    p.receipt = undefined;
    const text = String(e).replace(/^Error: /, '');
    p.message = /stale_target|unsupported|target_inactive|immutable_target|changed/.test(text)
      ? `${text} Nothing was saved; select the target again to retry.`
      : `${text} Nothing was saved.`;
    this.refresh();
  }
  private discard() {
    if (!this.pending || ['saving', 'previewing'].includes(this.pending.phase)) return;
    this.pending = undefined;
    this.refresh();
    this.host.querySelector<HTMLElement>('.quick-popup')?.focus();
  }
  private async save(p: Pending) {
    if (!p.receipt) return;
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
      const pop = this.popup;
      this.pending = undefined;
      this.popup = undefined;
      this.saved = result.rule?.id || '';
      const feedback = document.getElementById('feedback');
      if (feedback) feedback.textContent = result.message;
      this.refresh();
      if (pop)
        this.host
          .querySelector<HTMLElement>(`[data-focus="cell:${pop.tier}:${pop.direction}"]`)
          ?.focus({ preventScroll: true });
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
  private reviewBox(label = '') {
    const p = this.pending!;
    const box = el('div', '', 'inline-review phase-' + p.phase);
    box.tabIndex = -1;
    box.dataset.focus = 'review';
    box.setAttribute('role', 'group');
    box.setAttribute('aria-label', 'Rule change status');
    const head = el('div', '', 'inline-review-head');
    head.append(
      el(
        'span',
        p.phase === 'saving'
          ? 'Saving…'
          : p.phase === 'previewing'
            ? 'Verifying…'
            : p.phase === 'unknown'
              ? 'Save result unknown'
              : p.phase === 'error'
                ? 'Not saved'
                : 'Not saved yet',
        'draft-badge',
      ),
      el('strong', label || p.title),
    );
    box.append(head);
    if (p.scope && p.phase !== 'saving') box.append(el('p', p.scope, 'inline-review-scope'));
    if (p.message) box.append(el('p', p.message, 'rule-note'));
    const actions = el('div', '', 'inline-review-actions');
    if (p.phase === 'confirm') {
      const save = button('Save', 'review-save', 'primary');
      save.disabled = !canManageRules(this.state!.control);
      save.onclick = () => void this.save(p);
      const timer = el('span', '', 'review-timer');
      timer.setAttribute('role', 'timer');
      actions.append(save, this.discardButton(), timer);
    } else if (p.phase === 'unknown') {
      const check = button('Check save result', 'review-reconcile', 'primary');
      check.disabled = !p.reconcile;
      check.onclick = () => void this.reconcile();
      actions.append(check);
    } else if (p.phase === 'error') {
      actions.append(this.discardButton('Dismiss'));
      if (p.retry) {
        const again = button('Try again', 'review-again');
        again.onclick = () => p.retry?.();
        actions.append(again);
      }
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
    if (!p || p.phase !== 'confirm' || !p.expiresAt) {
      if (this.timer) clearInterval(this.timer);
      this.timer = undefined;
      return;
    }
    const paint = () => {
      if (this.pending !== p || p.phase !== 'confirm') return;
      const s = previewSeconds(p.expiresAt!, Date.now() + this.skew);
      const t = this.host.querySelector('.review-timer');
      if (t) t.textContent = `Review valid ${s} s`;
      if (s <= 0) {
        // Never refresh the token silently; the user must explicitly try again.
        p.phase = 'error';
        p.receipt = undefined;
        p.message = 'Review expired — nothing was saved.';
        this.refresh();
      }
    };
    paint();
    if (!this.timer) this.timer = setInterval(paint, 1000);
  }
}

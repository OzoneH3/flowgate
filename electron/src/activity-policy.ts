import { accountLabel } from './accounts';
import { uploadButton, priorityButton } from "./upload-shaping-view";
import { runtimeWitness } from './protocol';
import { matchesApplicationZone } from './application-zones';
import { acceptsPublication } from './publication';
import { applicationHeading } from './application-heading';
import { openZoneMigration } from './zone-migration-view';
import { ZONE_MIGRATION_CAPABILITY, zoneDefinitionDetails, ZONE_CAPABILITY, zoneLabel, type NetworkZone } from './network-zones';
import { popupPosition } from './popup-position';
import { networkScopeChoices } from './network-scope-choices';
import type { PolicyEntry } from './pane-model';
import { ANY_PROTOCOL_CAPABILITY, PROCESS_CAPABILITY } from './process-rules';
import type {
  Attempt,
  ClientState,
  ObservedSource,
  Rule,
  RuleAction,
  RuleEdit,
  RuleSource,
} from './protocol';
import { canManageRules, STORED_ASK_CAPABILITY } from './protocol';
import type { Row } from './model';
import {
  POLICY_CAPABILITY,
  APPLICATION_POLICY_CAPABILITY,
  authoritativePolicy,
  authoritativeZonePolicy,
  authoritativeProcessPolicy,
  type PolicyRuleRef,
  type DirectionPolicy,
} from './policy';
import { ruleStatus, ruleState, isRuleMasked, ownConfigured, zoneConfigured } from './rule-status';
import {
  ownRuleChip,
  ownShape,
  actionGlyph,
  storedAction,
  ASK_TOOLTIP,
  actionWord,
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
  const zone = authoritativeZonePolicy(row, state);
  const stored = directions.flatMap((d) => fallback[d]).map((r) => {
    const stateLabel = ruleState(r, fallback.now);
    return {
      id: r.id,
      version: String(r.version),
      action: r.action,
      priority: r.priority,
      scope: r.filter,
      disabled: r.disabled,
      expired: stateLabel === 'expired',
      active: ['allow', 'block', 'ask'].includes(stateLabel),
      expires: r.expires,
      stored_only: true,
      masked: isRuleMasked(r, state.control) === true,
    };
  });
  const maskedRules = stored.filter((r) => r.masked && !r.disabled && !r.expired);
  const zoneIDs = new Set(
    processPolicy?.zone_fallback_rule_ids || app?.zone_fallback_rule_ids || [],
  );
  const zoneFallback = (state.control.policy?.zones || [])
    .flatMap((z) => [...z.incoming.rules, ...z.outgoing.rules])
    .filter((r) => zoneIDs.has(r.id) && (!row.applicationZone || matchesApplicationZone(r.scope,row.applicationZone)));
  const unfilteredRules: PolicyRuleRef[] = zone
    ? [...zone.incoming.rules, ...zone.outgoing.rules]
    : authoritative
      ? directions.flatMap((d) => [
          ...(processPolicy?.[d].rules || []),
          ...(processPolicy
            ? processPolicy[d === 'incoming' ? 'application_incoming' : 'application_outgoing']
                .rules
            : app?.[d].rules || []),
        ])
      : stored;
  const rules = row.applicationZone ? unfilteredRules.filter(r=>matchesApplicationZone(r.scope,row.applicationZone!)) : unfilteredRules;
  const candidates =
    (app || processPolicy) &&
    (row.policyRows || row.rows).filter(
      (s) =>
        (s.runtime_application ? !!runtimeWitness(s, state.observation.activity?.processes || {}) && !!app?.process_ids.includes(runtimeWitness(s, state.observation.activity?.processes || {})!) :
        s.owners.length === 1 &&
        s.ownership_category === 'visible-holder' &&
        (app?.process_ids.includes(s.owners[0]) || processPolicy?.process_id === s.owners[0]) &&
        (!row.process || row.kind === 'application' || row.process.id === s.owners[0])),
    );
  return {
    authoritative,
    app,
    processPolicy,
    zone,
    zoneFallback,
    rules,
    maskedRules,
    available: authoritative ? !!app || !!processPolicy || !!zone : fallback.available,
    complete: authoritative && !!state.control.policy?.complete,
    reason: authoritative
      ? result.reason
      : 'Compatibility inventory: listed exact-identity rules; no backend summary.',
    candidate: candidates ? candidates[0] : undefined,
    processCandidate: candidates ? candidates.find(s => !s.holder_witness) : undefined,
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
  networkZone: NetworkZone | '';
  principal: 'machine' | 'self';
}
const SLOTS: { key: string; label: string; glyph: string; direction?: Direction }[] = [
  { key: 'priority', label: 'Priority', glyph: '↑' },
  { key: 'dl-limit', label: 'DL Limit', glyph: '↓' },
  { key: 'ul-limit', label: 'UL Limit', glyph: '↑' },
  { key: 'in-blocker', label: 'In Blocker', glyph: '✓', direction: 'incoming' },
  { key: 'out-blocker', label: 'Out Blocker', glyph: '✓', direction: 'outgoing' },
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
          : chip.tone === 'unavailable' || chip.tone === 'ask'
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
  private checking = false;
  private openSequence = 0;
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
      !['application', 'network'].includes(this.row.kind) &&
      this.state?.control.capabilities?.includes(PROCESS_CAPABILITY)
      ? 'process'
      : 'application';
  }
  private anyProtocol() {
    return !!this.state?.control.capabilities?.some((c) =>
      [ANY_PROTOCOL_CAPABILITY, ZONE_CAPABILITY].includes(c),
    );
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
    this.checking = true;
    const openSequence = ++this.openSequence;
    const targetId = this.row.id;
    const generation = this.state.control.generation;
    const row = this.row;
    const protocol: Protocol = this.anyProtocol()
      ? '*'
      : (row.kind === 'socket' ? row.socket?.socket.protocol : undefined) === 'udp'
        ? 'udp'
        : 'tcp';
    this.popup = {
      direction,
      tier,
      mode: 'auto',
      protocol,
      lifetime: 'persistent',
      enabled: true,
      networkZone:
        this.row.applicationZone?.zone || (this.row.kind === 'network' ? (this.row.id === 'network:local' ? 'local' : 'internet') : ''),
      principal: this.state.control.permissions?.can_manage_machine_rules ? 'machine' : 'self',
    };
    this.signature = '';
    this.host.querySelector('.quick-popup')?.remove();
    this.host.append(this.popupBox(selectionInventory(row, this.state)));
    this.place();
    // Focus the popup itself, never an action: the key that opened it must not also trigger it.
    this.host.querySelector<HTMLElement>('.quick-popup')?.focus({ preventScroll: true });
    // Paint the anchored shell first; refresh the existing bounded batch on demand.
    requestAnimationFrame(
      () =>
        void window.flowgate
          .ruleContext()
          .then((state) => {
            if (openSequence !== this.openSequence || !this.popup || this.row?.id !== targetId)
              return;
            if (!acceptsPublication(this.state, state)) state = this.state!;
            this.checking = false;
            if (state.control.generation !== generation || !state.control.connected) {
              this.close(false);
              return;
            }
            this.popupContext = JSON.stringify([
              this.row.id,
              this.row.process?.id,
              state.control.generation,
              state.control.policy?.snapshot.token,
              state.control.connected,
            ]);
            this.update(this.row, state);
          })
          .catch((error) => {
            if (openSequence === this.openSequence) {
              this.checking = false;
              this.close(false);
              const feedback =
                document.getElementById('feedback') || document.getElementById('paneMessage');
              if (feedback) feedback.textContent = 'Policy refresh unavailable: ' + String(error);
            }
          }),
    );
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
    this.openSequence++;
    this.checking = false;
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
    if (!acceptsPublication(this.state, state)) return;
    if (this.row?.id !== row?.id) {
      this.popup = undefined;
      if (this.pending && !['saving', 'unknown'].includes(this.pending.phase))
        this.pending = undefined;
    }
    this.row = row;
    this.state = state;
    if (
      this.popup &&
      this.popupContext !== this.context() &&
      !this.checking &&
      !this.hasOutstandingAction()
    )
      this.popup = undefined;
    if (Number.isFinite(state.control.serverNow)) this.skew = state.control.serverNow! - Date.now();
    this.host.hidden = !row || row.kind === 'overview' || row.kind === 'program' || row.kind === 'launch';
    if (this.host.hidden || !row) return;
    const inv = selectionInventory(row, state),
      c = state.control;
    const signature = JSON.stringify([
      row.id,
      row.process?.id,
      row.socket?.initiation,
      inv.rules,
      inv.maskedRules,
      inv.available,
      inv.complete,
      inv.reason,
      inv.processPolicy,
      inv.zone,
      inv.zoneFallback,
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
      this.checking,
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
    if (inv.zone) return inv.zone[d];
    if(this.row?.applicationZone){
      const base=inv.app?.[d];if(!base)return;
      const rules=inv.rules.filter(r=>r.scope.direction===d);
      return {...base,rules,application_rule:rules.length===1?rules[0]:null,scoped_rules:rules.length===1?0:rules.length,configured:rules.length?'scoped':'absent',reason:'Exact application/zone stored configuration; parent and global fallback policies remain separate.'} as DirectionPolicy;
    }
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
  // Info View matrix for Blocker, Limit, and Priority controls.
  private matrix(row: Row, inv: Inventory) {
    const table = el('table', '', 'info-rule-matrix');
    table.setAttribute('aria-label', 'Rules by type and initiation direction');
    const connection =
      row.kind === 'socket' && row.socket ? initiationPresentation(row.socket).direction : '';
    const head = el('tr');
    head.append(el('th', 'Type'));
    for (const d of directions) {
      const th = el('th', short(d));
      th.title = `${short(d) === 'In' ? 'Incoming' : 'Outgoing'} connection initiation`;
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
          ? 'This process only. Checked before app rules.'
          : tiers.length > 1
            ? 'App rules apply when no process rule matches.'
            : 'All processes for this executable revision and user.';
      tr.append(label);
      for (const d of directions) {
        const summary =
          inv.available || tier === 'process' ? this.tierSummary(inv, tier, d) : undefined;
        const td = el('td');
        const b = button('', `cell:${tier}:${d}`, 'rule-cell');
        if (!inv.authoritative && inv.available && tier === 'application') {
          // Compatibility inventory: whole-target rules only; narrower ones are a "+N scoped" hint.
          const own = row.applicationZone ? zoneConfigured(inv.fallback[d], inv.fallback.now) : ownConfigured(inv.fallback[d], inv.fallback.now);
          const [word, ...rest] = own.text.split(' +');
          b.append(blockerGlyph({ glyph: '', text: '', tone: own.tone, detail: '' }));
          b.append(el('span', word, 'cell-text'));
          if (rest.length) b.append(el('small', '+' + rest.join(' +'), 'cell-qualifier'));
          b.classList.add('tone-' + own.tone);
          b.title = 'Saved rules only.';
        } else {
          // NetLimiter Rule Status: this node's OWN rule; scoped rules never become the state.
          const chip = ownRuleChip(
            summary,
            tier === 'process' && inv.processPolicy?.state === 'inactive',
          );
          const [word, ...rest] = chip.text.split(' · ');
          b.append(blockerGlyph(chip), el('span', word, 'cell-text'));
          const qualifier = rest.filter((part) => !['all', 'ended'].includes(part));
          if (qualifier.length) b.append(el('small', qualifier.join(' · '), 'cell-qualifier'));
          b.classList.add('tone-' + chip.tone);
          b.title = `${short(d)} · ${tier === 'process' ? 'this process' : 'application'}\n${chip.tone === 'ask' ? ASK_TOOLTIP : chip.text}`;
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
    ]) {
      const tr = el('tr', '', 'unsupported-family');
      const label = el('th', name);
      label.scope = 'row';
      tr.append(label);
      // Priority is direction-less in the reference: one cell spanning In and Out.
      for (const d of name === 'Priority' ? ['both'] : directions) {
        const td = el('td');
        if (d === 'both') td.colSpan = 2;
        if (name === 'Priority' && this.row && this.state) { td.append(priorityButton(this.row,this.state)); tr.append(td); continue; }
        if (name === 'Limit' && this.row && this.state) { td.append(uploadButton(this.row,this.state,d === 'incoming' ? 'download' : 'upload')); tr.append(td); continue; }
        const cell = el('span', '', 'rule-cell static' + (d === 'both' ? ' wide' : ''));
        cell.append(
          el('span', glyph, 'blocker-glyph tone-none family-' + name.toLowerCase()),
          el('span', 'n/a', 'cell-text'),
        );
        cell.title = `${name} unavailable.`;
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
      'Set protocol, endpoint, and expiry.';
    const tier = this.defaultTier();
    add.disabled =
      !canManageRules(c) ||
      !!(row.applicationZone && row.applicationZone.model!==c.networkZones?.model) ||
      (!inv.candidate && !inv.zone) ||
      !c.capabilities?.includes('observed-rule-create-v1') ||
      (tier === 'process' && inv.processPolicy?.state !== 'active');
    add.onclick = () => {
      const source = this.newSource('incoming', tier, inv);
      if (source) void openRule(source, { activity: true, networkZone: this.row?.applicationZone?.zone });
    };
    links.append(add);
    wrap.append(links);
    const p = inv.processPolicy;
    const notes: string[] = [];
    if (!c.connected) notes.push('Controller disconnected');
    else if (c.enforcement?.state === 'stopped') {
      /* overall status already visible */
    } else if (c.enforcement?.state !== 'active')
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
    if (inv.rules.length || inv.zoneFallback.length || inv.maskedRules.length) {
      const details = el('details', '', 'rule-details');
      details.open = detailsOpen;
      const counts = [`${inv.rules.length} rule${inv.rules.length === 1 ? '' : 's'}`];
      if (inv.zoneFallback.length) counts.push(`${inv.zoneFallback.length} zone fallback`);
      if (inv.maskedRules.length) counts.push(`${inv.maskedRules.length} masked`);
      details.append(el('summary', counts.join(' + ')));
      const busy = !!this.pending && this.pending.phase !== 'error';
      // Own (whole-target) rules first; scoped rules are a separate list, never the node state.
      const groups: [string, PolicyRuleRef[], boolean][] = [
        [
          p ? `This process · PID ${p.target.pid}` : 'This process',
          inv.rules.filter((r) => !!r.scope.process),
          true,
        ],
        [
          inv.zone
            ? 'All programs · ' + zoneLabel(inv.zone.zone)
            : row.kind === 'application' || !p
              ? 'Application · all instances'
              : 'Application fallback · all instances',
          inv.rules.filter((r) => !r.scope.process),
          !inv.zone,
        ],
      ];
      groups.push(['All-program zone fallback', inv.zoneFallback, false]);
      for (const [name, refs, split] of groups) {
        if (!refs.length) continue;
        details.append(el('h4', name, 'activity-rule-group'));
        const scoped = split ? refs.filter((r) => !ownShape(r)) : [];
        for (const d of directions)
          for (const ref of refs.filter((r) => r.scope.direction === d && !scoped.includes(r)))
            details.append(this.ruleLine(ref, inv, busy));
        if (!scoped.length) continue;
        details.append(el('h4', `Scoped rules (${scoped.length})`, 'activity-rule-group scoped'));
        for (const d of directions)
          for (const ref of scoped.filter((r) => r.scope.direction === d))
            details.append(this.ruleLine(ref, inv, busy));
      }
      for (const ref of inv.maskedRules) details.append(this.maskedLine(ref));
      details.append(
        el(
          'p',
          p?.precedence ||
            (inv.zone
              ? 'Application and process rules are separate overrides. Unknown network membership does not match a zone rule.'
              : 'Configured inventory, not a per-connection verdict. “Not set” is no explicit rule.'),
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
        `${actionGlyph(ref.action)} ${actionWord(ref.action)}`,
        `rule-action-${ref.action}`,
      ),
      el('span', shortScope(ref), 'activity-rule-scope'),
      el('span', state, 'rule-enabled-state state-' + state.toLowerCase()),
    );
    if (ref.action === 'ask') title.title = ASK_TOOLTIP;
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
        void openRule({ id: ref.id }, { activity: true });
      const remove = button('Delete…', `list:${ref.id}:delete`);
      remove.disabled = blocked || !c.capabilities?.includes('conditional-rule-delete-v1');
      const generation = c.generation;
      remove.onclick = () =>
        this.delegate
          ? this.delegate({ kind: 'delete', id: ref.id })
          : confirmRuleDelete(rule, generation);
      actions.append(advanced, remove);
      if (rule.schema === 4 && rule.filter.network_zone && this.state?.control.capabilities?.includes(ZONE_MIGRATION_CAPABILITY)) {
        const migrate = button('Review automatic scope…', `list:${ref.id}:migrate`);
        migrate.disabled = !window.flowgate.zoneMigrationPreview;
        migrate.title = 'Review scope migration in the main window.';
        migrate.onclick = () => openZoneMigration({generation, id:rule.id, version:rule.version});
        actions.append(migrate);
      }
      card.append(actions);
    }
    void inv;
    return card;
  }
  private editable(ref: PolicyRuleRef): Rule | undefined {
    if (
      ref.scope.all_programs &&
      ref.scope.all_uids &&
      !this.state?.control.permissions?.can_manage_machine_rules
    )
      return undefined;
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
  private askWritable() {
    return !!this.state?.control.capabilities?.includes(STORED_ASK_CAPABILITY);
  }
  // NetLimiter order Ask | Allow | Deny; Ask only where the daemon stores it.
  private actions(): RuleAction[] {
    return this.askWritable() ? ['ask', 'allow', 'block'] : ['allow', 'block'];
  }
  // application-policy-v1: application/process cells set the ONE canonical own rule.
  private policyPath(inv: Inventory) {
    return (
      !inv.zone &&
      !this.row?.applicationZone &&
      inv.authoritative &&
      !!this.state?.control.capabilities?.includes(APPLICATION_POLICY_CAPABILITY)
    );
  }
  // The tier's own rule for the chosen zone (backend application_rule, or the zone's canonical
  // rule); never a scoped rule.
  private own(inv: Inventory, d: Direction, tier: Tier): PolicyRuleRef | undefined {
    const s = this.tierSummary(inv, tier, d),
      zone = this.popup?.networkZone || '';
    const ref = zone
      ? s?.rules.find((r) => r.kind === 'zone' && r.scope.network_zone === zone)
      : s?.application_rule;
    return ref ? s!.rules.find((r) => r.id === ref.id) || ref : undefined;
  }
  private resync() {
    void window.flowgate
      .ruleContext()
      .then((state) => {
        if (acceptsPublication(this.state, state)) this.update(this.row, state);
      })
      .catch(() => {});
  }
  private blockReason(inv: Inventory, tier: Tier): string {
    const c = this.state!.control;
    if (!canManageRules(c)) return 'Read-only: this connection cannot change rules.';
    if (tier === 'process' && inv.candidate?.holder_witness && !inv.processCandidate)
      return 'Worker or merged socket-holder evidence cannot bind a process rule.';
    if (!inv.available)
      return this.row?.kind === 'network'
        ? 'Backend update required for configured network-zone policy.'
        : inv.reason;
    if (
      inv.zone &&
      (!c.networkZones || c.policy?.network_zones?.revision !== c.networkZones.revision)
    )
      return 'Network-zone definition unavailable or changed; refresh.';
    if (tier === 'process' && (!inv.processPolicy || inv.processPolicy.state !== 'active'))
      return (
        inv.processPolicy?.reason ||
        'This process identity is unsupported or unavailable; no application-wide substitute is made.'
      );
    return '';
  }
  private newSource(direction: Direction, tier: Tier, inv: Inventory): RuleSource | undefined {
    const c = this.state!.control,
      candidate = tier === 'process' ? inv.processCandidate : inv.candidate;
    if(this.row?.applicationZone && this.row.applicationZone.model!==c.networkZones?.model)return;
    if (inv.zone && c.networkZones)
      return {
        zone: {
          generation: c.generation,
          zone: inv.zone.zone,
          scope:
            this.popup?.principal || (c.permissions?.can_manage_machine_rules ? 'machine' : 'self'),
          revision: c.networkZones.revision,
          direction,
        },
      };
    if (!candidate) return;
    return {
      observed: {
        ...(c.capabilities?.includes(PROCESS_CAPABILITY) ? { target_scope: tier } : {}),
        generation: c.generation,
        row_id: candidate.id,
        process_id: runtimeWitness(candidate, this.state!.observation.activity?.processes || {}) || candidate.owners[0],
        direction,
      } satisfies ObservedSource,
    };
  }
  // ---- floating quick setter ------------------------------------------------------------
  private popupBox(inv: Inventory) {
    const pop = this.popup!,
      c = this.state!.control,
      { direction, tier } = pop;
    const box = el('div', '', 'quick-popup quick-editor quick-rule-editor');
    box.tabIndex = -1;
    box.dataset.focus = 'quick';
    box.setAttribute('role', 'dialog');
    box.setAttribute(
      'aria-label',
      `${short(direction)} Blocker quick setter · ${tier === 'process' ? 'this process' : 'application'}`,
    );
    const selected = this.row;
    const app = selected?.process?.application || selected?.displayApplication;
    const header = el('header', '', 'quick-editor-header');
    const title = el('div', '', 'quick-editor-title');
    title.append(
      el('div', direction === 'incoming' ? 'Incoming rules' : 'Outgoing rules', 'quick-editor-kind'),
      applicationHeading(app, selected?.label || 'Selected target'),
    );
    const close = button('×', 'qs-close', 'quick-editor-close');
    close.setAttribute('aria-label', 'Close rule editor');
    close.disabled = this.hasOutstandingAction();
    close.onclick = () => this.close(true);
    header.append(title, close);
    box.append(header);
    const reason = this.blockReason(inv, tier);
    const busy = this.checking || (!!this.pending && this.pending.phase !== 'error');
    box.setAttribute('aria-busy', String(this.checking));
    const policy = this.policyPath(inv);
    const all = this.applicable(inv, direction, tier);
    const own = policy ? this.own(inv, direction, tier) : undefined;
    // Never route an application-level action into a scoped rule: the setter acts on the node's
    // own rule only. Older daemons: endpoint-wide rules stand in for it; scoped ones are listed.
    const rules = policy ? (own ? [own] : []) : inv.zone || this.row?.applicationZone ? all : all.filter(ownShape);
    const additional = all.filter((r) => r.id !== own?.id && !rules.some((x) => x.id === r.id));
    const wholeApplication = additional.filter((r) => policy && tier === 'application' && !pop.networkZone && !inv.zone && ownShape(r));
    const scoped = additional.filter((r) => !wholeApplication.includes(r));
    const targetShort = inv.zone
      ? `All programs · ${pop.principal === 'machine' ? 'all users' : 'current user'}`
      : tier === 'process'
        ? `Process${inv.processPolicy ? ' ' + inv.processPolicy.target.pid : ''}`
        : 'Application';
    const lifetimeShort = (expires: string) =>
      expires.startsWith('0001-')
        ? tier === 'process'
          ? 'session'
          : 'persistent'
        : `until ${new Date(expires).toLocaleTimeString()}`;
    if (policy) this.policySetter(box, inv, own, reason, busy, targetShort);
    else if (rules.length && pop.mode === 'auto') {
      if (rules.length > 1)
        box.append(
          el('p', `${rules.length} ${short(direction)} rules · ${targetShort}`, 'qs-scope'),
        );
      else {
        const only = rules[0];
        box.append(
          el(
            'p',
            `${short(direction)} · ${only.scope.all_programs ? 'All programs · ' + (only.scope.all_uids ? 'all users' : accountLabel(only.scope.uid)) : targetShort} · ${zoneLabel(only.scope.network_zone)} · ${shortScope(only).split(' · ')[0]} · ${lifetimeShort(only.expires)}`,
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
          void openRule({ id: only.id }, { activity: true });
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
      addNew.disabled = !!reason || busy || !!(this.row?.applicationZone && this.row.applicationZone.model!==c.networkZones?.model);
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
        (this.row?.applicationZone && this.row.applicationZone.model!==c.networkZones?.model ? 'Legacy classifier: edit an existing rule or review explicit migration before creating an automatic-zone rule.' : '') ||
        (!inv.candidate && !inv.zone
          ? 'No live, uniquely owned native socket to verify this target.'
          : '');
      const lifetime =
        tier === 'process'
          ? 'until this process exits'
          : pop.lifetime === 'hour'
            ? 'for 1 hour'
            : 'persistent';
      box.append(
        el(
          'p',
          `${short(direction)} · ${targetShort} · ${protocolText(pop.protocol)}${tier === 'process' ? ' · session' : ''}${pop.enabled ? '' : ' · stored disabled'}`,
          'qs-scope',
        ),
      );
      const anyEndpoint = el('span', 'Any endpoint', 'qs-endpoint');
      anyEndpoint.title = 'Any remote address · any local port · any remote port';
      box.append(this.zoneSelect(inv, busy));
      if (inv.zone && c.permissions?.can_manage_machine_rules) {
        const who = el('select');
        who.dataset.focus = 'qs-principal';
        who.setAttribute('aria-label', 'Programs owned by');
        for (const [value, label] of [
          ['machine', 'All users'],
          ['self', 'Current user'],
        ]) {
          const option = el('option', label);
          option.value = value;
          who.append(option);
        }
        who.value = pop.principal;
        who.disabled = busy;
        who.onchange = () => {
          pop.principal = who.value as 'machine' | 'self';
          this.refresh();
        };
        box.append(who);
      }
      box.append(anyEndpoint);
      box.append(this.actionRow(undefined, inv, !!blocked || busy));
      const links = el('div', '', 'qs-links');
      const advanced = button('Advanced', 'qs-advanced', 'link-button');
      advanced.disabled = !!blocked || busy;
      advanced.title = 'Set address, port, and expiry.';
      advanced.onclick = () => {
        const source = this.newSource(direction, tier, inv);
        if (source)
          void openRule(source, {
            activity: true,
            protocol: pop.protocol === '*' ? undefined : pop.protocol,
            networkZone: this.row?.applicationZone?.zone,
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
          'Choose one protocol for the rule.';
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
        life.title = 'Switch between No expiry and 1 hour.';
        life.disabled = busy;
        life.onclick = () => {
          pop.lifetime = pop.lifetime === 'hour' ? 'persistent' : 'hour';
          this.refresh();
        };
        links.append(life);
      }
      box.append(links);
      if (this.checking) box.append(el('span', 'Checking…', 'qs-checking'));
      if (blocked) box.append(el('p', blocked, 'rule-note'));
    }
    if (wholeApplication.length)
      box.append(this.ruleList(wholeApplication, busy, 'Additional whole-application rules'));
    if (scoped.length) box.append(this.ruleList(scoped, busy, pop.networkZone ? 'Other rules' : 'Scoped rules'));
    for (const ref of inv.maskedRules) {
      if (ref.scope.direction === direction && tier === 'application' &&
          (ref.scope.network_zone || '') === (pop.networkZone || '')) box.append(this.maskedLine(ref));
    }
    if (this.pending && this.pending.rowId === this.row?.id) box.append(this.reviewBox());
    return box;
  }
  private zoneSelect(inv: Inventory, busy: boolean) {
    const pop = this.popup!,
      c = this.state!.control,
      frag = document.createDocumentFragment();
    const zoneControl = networkScopeChoices('qs-zone', pop.networkZone || 'all', (scope) => {
      pop.networkZone = scope === 'all' ? '' : scope;
      this.refresh();
    });
    zoneControl.disabled = busy || !!inv.zone || !!this.row?.applicationZone || !c.capabilities?.includes(ZONE_CAPABILITY);
    zoneControl.title = c.capabilities?.includes(ZONE_CAPABILITY)
      ? 'Choose the network scope.'
      : 'Backend update required for Local Network / Internet rules';
    frag.append(zoneControl);
    if (pop.networkZone === 'internet' && c.networkZones?.model === 'configured-prefix-v1' && c.networkZones.internet_prefixes.length === 0)
      frag.append(
        el('p', 'No Internet prefixes configured; no peers currently match.', 'rule-note'),
      );
    if (pop.networkZone) frag.append(el('small', zoneDefinitionDetails(c.networkZones), 'rule-note'));
    return frag;
  }
  // NetLimiter quick setter: [Enabled] Ask | Allow | Deny, Advanced, Delete — one click sets the
  // node's own canonical rule (backend creates it or updates it in place); no review step.
  private policySetter(
    box: HTMLElement,
    inv: Inventory,
    own: PolicyRuleRef | undefined,
    reason: string,
    busy: boolean,
    targetShort: string,
  ) {
    const pop = this.popup!,
      c = this.state!.control;
    box.append(
      el(
        'p',
        `${short(pop.direction)} · ${targetShort} · TCP + UDP · ${pop.networkZone ? zoneLabel(pop.networkZone) : 'Any network'} · ${pop.tier === 'process' ? 'session' : 'persistent'}`,
        'qs-scope',
      ),
    );
    box.append(this.zoneSelect(inv, busy));
    const anyEndpoint = el('span', 'Any endpoint', 'qs-endpoint');
    anyEndpoint.title = 'TCP and UDP · any address and port';
    box.append(anyEndpoint);
    const setBlocked =
      reason ||
      (!inv.candidate ? 'No live, uniquely owned native socket to verify this target.' : '');
    box.append(this.actionRow(own, inv, !!reason || busy, setBlocked));
    if (own) {
      const meta = el(
        'p',
        `Own rule · ${refState(own)} ${actionWord(own.action)} · ${own.expires.startsWith('0001-') ? (own.scope.process || pop.tier === 'process' ? 'session' : 'persistent') : 'until ' + new Date(own.expires).toLocaleString()}`,
        'qs-own' + (own.id === this.saved ? ' recently-saved' : ''),
      );
      meta.title = `${scopeLabel(own)}\n${own.id} · version ${own.version}`;
      box.append(meta);
    }
    const links = el('div', '', 'qs-links');
    const advanced = button('Advanced', 'qs-advanced', 'link-button');
    advanced.disabled = !!reason || busy || own?.target_state === 'inactive';
    advanced.title = own
      ? 'Open the rule editor.'
      : 'Set address, port, and expiry.';
    advanced.onclick = () => {
      if (own)
        return void openRule({ id: own.id }, { activity: true });
      const source = this.newSource(pop.direction, pop.tier, inv);
      if (source) void openRule(source, { activity: true });
    };
    // Delete acts on the own rule only (also for an ended process target).
    const rule = own && this.editable(own);
    const remove = button('Delete', own ? 'qs-delete' : 'qs-delete-none', 'link-button');
    remove.disabled =
      !canManageRules(c) ||
      busy ||
      !rule ||
      !c.capabilities?.includes('conditional-rule-delete-v1');
    remove.title = own ? 'Delete this rule' : 'No own rule to delete.';
    const generation = c.generation;
    remove.onclick = () => {
      if (rule)
        this.delegate
          ? this.delegate({ kind: 'delete', id: rule.id })
          : confirmRuleDelete(rule, generation);
    };
    links.append(advanced, remove);
    box.append(links);
    if (this.checking) box.append(el('span', 'Checking…', 'qs-checking'));
    if (setBlocked) box.append(el('p', setBlocked, 'rule-note'));
  }
  private maskedLine(ref: PolicyRuleRef) {
    const line = el('div', '', 'qs-scoped-rule');
    line.dataset.ruleId = ref.id;
    line.append(
      el('span', actionWord(ref.action)),
      el('span', shortScope(ref), 'activity-rule-scope'),
      el('span', 'Masked by newer rule', 'rule-enabled-state'),
    );
    return line;
  }
  // Additional rules are separate from the canonical setter target.
  private ruleList(refs: PolicyRuleRef[], busy: boolean, heading: string) {
    const c = this.state!.control;
    const wrap = el('div', '', 'qs-scoped');
    wrap.append(el('h4', `${heading} (${refs.length})`));
    for (const ref of refs) {
      const line = el('div', '', 'qs-scoped-rule');
      line.dataset.ruleId = ref.id;
      line.append(
        el(
          'span',
          `${actionGlyph(ref.action)} ${actionWord(ref.action)}`,
          `rule-action-${ref.action}`,
        ),
        el('span', shortScope(ref), 'activity-rule-scope'),
        el('span', refState(ref), 'rule-enabled-state state-' + refState(ref).toLowerCase()),
      );
      line.title = `${scopeLabel(ref)}\n${ref.id} · version ${ref.version}`;
      const rule = this.editable(ref);
      const advanced = button('Advanced', `qs-scoped:${ref.id}:advanced`, 'link-button');
      advanced.disabled = !canManageRules(c) || busy || !rule || ref.target_state === 'inactive';
      advanced.onclick = () =>
        void openRule({ id: ref.id }, { activity: true });
      const remove = button('Delete', `qs-scoped:${ref.id}:delete`, 'link-button');
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
      line.append(advanced, remove);
      wrap.append(line);
    }
    return wrap;
  }
  // [enabled] [? Ask] [✓ Allow] [✕ Deny] — for an existing rule the current action is highlighted
  // and a click changes only that; for a new rule a click creates exactly the scope shown above.
  // policy (application-policy-v1, string = why setting is blocked, '' = allowed): every action
  // click sets the own canonical rule; the enabled box acts on the own rule only.
  private actionRow(
    ref: PolicyRuleRef | undefined,
    inv: Inventory,
    blocked: boolean,
    policy?: string,
  ) {
    const c = this.state!.control;
    const isPolicy = policy !== undefined;
    const row = el('div', '', 'qs-row');
    const inactiveTarget =
      !!ref && (ref.target_state === 'inactive' || c.rule_states?.[ref.id]?.state === 'inactive');
    const editable = !ref || !!this.editable(ref);
    // An action this daemon cannot write (unknown, or Ask without stored-ask-v1) is shown read-only:
    // never flipped, enabled or re-saved as Allow/Deny here.
    const foreign =
      !!ref && (!storedAction(ref.action) || (ref.action === 'ask' && !this.askWritable()));
    const disabled = blocked || foreign || (!!ref && (ref.expired || inactiveTarget || !editable));
    const key = ref ? `qs:${ref.id}` : 'qs:new';
    const enabled = el('input');
    enabled.type = 'checkbox';
    enabled.dataset.focus = `${key}:enabled`;
    enabled.checked = ref ? !ref.disabled : isPolicy || this.popup!.enabled;
    enabled.disabled = disabled || (isPolicy && !ref);
    enabled.title = ref
      ? ref.disabled
        ? 'Enable this rule'
        : 'Disable this rule'
      : isPolicy
        ? 'Choose an action to create an enabled rule.'
        : 'Save the new rule enabled.';
    enabled.setAttribute('aria-label', ref ? 'Rule enabled' : 'New rule enabled');
    enabled.onchange = () => {
      if (!ref) {
        this.popup!.enabled = enabled.checked;
        return;
      }
      this.review_edit(ref, enabled.checked ? 'Enable rule' : 'Disable rule', {
        action: ref.action as RuleAction,
        disabled: !enabled.checked,
      });
    };
    const enabledLabel = el('label', '', 'quick-editor-enabled');
    enabledLabel.append(enabled, el('span', 'Enabled'));
    row.append(enabledLabel);
    if (ref?.stored_only) {
      const label = foreign ? actionWord(ref.action) + ' · ' + refState(ref) : refState(ref);
      row.append(el('span', label, 'rule-enabled-state'));
    }
    if (foreign)
      row.title =
        ref!.action === 'ask'
          ? `${ASK_TOOLTIP}. Update the daemon to edit Ask rules.`
          : `Edit ${ref!.action} in Advanced or the rule list.`;
    for (const action of this.actions()) {
      const b = button(actionWord(action), `${key}:${action}`, `qs-action qs-${action}`);
      b.prepend(el('span', actionGlyph(action), 'blocker-glyph tone-' + action));
      const current = ref?.action === action;
      if (current) b.classList.add('current');
      b.setAttribute('aria-pressed', String(current));
      // Policy: clicking the current action of a disabled own rule sets it active again.
      b.disabled = isPolicy
        ? blocked ||
          !!policy ||
          foreign ||
          inactiveTarget ||
          (current && !!ref?.active && !ref.disabled && !ref.expired)
        : disabled || current;
      const what = action === 'ask' ? ASK_TOOLTIP : actionWord(action);
      b.title = isPolicy
        ? current && ref?.active
          ? `Current action: ${what}.`
          : `${what} · ${this.popup?.tier === 'process' ? 'this process' : 'this app'} · TCP/UDP, any endpoint`
        : ref
          ? current
            ? `Current action: ${what}.`
            : `Set ${actionWord(action)}. Keep scope and expiry.`
          : `Save the ${actionWord(action)} rule shown above.`;
      b.onclick = () => {
        if (isPolicy) this.review_policy(inv, action);
        else if (ref)
          this.review_edit(ref, `Change to ${actionWord(action)}`, {
            action,
            disabled: ref.disabled,
          });
        else this.review_new(inv, action);
      };
      row.append(b);
    }
    if (ref && !isPolicy) {
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
        void openRule({ id: ref.id }, { activity: true });
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
    const { width, height } = pop.getBoundingClientRect();
    const { left, top } = popupPosition(anchor.getBoundingClientRect(), width, height, {
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
  private review_new(inv: Inventory, action: RuleAction) {
    const pop = this.popup!;
    const { direction, tier, protocol, lifetime, enabled, networkZone } = pop;
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
            ...(networkZone ? { network_zone: networkZone } : {}),
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
            (rule.filter.network_zone || '') === networkZone &&
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
  // One click (NetLimiter): preview the canonical own rule and save it immediately; the backend
  // creates it or updates it in place (preview.replaces) and never selects a scoped rule.
  private review_policy(inv: Inventory, action: RuleAction) {
    const { direction, tier, networkZone } = this.popup!;
    const source = this.newSource(direction, tier, inv);
    if (!source?.observed) return;
    const run = async () => {
      const p = this.begin(
        `${actionWord(action)} · ${tier === 'process' ? 'this process' : 'application'} ${short(direction)}`,
      );
      try {
        const draft = await window.flowgate.ruleDraft(source);
        if (!this.current(p)) return;
        await this.preview(
          p,
          {
            token: draft.token,
            ...(networkZone ? { network_zone: networkZone } : {}),
            action,
            protocol: '*',
            remote_address: '*',
            local_port: 0,
            remote_port: 0,
            priority: 100,
            disabled: false,
            expiry: 'permanent',
            creation_scope: 'policy',
          },
          (rule) =>
            rule.action === action &&
            rule.filter.direction === direction &&
            rule.filter.protocol === '*' &&
            !rule.disabled &&
            (rule.filter.network_zone || '') === networkZone &&
            !!rule.filter.process === (tier === 'process') &&
            rule.expires.startsWith('0001-'),
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
    o: { action: RuleAction; disabled: boolean },
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
    if (/conflict/.test(text)) this.resync();
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
      const feedback =
        document.getElementById('feedback') || document.getElementById('paneMessage');
      const r = result.rule;
      if (feedback)
        feedback.textContent = r
          ? `${actionWord(r.action)} · ${reviewedScope(r)} · ${r.id} v${r.version}${r.disabled ? ' · disabled' : ''}. ${result.message}`
          : result.message;
      this.refresh();
      this.resync();
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
      if (/conflict/.test(result.message)) this.resync();
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

import type { ClientState, ObservedSource, Rule, RuleSource } from './protocol';
import { canManageRules } from './protocol';
import type { Row } from './model';
import {
  POLICY_CAPABILITY,
  authoritativePolicy,
  policyLabel,
  type PolicyRuleRef,
  type DirectionPolicy,
} from './policy';
import { ruleStatus, ruleState, configuredPolicy } from './rule-status';
import { openRule, confirmRuleDelete } from './workflows';
type Direction = 'incoming' | 'outgoing';
const directions: Direction[] = ['incoming', 'outgoing'];
const el = <K extends keyof HTMLElementTagNameMap>(tag: K, text = '', cls = '') => {
  const n = document.createElement(tag);
  n.textContent = text;
  n.className = cls;
  return n;
};
export function scopeLabel(ref: PolicyRuleRef) {
  const f = ref.scope;
  const protocol = f.protocol === '*' ? 'TCP + UDP' : f.protocol.toUpperCase();
  return `${protocol} · remote ${f.remote_address && f.remote_address !== '*' ? f.remote_address : f.remote || 'any address'} · local port ${f.local_port || 'any'} · remote port ${f.remote_port || 'any'}`;
}
export function selectionInventory(row: Row, state: ClientState) {
  const authoritative = !!state.control.capabilities?.includes(POLICY_CAPABILITY);
  const result = authoritativePolicy(row, state),
    app = result.application;
  const fallback = ruleStatus(row, state);
  const rules: PolicyRuleRef[] = authoritative
    ? directions.flatMap((d) => app?.[d].rules || [])
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
    app &&
    row.rows.find(
      (s) =>
        s.owners.length === 1 &&
        s.ownership_category === 'visible-holder' &&
        app.process_ids.includes(s.owners[0]) &&
        (!row.process || row.kind === 'application' || row.process.id === s.owners[0]),
    );
  return {
    authoritative,
    app,
    rules,
    available: authoritative ? !!app : fallback.available,
    complete: authoritative && !!state.control.policy?.complete,
    reason: authoritative
      ? result.reason
      : 'Compatibility inventory: listed exact-identity rules; no backend summary.',
    candidate,
    fallback,
  };
}
export class ActivityPolicy {
  private row?: Row;
  private state?: ClientState;
  private signature = '';
  private quick?: { direction: Direction; id: string };
  private saved = '';
  private quickValues?: {
    key: string;
    protocol: string;
    expiry: string;
    any: boolean;
    enabled: boolean;
  };
  constructor(private host: HTMLElement) {
    host.addEventListener('keydown', (event) => {
      if (event.key === 'Escape' && this.quick) {
        event.stopPropagation();
        const direction = this.quick.direction;
        this.quick = undefined;
        this.signature = '';
        if (this.state) this.update(this.row, this.state);
        host.querySelector<HTMLElement>(`.sidebar-policy[data-direction="${direction}"]`)?.focus();
      }
    });
    window.addEventListener('activity-rule-saved', (e) => {
      this.saved = (e as CustomEvent<string>).detail;
      this.signature = '';
      if (this.state) this.update(this.row, this.state);
    });
  }
  activate(direction: Direction) {
    if (!this.row || !this.state) return;
    const inv = selectionInventory(this.row, this.state);
    this.quick = {
      direction,
      id: inv.rules.some((r) => r.scope.direction === direction) ? '' : 'new',
    };
    this.signature = '';
    this.update(this.row, this.state);
    this.host.querySelector<HTMLElement>('.activity-quick select')?.focus({ preventScroll: true });
    this.host.scrollIntoView({ block: 'nearest' });
  }
  update(row: Row | undefined, state: ClientState) {
    if (this.row?.id !== row?.id) this.quick = undefined;
    this.row = row;
    this.state = state;
    this.host.hidden = !row || row.kind === 'overview';
    if (this.host.hidden || !row) return;
    const inv = selectionInventory(row, state),
      c = state.control;
    const signature = JSON.stringify([
      row.id,
      row.process?.id,
      inv.rules,
      inv.available,
      inv.complete,
      inv.reason,
      inv.app?.incoming,
      inv.app?.outgoing,
      inv.candidate?.id,
      canManageRules(c),
      c.generation,
      c.connected,
      c.enforcement,
      this.quick,
      this.saved,
    ]);
    if (signature === this.signature) return;
    this.signature = signature;
    const oldScroll = this.host.querySelector('.activity-rule-list')?.scrollTop || 0;
    const fragment = document.createDocumentFragment();
    fragment.append(el('h3', 'Rules', 'info-section-title'));
    const scope = el(
      'p',
      row.kind === 'process'
        ? 'Application policy · all process instances'
        : row.kind === 'socket'
          ? 'Application policy · not this connection’s historical verdict'
          : 'Configured application policy',
      'activity-policy-context',
    );
    scope.title =
      'Rules target application key, executable revision and user ID. They do not target a process instance.';
    fragment.append(scope);
    const matrix = el('table', '', 'info-rule-matrix');
    matrix.innerHTML =
      '<colgroup><col style="width:65px"><col style="width:100px"><col></colgroup><tr><th>Type</th><th>In</th><th>Out</th></tr>';
    const line = el('tr');
    line.append(el('td', 'Blocker'));
    for (const d of directions) {
      const summary = inv.app?.[d];
      const label = summary
        ? policyLabel(summary)
        : inv.available
          ? configuredPolicy(inv.fallback[d], inv.fallback.now)
          : 'Unavailable';
      const cell = el('td'),
        b = el('button', label === 'No explicit rule' ? 'Not set' : label, 'sidebar-policy');
      b.dataset.direction = d;
      b.title = `${d} configured policy. ${summary?.reason || inv.reason}\n${summary?.enforcement.reason || 'Coverage unavailable'}`;
      b.setAttribute('aria-label', `${d} configured policy · ${label} · quick setter`);
      b.onclick = () => this.activate(d);
      cell.append(b);
      line.append(cell);
    }
    matrix.append(line);
    fragment.append(matrix);
    if (!inv.available) fragment.append(el('p', inv.reason, 'activity-policy-note'));
    else {
      const covered = directions.filter((d) => inv.app?.[d].enforcement.covered);
      fragment.append(
        el(
          'p',
          c.enforcement?.state === 'stopped'
            ? 'Stored rules · firewall stopped'
            : covered.length
              ? `Enforced: ${covered.join(' + ')}`
              : 'Stored rules · coverage unavailable / not covered',
          'activity-policy-coverage',
        ),
      );
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
      if (this.quick) fragment.append(this.quickSetter(inv));
      const list = el('div', '', 'activity-rule-list');
      list.setAttribute('aria-label', 'Relevant configured firewall rules');
      if (!inv.rules.length)
        list.append(
          el(
            'p',
            'No explicit firewall rules. Choose In or Out above to create one.',
            'activity-policy-note',
          ),
        );
      for (const ref of inv.rules) {
        const card = el('section', '', 'activity-rule');
        card.dataset.ruleId = ref.id;
        if (ref.id === this.saved) card.classList.add('recently-saved');
        const title = el('div', '', 'activity-rule-title');
        title.append(
          el('span', ref.scope.direction === 'incoming' ? 'In' : 'Out', 'rule-direction-chip'),
          el('strong', ref.action === 'allow' ? 'Allow' : 'Block', `rule-action-${ref.action}`),
          el(
            'span',
            ref.expired
              ? 'Expired'
              : ref.disabled
                ? 'Disabled'
                : ref.active
                  ? 'Enabled'
                  : 'Inactive',
            'rule-enabled-state',
          ),
        );
        card.append(title, el('p', scopeLabel(ref), 'activity-rule-scope'));
        const expiry = el(
          'p',
          ref.expires.startsWith('0001-')
            ? 'No expiry'
            : `Expires ${new Date(ref.expires).toLocaleString()}`,
          'activity-rule-expiry',
        );
        expiry.title = `${ref.id} · version ${ref.version} · ${ref.expires}`;
        card.append(expiry);
        const rule = this.editable(ref);
        if (canManageRules(c) && rule) {
          const actions = el('div', '', 'activity-rule-actions');
          const quick = el('button', 'Quick set');
          quick.disabled = ref.expired;
          quick.title = ref.expired
            ? 'Expired rule: use Advanced to explicitly review expiry.'
            : 'Change this exact rule; scope and expiry remain unchanged.';
          quick.onclick = () => {
            this.quick = { direction: ref.scope.direction as Direction, id: ref.id };
            this.signature = '';
            this.update(this.row, this.state!);
          };
          const advanced = el('button', 'Advanced');
          advanced.onclick = () => void openRule({ id: ref.id }, { activity: true });
          const toggle = el('button', ref.disabled ? 'Enable…' : 'Disable…');
          toggle.disabled = ref.expired;
          toggle.onclick = () =>
            void openRule({ id: ref.id }, { activity: true, quick: true, disabled: !ref.disabled });
          const remove = el('button', 'Delete…');
          remove.disabled = !c.capabilities?.includes('conditional-rule-delete-v1');
          const generation = c.generation;
          remove.onclick = () => confirmRuleDelete(rule, generation);
          actions.append(quick, advanced, toggle, remove);
          card.append(actions);
        } else if (canManageRules(c))
          card.append(
            el('p', 'Refresh required before editing this exact version.', 'activity-policy-note'),
          );
        list.append(card);
      }
      fragment.append(list);
      if (!canManageRules(c))
        fragment.append(el('p', 'Read-only rule access.', 'activity-policy-note'));
      const details = el('details', '', 'activity-policy-details');
      details.append(el('summary', 'Scope, defaults and enforcement details'));
      for (const d of directions) {
        const s = inv.app?.[d];
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
          'Incoming/outgoing means connection initiation, not upload/download. Editing rules may not disconnect already-approved TCP sessions.',
        ),
      );
      fragment.append(details);
    }
    this.host.replaceChildren(fragment);
    const list = this.host.querySelector('.activity-rule-list');
    if (list) list.scrollTop = oldScroll;
  }
  private editable(ref: PolicyRuleRef): Rule | undefined {
    return this.state?.control.rules?.find(
      (r) =>
        r.id === ref.id && Number.isSafeInteger(r.version) && String(r.version) === ref.version,
    );
  }
  private quickSetter(inv: ReturnType<typeof selectionInventory>) {
    const { direction, id } = this.quick!,
      c = this.state!.control;
    const box = el('section', '', 'activity-quick');
    box.setAttribute('aria-label', `${direction} quick setter`);
    const title = el('div', '', 'activity-quick-heading');
    title.append(
      el('strong', `${direction === 'incoming' ? 'Incoming' : 'Outgoing'} quick setter`),
    );
    const close = el('button', '×');
    close.setAttribute('aria-label', 'Close quick setter');
    close.onclick = () => {
      this.quick = undefined;
      this.signature = '';
      this.update(this.row, this.state!);
    };
    title.append(close);
    box.append(title);
    const target = el('select');
    target.setAttribute('aria-label', 'Rule to create or change');
    target.append(new Option('Choose a rule…', ''), new Option('New separate rule', 'new'));
    for (const r of inv.rules.filter((r) => r.scope.direction === direction))
      target.append(new Option(`${r.action} · ${scopeLabel(r)} · ${r.id}`, r.id));
    target.value = id;
    target.onchange = () => {
      this.quick = { direction, id: target.value };
      this.signature = '';
      this.update(this.row, this.state!);
    };
    box.append(target);
    const ref = inv.rules.find((r) => r.id === id),
      candidate = inv.candidate;
    const source: RuleSource | undefined =
      id === 'new' && candidate
        ? {
            observed: {
              generation: c.generation,
              row_id: candidate.id,
              process_id: candidate.owners[0],
              direction,
            } satisfies ObservedSource,
          }
        : ref && this.editable(ref)
          ? { id: ref.id }
          : undefined;
    const supported = id !== 'new' || c.capabilities?.includes('observed-rule-create-v1');
    const reason = !canManageRules(c)
      ? 'Rule management is read-only.'
      : !supported
        ? 'Backend update required for creation from Activity.'
        : !source
          ? 'Select a supported live native application or an existing exact rule.'
          : ref?.expired
            ? 'Expired rule: use Advanced and explicitly review expiry.'
            : '';
    if (reason) box.append(el('p', reason, 'activity-policy-note'));
    const protocol = el('select');
    protocol.setAttribute('aria-label', 'Quick rule protocol');
    protocol.append(new Option('TCP', 'tcp'), new Option('UDP', 'udp'));
    const key = `${this.row!.id}|${direction}|${id}`;
    if (this.quickValues?.key !== key)
      this.quickValues = {
        key,
        protocol: candidate?.socket.protocol === 'udp' ? 'udp' : 'tcp',
        expiry: 'hour',
        any: false,
        enabled: !ref?.disabled,
      };
    protocol.value = this.quickValues.protocol;
    const expiry = el('select');
    expiry.setAttribute('aria-label', 'Quick rule expiry');
    expiry.append(new Option('For 1 hour', 'hour'), new Option('Persistent', 'permanent'));
    expiry.value = this.quickValues.expiry;
    const any = el('input');
    any.type = 'checkbox';
    any.checked = this.quickValues.any;
    const anyLabel = el('label', '');
    anyLabel.append(any, document.createTextNode('All addresses and ports for this protocol'));
    const enabled = el('input');
    enabled.type = 'checkbox';
    enabled.checked = this.quickValues.enabled;
    for (const control of [protocol, expiry, any, enabled])
      control.addEventListener('change', () => {
        this.quickValues = {
          key,
          protocol: protocol.value,
          expiry: expiry.value,
          any: any.checked,
          enabled: enabled.checked,
        };
      });
    const enabledLabel = el('label', '');
    enabledLabel.append(enabled, document.createTextNode('Enabled'));
    if (id === 'new') box.append(protocol, expiry, anyLabel);
    else if (ref)
      box.append(el('p', scopeLabel(ref)), el('p', 'Scope and absolute expiry will be preserved.'));
    box.append(enabledLabel);
    const actions = el('div', '', 'activity-quick-actions');
    for (const action of ['allow', 'block'] as const) {
      const b = el('button', action === 'allow' ? 'Allow…' : 'Block…', `quick-${action}`);
      const refresh = () =>
        (b.disabled = !!reason || !source || !!ref?.expired || (id === 'new' && !any.checked));
      any.addEventListener('change', refresh);
      refresh();
      b.onclick = () => {
        if (source)
          void openRule(source, {
            activity: true,
            quick: true,
            action,
            disabled: !enabled.checked,
            ...(id === 'new'
              ? {
                  protocol: protocol.value,
                  expiry: expiry.value as 'hour' | 'permanent',
                  applicationScope: true,
                }
              : {}),
          });
      };
      actions.append(b);
    }
    const advanced = el('button', 'Advanced…');
    advanced.disabled = !source || !canManageRules(c) || !supported;
    advanced.onclick = () => {
      if (source) void openRule(source, { activity: true });
    };
    actions.append(advanced);
    box.append(
      actions,
      el(
        'p',
        'Preview and Save review the exact scope. No rule is saved by choosing an action.',
        'activity-policy-note',
      ),
    );
    return box;
  }
}

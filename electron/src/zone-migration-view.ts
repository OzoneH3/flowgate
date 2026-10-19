import {
  zoneLabel,
  zoneDefinitionDetails,
  ZONE_MIGRATION_CAPABILITY,
  zoneRuleLabel,
} from './network-zones';
import type { ClientState } from './protocol';
import type { MigrationTarget, MigrationView } from './zone-migration';
const el = <K extends keyof HTMLElementTagNameMap>(tag: K, text = '') => {
  const e = document.createElement(tag);
  e.textContent = text;
  return e;
};
let openView: ((target: MigrationTarget) => void) | undefined;
export function openZoneMigration(target: MigrationTarget) {
  openView?.(target);
}
export function setupZoneMigration() {
  const dialog = el('dialog');
  dialog.id = 'zoneMigrationDialog';
  dialog.className = 'essential-dialog zone-migration-dialog';
  const header = el('header'),
    title = el('h2', 'Review automatic network scope');
  title.tabIndex = -1;
  header.append(
    title,
    el(
      'p',
      'Existing rules keep their legacy scope until you explicitly confirm a reviewed migration. This does not start protection.',
    ),
  );
  const body = el('section');
  body.className = 'essential-body';
  const identity = el('p');
  identity.id = 'zoneMigrationIdentity';
  const message = el('p');
  message.id = 'zoneMigrationMessage';
  message.setAttribute('role', 'status');
  const definition = el('details'), definitionText = el('p');
  definition.id = 'zoneMigrationDefinition';
  definition.append(el('summary', 'Backend classification definition and revision'), definitionText);
  const warning = el(
    'p',
    'Automatic coverage follows future interface/address/route and registry changes. Local does not mean trusted.',
  );
  warning.className = 'warning';
  const coverage = el('section');
  coverage.id = 'zoneMigrationCoverage';
  const scope = el('details'),
    scopeText = el('pre');
  scope.append(el('summary', 'Full backend scope'), scopeText);
  const label = el('label'),
    accept = el('input');
  accept.id = 'zoneMigrationAccept';
  accept.type = 'checkbox';
  label.append(
    accept,
    ' I accept these coverage changes and future automatic updates for this exact rule.',
  );
  body.append(identity, message, definition, warning, coverage, scope, label);
  const footer = el('footer'),
    refresh = el('button', 'Refresh review'),
    save = el('button', 'Confirm migration'),
    check = el('button', 'Check result'),
    close = el('button', 'Close');
  refresh.id = 'zoneMigrationRefresh';
  save.id = 'zoneMigrationConfirm';
  check.id = 'zoneMigrationReconcile';
  close.id = 'zoneMigrationClose';
  for (const b of [refresh, save, check, close]) b.type = 'button';
  footer.append(refresh, save, check, close);
  dialog.append(header, body, footer);
  document.body.append(dialog);
  let state: MigrationView | undefined,
    target: MigrationTarget | undefined,
    token = '',
    busy = false,
    epoch = 0,
    timer: ReturnType<typeof setInterval> | undefined,
    polling = false;
  const render = (next: MigrationView) => {
    state = next;
    message.textContent = next.message;
    identity.textContent = next.original
      ? `${next.original.executable || next.original.filter.application || 'All programs'} · ${next.original.action} · ${next.original.filter.direction} ${next.original.filter.protocol} · ${zoneRuleLabel(next.original)} · rule ${next.original.id}, version ${next.original.version}`
      : '';
    const p = next.preview;
    if (p && p.token !== token) {
      token = p.token;
      accept.checked = false;
      coverage.replaceChildren();
      coverage.append(
        el(
          'strong',
          `${p.added_prefixes.length} added CIDRs · ${p.removed_prefixes.length} removed CIDRs · current snapshot only`,
        ),
      );
      for (const [name, values] of [
        ['Added coverage', p.added_prefixes],
        ['Removed coverage', p.removed_prefixes],
        ['Legacy coverage', p.old_prefixes],
        ['Automatic coverage now', p.new_prefixes],
      ] as const) {
        const d = el('details'),
          pre = el('pre', values.join('\n') || 'None');
        d.append(el('summary', `${name} (${values.length})`), pre);
        coverage.append(d);
      }
      const examples = el('details'),
        table = el('table'),
        head = el('tr');
      for (const s of ['Peer', 'Legacy', 'Automatic', 'Backend reason']) head.append(el('th', s));
      table.append(head);
      for (const s of p.samples) {
        const tr = el('tr');
        for (const text of [
          s.address,
          s.old_zone ? zoneLabel(s.old_zone) : 'Unavailable',
          s.new_zone ? zoneLabel(s.new_zone) : 'Unavailable',
          s.reason,
        ])
          tr.append(el('td', text));
        table.append(tr);
      }
      examples.append(
        el('summary', 'Backend classification examples (not observed connections)'),
        table,
      );
      coverage.append(examples);
      scopeText.textContent = p.scope_preview;
    }
    if (!p) {
      token = '';
      accept.checked = false;
      coverage.replaceChildren();
      scopeText.textContent = 'No reviewed scope yet.';
    }
    save.disabled = busy || !next.canConfirm || !accept.checked;
    accept.disabled = busy || !next.canConfirm;
    refresh.disabled = busy || next.phase === 'unknown' || next.phase === 'saving' || !target;
    check.hidden = next.phase !== 'unknown';
    check.disabled = busy || !next.connected;
    close.disabled = busy;
  };
  async function action(fn: () => Promise<MigrationView>) {
    if (busy) return;
    const seq = ++epoch;
    busy = true;
    if (state) render(state);
    try {
      const value = await fn();
      if (seq === epoch) render(value);
    } catch (error) {
      const failure = String((error as Error).message);
      if (state) state = { ...state, message: failure, canConfirm: false };
      message.textContent = failure;
    } finally {
      if (seq === epoch) {
        busy = false;
        if (state) render(state);
      }
    }
  }
  const stop = () => {
    clearInterval(timer);
    timer = undefined;
    ++epoch;
    busy = false;
  };
  close.onclick = () => {
    dialog.close();
    stop();
  };
  dialog.addEventListener('close', stop);
  dialog.addEventListener('cancel', (event) => {
    if (busy) event.preventDefault();
  });
  dialog.addEventListener('keydown', (event) => {
    if (
      event.key === 'Enter' &&
      (event.target === title || event.target === dialog || event.repeat)
    ) {
      event.preventDefault();
      event.stopPropagation();
    }
  });
  accept.onchange = () => {
    if (state) render(state);
  };
  save.onclick = () => {
    if (state?.canConfirm && accept.checked && token)
      void action(() => window.flowgate.zoneMigrationConfirm(token));
  };
  check.onclick = () => void action(() => window.flowgate.zoneMigrationReconcile());
  refresh.onclick = () => {
    if (target) void action(() => window.flowgate.zoneMigrationPreview(target!));
  };
  openView = (selection) => {
    if (dialog.open) {
      title.focus();
      return;
    }
    const unresolved = state?.phase === 'unknown' && state.target;
    target = structuredClone(unresolved || selection);
    token = '';
    accept.checked = false;
    coverage.replaceChildren();
    save.disabled = true;
    accept.disabled = true;
    identity.textContent = `Rule ${target.id}, version ${target.version}`;
    scopeText.textContent = 'No reviewed scope yet.';
    refresh.disabled = true;
    check.hidden = true;
    if (!unresolved) state = undefined;
    message.textContent = unresolved
      ? 'Checking the earlier unresolved migration; no save is being retried.'
      : 'Checking exact scope changes…';
    dialog.showModal();
    title.focus();
    void action(() =>
      unresolved
        ? window.flowgate.zoneMigrationState()
        : window.flowgate.zoneMigrationPreview(target!),
    );
    timer = setInterval(async () => {
      if (busy || polling || !dialog.open) return;
      const seq = epoch;
      polling = true;
      try {
        const value = await window.flowgate.zoneMigrationState();
        if (seq === epoch && !busy) render(value);
      } catch (error) {
        message.textContent = String(error);
      } finally {
        polling = false;
      }
    }, 750);
  };
  window.addEventListener('pagehide', stop);
  const button = el('button', 'Review automatic scope…');
  button.id = 'migrateZone';
  button.type = 'button';
  button.disabled = true;
  document.querySelector('#rulesView .filterbar')!.append(button);
  return {
    update(next: ClientState, selected: string) {
      definitionText.textContent = zoneDefinitionDetails(next.control.networkZones);
      const rule = next.control.rules?.find((r) => r.id === selected);
      const unresolved = state?.phase === 'unknown' && state.target;
      button.textContent = unresolved ? 'Check migration result…' : 'Review automatic scope…';
      button.hidden =
        !unresolved &&
        (!next.control.capabilities?.includes(ZONE_MIGRATION_CAPABILITY) ||
          !rule?.filter.network_zone ||
          rule.schema !== 4);
      button.disabled =
        (!unresolved && !rule) ||
        !next.control.connected ||
        !next.control.permissions?.can_manage_rules;
      button.onclick = () => {
        if (unresolved) openView?.(unresolved);
        else if (rule)
          openView?.({ generation: next.control.generation, id: rule.id, version: rule.version });
      };
    },
  };
}

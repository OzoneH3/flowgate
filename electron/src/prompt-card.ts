import { applicationHeading } from './application-heading';
import { connectionPresentation } from './connection-presentation';
import { REMEMBER_DURATIONS, type RememberOption } from './decision-remember';
import { FOR_A_WHILE_NOTE, FOR_A_WHILE_TOOLTIP } from './process-lease';
import type { ViewEvent } from './protocol';

// The request card shared by the permission window and the Pending requests
// tab. First view is compact: application,
// direction, remote endpoint, one local/protocol line, remaining time, then
// Allow | Deny | Remember | For a while. Everything technical sits behind the
// single "Details" disclosure. Only structure here; the renderer wires state.
export interface CardOptions {
  name: string;
  rememberMode: boolean;
  forAWhile: boolean;
  rememberOptions: RememberOption[];
}
function el<K extends keyof HTMLElementTagNameMap>(tag: K, text = '', className = '', id = '') {
  const x = document.createElement(tag);
  if (text) x.textContent = text;
  if (className) x.className = className;
  if (id) x.id = id;
  return x;
}
function row(list: HTMLElement, label: string, value: string, id = '') {
  const dd = el('dd', value || 'Unknown', '', id);
  list.append(el('dt', label), dd);
  return dd;
}
function checkbox(id: string, label: string, className: string, title = '') {
  const wrap = el('label', '', className),
    box = el('input', '', '', id);
  box.type = 'checkbox';
  wrap.append(box, ' ' + label);
  if (title) wrap.title = title;
  return wrap;
}
export function buildRequestCard(e: ViewEvent, o: CardOptions): HTMLElement[] {
  const p = connectionPresentation(e.flow),
    protocol = e.flow.protocol.toUpperCase();
  const route = el('div', '', 'connection-route');
  route.title = p.relation;
  route.append(
    el('h3', `${p.direction} connection`, 'connection-banner'),
    applicationHeading(e.attribution.application, o.name),
    el('strong', e.flow.remote, 'remote-endpoint'),
  );
  const nodes: HTMLElement[] = [
    route,
    el('p', `${protocol} · local ${e.flow.local} · ${p.zone}`, 'connection-line', 'connectionLine'),
  ];
  if (!e.attribution.visibility_complete || e.attribution.status !== 'directly-associated')
    nodes.push(el('p', `Attribution: ${e.attribution.status} · see Details`, 'attribution-warning'));
  const similar = el('p', '', 'similar-requests', 'similarRequests');
  nodes.push(el('p', '', 'expiry'), similar, el('div', '', 'lease-info', 'leaseInfo'));

  const details = el('details', '', 'identity-details', 'requestMore');
  details.append(el('summary', 'Details'));
  const list = el('dl', '', 'connection-fields', 'detailFields');
  row(list, 'Direction', p.relation);
  row(list, 'Remote', e.flow.remote);
  row(list, 'Local', e.flow.local);
  row(list, 'Protocol', protocol);
  row(list, 'Network', `${p.zone}${e.flow.network_scope?.reason ? '\n' + e.flow.network_scope.reason : ''}`);
  row(list, 'Deadline', e.deadline);
  row(list, 'Executable', e.attribution.application?.executable || 'Unavailable');
  row(
    list,
    'Process',
    e.attribution.owners.map((x) => `PID ${x.pid} · start ${x.start_ticks} · UID ${x.uid}`).join('\n') ||
      'Unavailable',
  );
  row(list, 'Attribution', `${e.attribution.status}\n${e.attribution.reason}`);
  row(
    list,
    'Coverage',
    e.attribution.visibility_complete
      ? 'Backend reports complete visibility'
      : 'Limited observation; hidden owners or races may remain',
  );
  row(list, 'Asked by', '', 'askSource');
  row(list, 'Scope', '', 'permissionTarget');
  row(list, 'Status', e.reason, 'requestStatus');
  const revalidation = el('pre', '', 'scope-preview', 'revalidationDetails');
  revalidation.hidden = true;
  details.append(list, el('p', '', 'scope-preview', 'scopePreview'), revalidation);
  nodes.push(details);

  // Sticky at the bottom of the scrolling body: the decision row and the
  // selected option's controls (incl. the deletion time) stay visible.
  const dock = el('div', '', 'decision-dock', 'decisionDock');
  const controls = el('div', '', 'decision-controls', 'decisionControls');
  for (const [id, label] of [
    ['allow', 'Allow'],
    ['block', 'Deny'],
  ] as const) {
    const button = el('button', label, id, id);
    button.type = 'button';
    controls.append(button);
  }
  if (o.rememberMode) controls.append(checkbox('rememberToggle', 'Remember', 'remember-toggle'));
  if (o.forAWhile)
    controls.append(checkbox('forAWhileToggle', 'For a while', 'option-toggle for-a-while-toggle', FOR_A_WHILE_TOOLTIP));
  dock.append(controls);
  if (o.forAWhile) {
    const note = el('p', FOR_A_WHILE_NOTE, 'for-a-while-note', 'forAWhileNote');
    note.hidden = true;
    dock.append(note);
  }
  if (o.rememberMode) {
    const panel = el('fieldset', '', 'remember-panel', 'rememberPanel');
    panel.hidden = true;
    panel.append(el('legend', 'Create rule for:'));
    for (const option of o.rememberOptions) {
      const label = el('label', '', 'remember-field'),
        input = el('input');
      input.type = 'checkbox';
      input.dataset.field = option.field;
      input.dataset.available = String(option.available);
      if (option.field === 'application') {
        input.checked = true;
        input.disabled = true;
        label.title = 'The rule always applies to this application';
      } else label.title = option.reason || '';
      label.append(input, ' ' + option.label);
      panel.append(label);
    }
    const durationLabel = el('label', 'Delete the rule after: ', 'remember-duration'),
      duration = el('select', '', '', 'rememberDuration');
    for (const d of REMEMBER_DURATIONS) duration.append(new Option(d.label, String(d.seconds)));
    durationLabel.append(duration);
    const summary = el('p', '', 'remember-summary', 'rememberSummary');
    summary.setAttribute('role', 'status');
    const refresh = el('button', 'Refresh review', 'link-button', 'refreshDecision');
    refresh.type = 'button';
    refresh.hidden = true;
    panel.append(durationLabel, summary, refresh);
    dock.append(panel);
  }
  const note = el('p', '', 'decision-note', 'decisionNote'),
    review = el('p', '', 'decision-review', 'decisionReview'),
    result = el('p', '', 'request-result', 'requestResult');
  note.setAttribute('role', 'status');
  result.setAttribute('role', 'status');
  const reconcile = el('button', 'Check result', 'link-button', 'decisionReconcile'),
    future = el('button', 'Create application rule for future connections…', 'link-button', 'futureApplicationRule');
  reconcile.type = future.type = 'button';
  reconcile.hidden = future.hidden = true;
  dock.append(note, review, result, reconcile, future);
  nodes.push(dock);
  return nodes;
}

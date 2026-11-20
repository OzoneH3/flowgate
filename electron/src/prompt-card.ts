import { accountLabel } from './accounts';
import { applicationHeading } from './application-heading';
import { attributionReasonLabel } from './attribution-reason';
import { connectionPresentation } from './connection-presentation';
import { REMEMBER_DURATIONS, type RememberOption } from './decision-remember';
import { FOR_A_WHILE_NOTE, FOR_A_WHILE_TOOLTIP, durationLabel } from './process-lease';
import { PREVIOUS_REVISION_NOTICE, previousRevisionTitle } from './prompt-decision';
import type { Application, ViewEvent } from './protocol';
import { gameIconApplication, provenanceDetails, targetLines } from './provenance';
import { pairDetailRows, type LocalPairView } from './local-pair';
import { connectionFields, connectionHeader, fromTo, promptSummary, rememberLabel } from './prompt-summary';

// Both surfaces use the same request content and controls. The popup exposes
// its sections to permission-popup.css. The renderer binds decision state.
export interface CardOptions {
  name: string;
  popup?: boolean;
  rememberMode: boolean;
  forAWhile: boolean;
  rememberOptions: RememberOption[];
  // decision-for-a-while-durations-v1 (FlowGate extension): offered durations.
  forAWhileDurations?: number[];
  // local-pair-v1: both endpoints of a same-host connection (renderer computes).
  pair?: LocalPairView;
  // The verified game's own application (icon), when Activity lists it.
  gameApplication?: Application;
  // Details view state survives a card rebuild of the same request.
  detailsOpen?: boolean;
  onDetails?: (open: boolean) => void;
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
function addClass(node: HTMLElement, name: string) {
  node.className = node.className ? node.className + ' ' + name : name;
}
function checkbox(id: string, label: string, className: string, title = '') {
  const wrap = el('label', '', className),
    box = el('input', '', '', id);
  box.type = 'checkbox';
  wrap.append(box, ' ' + label);
  if (title) wrap.title = title;
  return wrap;
}
/** One expandable Details section with its own field list. */
function section(parent: HTMLElement, title: string, key: string, open = false) {
  const box = el('details', '', 'detail-section');
  box.dataset.section = key;
  box.open = open;
  box.append(el('summary', title));
  const list = el('dl', '', 'connection-fields');
  box.append(list);
  parent.append(box);
  return { box, list };
}
export function buildRequestCard(e: ViewEvent, o: CardOptions): HTMLElement[] {
  const p = connectionPresentation(e.flow),
    protocol = e.flow.protocol.toUpperCase(),
    summary = promptSummary(e, o.name);

  // ---- first view ----------------------------
  // Preserve the From/To roles even when the popup leads with the application.
  const route = el('div', '', 'connection-route nl-card-top', 'requestSummary');
  const bar = el('h3', '', 'connection-banner nl-bar', 'connectionHeader');
  const chevron = el('button', '', 'nl-chevron', 'cardCollapse');
  chevron.type = 'button';
  chevron.setAttribute('aria-label', 'Collapse connection details');
  chevron.setAttribute('aria-expanded', 'true');
  bar.append(chevron, el('span', '', `nl-direction nl-${e.flow.direction === 'incoming' ? 'in' : 'out'}`), el('span', connectionHeader(e.flow), 'nl-bar-text'));
  const sides = fromTo(e, summary);
  const programCell = () => {
    // The game's own metadata (icon) never renames the verified title.
    const game = summary.contextApplication || (summary.ownIdentity ? undefined : gameIconApplication(e.attribution.provenance) || o.gameApplication);
    const heading = summary.contextApplication
      ? applicationHeading(summary.contextApplication, summary.title)
      : game
      ? applicationHeading(game, summary.title, summary.title)
      : applicationHeading(
          summary.ownIdentity
            ? e.attribution.application
            : { key: '', revision: '', name: summary.title, executable: e.attribution.application?.executable || '' },
          summary.title,
        );
    heading.id = 'requestApplication';
    if (o.popup) {
      heading.setAttribute('role', 'heading');
      heading.setAttribute('aria-level', '1');
      heading.querySelector('.application-icon')?.setAttribute('aria-hidden', 'true');
    }
    addClass(heading, 'nl-program');
    const cell = el('div', '', 'nl-cell');
    cell.append(heading);
    if (summary.owner) {
      // A Proton game is the launch context; the helper owns the socket.
      const owner = el('span', '', 'request-owner nl-owner', 'requestOwner');
      owner.append(el('span', 'socket owner ', 'nl-owner-label'), el('span', summary.owner, 'nl-owner-name'));
      owner.title = summary.contextApplication
        ? `${summary.title} was invoked through ${summary.owner}; permission still applies to the interpreter itself — see Details`
        : e.attribution.application?.kind === 'electron'
          ? `${summary.owner} (Electron runtime) opened this connection for this application; verified through its process chain — see Details`
          : `${summary.owner} opened this connection; ${summary.title} is the game it was launched for`;
      cell.append(owner);
    }
    if (summary.launchedBy) {
      // Display only: the program that started this one (e.g. Heroic → nile).
      const parent = e.attribution.provenance?.parent;
      const by = el('span', '', 'request-owner nl-owner', 'requestLaunchedBy');
      const label = el('span', summary.launchedBy, 'nl-owner-name');
      by.append(el('span', 'launched by ', 'nl-owner-label'), label);
      by.title = `${parent?.name} (PID ${parent?.pid}) started this program; rules still apply to ${summary.owner || summary.title} itself`;
      if (parent?.application?.key)
        void window.flowgate
          .applicationMetadata([JSON.stringify([parent.application.key, parent.application.revision, parent.application.executable])])
          .then((m) => {
            const name = Object.values(m)[0]?.name;
            if (name) label.textContent = name;
          })
          .catch(() => {});
      cell.append(by);
    }
    if (summary.note) {
      const note = el('span', summary.note, 'request-owner nl-owner nl-unverified', 'requestHostedNote');
      note.title = e.attribution.application?.hosted?.reason || '';
      cell.append(note);
    }
    return cell;
  };
  const peerCell = (text: string) => {
    const cell = el('div', '', 'nl-cell');
    cell.append(el('span', text, 'nl-peer', 'requestDestination'));
    return cell;
  };
  const box = el('div', '', 'nl-box', 'fromToBox');
  for (const [label, side] of [
    ['From', sides.from],
    ['To', sides.to],
  ] as const) {
    const r = el('div', '', 'nl-row');
    if (o.popup) r.id = side.kind === 'program' ? 'requestIdentity' : 'requestPeer';
    r.append(el('span', label, 'nl-label'), side.kind === 'program' ? programCell() : peerCell(side.text));
    if (o.popup && side.kind === 'program') box.prepend(r);
    else box.append(r);
  }
  const f = connectionFields(e);
  const fields = el('dl', '', 'nl-fields', 'connectionFields');
  const empty = (label: string, id: string) => {
    const dd = el('dd', '', '', id);
    fields.append(el('dt', label), dd);
    return dd;
  };
  const appField = empty('Application:', 'fieldApplication');
  appField.append(el('span', f.application, 'nl-link'));
  appField.title = f.executable;
  row(fields, 'Process Id:', f.process, 'fieldProcess');
  for (const [label, id, ep] of [
    ['Local Address:', 'fieldLocal', f.local],
    ['Remote Address:', 'fieldRemote', f.remote],
  ] as const) {
    const dd = empty(label, id);
    dd.append(el('span', ep.address, 'nl-address'));
    if (ep.port) {
      const group = el('span', '', 'nl-port-group');
      group.append(el('span', 'Port:', 'nl-port-label'), el('span', ep.port, 'nl-port'));
      dd.append(group);
    }
  }
  if (o.popup) route.append(box, bar, fields);
  else route.append(bar, box, fields);
  const meta = el('div', '', 'request-meta nl-links');
  const status = el('p', '', 'expiry request-status-line', 'requestStatusLine');
  status.setAttribute('role', 'status');
  const more = el('button', 'Details', 'link-button details-link', 'detailsToggle');
  more.type = 'button';
  more.setAttribute('aria-expanded', 'false');
  more.setAttribute('aria-controls', 'requestMore');
  meta.append(more, status);
  const card = el('section', '', 'nl-card', 'requestCard');
  const nodes: HTMLElement[] = [card];
  card.append(route, meta);
  // The popup also keeps the application and peer visible when collapsed.
  chevron.onclick = () => {
    const collapsed = !fields.hidden;
    fields.hidden = meta.hidden = collapsed;
    if (!o.popup) box.hidden = collapsed;
    chevron.setAttribute('aria-expanded', String(!collapsed));
    o.onDetails?.(false);
  };

  // ---- Details view (separate; hidden until Details is clicked) -------------
  const details = el('section', '', 'request-details-view', 'requestMore');
  details.hidden = true;
  details.setAttribute('aria-label', 'Request details');
  const back = el('button', '‹ Back', 'link-button details-back', 'detailsBack');
  back.type = 'button';
  const head = el('div', '', 'details-head');
  head.append(back, el('h4', 'Details'));
  details.append(head);

  const conn = section(details, 'Connection', 'connection', true).list;
  row(
    conn,
    'Direction',
    e.local_peer
      ? e.flow.direction === 'incoming'
        ? 'Local program → this program (same host)'
        : 'This program → local program (same host)'
      : p.relation,
  );
  row(conn, 'Remote', e.flow.remote);
  row(conn, 'Local', e.flow.local);
  row(conn, 'Protocol', protocol);
  row(conn, 'Network', p.zone);
  if (e.flow.network_scope?.reason) row(conn, 'Zone basis', e.flow.network_scope.reason);
  if (e.flow.netns) row(conn, 'Namespace', e.flow.netns);
  row(conn, 'Deadline', e.deadline);

  const app = section(details, 'Application', 'application').list;
  row(app, 'Executable', e.attribution.application?.executable || 'Unavailable');
  if (e.attribution.permission_target?.prefix) row(app, 'Prefix', e.attribution.permission_target.prefix);
  row(
    app,
    'Process',
    e.attribution.owners.map((x) => `PID ${x.pid} · start ${x.start_ticks} · ${accountLabel(x.uid)}`).join('\n') || 'Unavailable',
  );
  row(app, 'Attribution', e.attribution.status);
  if (e.attribution.reason_code)
    row(app, 'Attribution category', attributionReasonLabel(e.attribution.reason_code)).title = e.attribution.reason_code;
  row(app, 'Reason', e.attribution.reason);
  const table=e.attribution.runtime_table;
  if(table){
    row(app,'Windows socket owner',table.windows_handle_holders.map(h=>`${h.image} · Windows PID ${h.pid} · creation ${h.creation_time}`).join('\n'));
    row(app,'Broker / socket',`PID ${table.broker_pid} · start ${table.broker_start_ticks} · cookie ${table.socket_cookie}`);
    row(app,'Verification',table.method);
  }
  row(
    app,
    'Coverage',
    e.attribution.visibility_complete ? 'Complete visibility' : 'Limited; hidden owners or races may remain',
  );

  const hosted = e.attribution.application?.hosted;
  if (hosted) {
    // Reported hosted context is distinct from permission authority.
    const l = section(details, 'Electron app', 'hosted').list;
    row(l, 'State', hosted.state === 'best-effort' ? 'Best-effort application match. Saved rules use the user, runtime and application entry; manipulated launch evidence can impersonate this identity.' : hosted.state === 'verified' ? 'Verified by reporting backend' : 'Application unverified. Bundle metadata is display context only; application-wide Remember is unavailable.');
    row(l, 'Runtime', hosted.runtime);
    if (hosted.bundle) row(l, hosted.state === 'verified' ? 'Bundle' : 'Observed bundle argument', hosted.bundle);
    if (hosted.package_name)
      row(l, 'Package', [hosted.package_name, hosted.product_name, hosted.version].filter(Boolean).join(' · '));
    if (hosted.integrity) row(l, 'Integrity', hosted.integrity);
    if (hosted.chain.length)
      row(l, 'Chain', hosted.chain.map((c) => `PID ${c.pid} · start ${c.start_ticks} · ${c.type}`).join('\n'));
    row(l, 'Reason', hosted.reason);
  }
  const launch = provenanceDetails(e);
  if (launch.length) {
    const l = section(details, 'Launch', 'launch').list;
    for (const [label, value] of launch) row(l, label, value);
  }
  if (o.pair) {
    const l = section(details, 'Local connection', 'local-pair').list;
    for (const [label, value] of pairDetailRows(o.pair)) row(l, label, value);
  }

  const rule = section(details, 'Rule', 'rule').list;
  const lines = targetLines(e.attribution.permission_target);
  if (lines.length) {
    // Scope of the option currently selected; the renderer switches it.
    const scope = row(rule, 'Selected', `${lines[0].label}: ${lines[0].text}`, 'permissionScope');
    addClass(scope, 'permission-scope');
    for (const line of lines)
      scope.dataset[line.label === 'Once' ? 'once' : line.label === 'Remember' ? 'remember' : 'forAWhile'] =
        `${line.label}: ${line.text}`;
  }
  if (e.attribution.permission_target) {
    row(rule, 'Remember', e.attribution.permission_target.remember);
    if (e.attribution.permission_target.shared_with_note)
      row(rule, 'Shared', e.attribution.permission_target.shared_with_note);
    row(rule, 'Rule key', e.attribution.permission_target.key_basis);
  }
  row(rule, 'Asked by', '', 'askSource');
  row(rule, 'Scope', '', 'permissionTarget');
  addClass(row(rule, 'Preview', '', 'scopePreview'), 'scope-preview');
  row(rule, 'Overlaps', '', 'ruleOverlaps');
  if (e.previous_revision_rules?.length) {
    const notice = row(rule, 'Revision', PREVIOUS_REVISION_NOTICE + '\n' + previousRevisionTitle(e.previous_revision_rules), 'previousRevisionNotice');
    addClass(notice, 'previous-revision');
  }

  const statusSection = section(details, 'Status', 'status'),
    state = statusSection.list;
  row(state, 'Backend', e.reason, 'requestStatus');
  row(state, 'Last result', '', 'requestLastResult');
  row(state, 'Review', '', 'requestReviewDetail');
  addClass(row(state, 'Similar', '', 'similarRequests'), 'similar-requests');
  const failure = row(state, 'Failure', '', 'revalidationDetails');
  addClass(failure, 'scope-preview');
  const leases = el('div', '', 'lease-info', 'leaseInfo');
  statusSection.box.append(leases);
  card.append(details);

  // ---- decision row ----------------------------------------------------------
  const dock = el('div', '', 'decision-dock', 'decisionDock');
  const controls = el('div', '', 'decision-controls', 'decisionControls');
  const actions = o.popup ? el('div', '', '', 'decisionActions') : controls;
  const options = o.popup ? el('div', '', '', 'decisionOptions') : controls;
  if (o.popup) controls.append(actions, options);
  for (const [id, label] of [
    ['allow', 'Allow'],
    ['block', 'Deny'],
  ] as const) {
    const button = el('button', label, id, id);
    button.type = 'button';
    actions.append(button);
  }
  if (o.rememberMode)
    options.append(checkbox('rememberToggle', 'Remember', 'remember-toggle', "Create rule and don't ask me again"));
  if (o.forAWhile)
    options.append(checkbox('forAWhileToggle', 'For a while', 'option-toggle for-a-while-toggle', FOR_A_WHILE_TOOLTIP));
  if (o.forAWhile && (o.forAWhileDurations?.length ?? 0) > 1) {
    // Shown only while For a while is checked (renderer), beside Allow/Deny.
    const wrap = el('span', '', 'for-a-while-duration', 'forAWhileDurationWrap'),
      select = el('select', '', '', 'forAWhileDuration');
    select.setAttribute('aria-label', 'For a while duration');
    for (const d of o.forAWhileDurations!) select.append(new Option(durationLabel(d), String(d)));
    wrap.append(select, el('span', '', 'for-a-while-expiry', 'forAWhileExpiry'));
    wrap.hidden = true;
    options.append(wrap);
  }
  dock.append(controls);
  const onceNote = el('p', '', 'decision-note', 'udpOnceNote');
  onceNote.hidden = true;
  dock.append(onceNote);
  if (o.forAWhile) {
    const note = el('p', FOR_A_WHILE_NOTE, 'for-a-while-note', 'forAWhileNote');
    note.hidden = true;
    dock.append(note);
  }
  if (o.rememberMode) {
    const panel = el('fieldset', '', 'remember-panel', 'rememberPanel');
    panel.hidden = true;
    panel.append(el('legend', 'Create rule for:'));
    // What the rule covers, concisely, before the click (helper/prefix scope).
    const target = el('p', rememberLabel(e.attribution.permission_target), 'remember-scope', 'rememberScope');
    if (e.attribution.permission_target?.shared_with_note) target.title = e.attribution.permission_target.shared_with_note;
    panel.append(target);
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
    const durationLabel = el('label', 'Rule expires after: ', 'remember-duration'),
      duration = el('select', '', '', 'rememberDuration');
    for (const d of REMEMBER_DURATIONS) duration.append(new Option(d.label, String(d.seconds)));
    duration.title = 'At expiry, the rule stops matching. Expiry does not immediately delete the saved rule.';
    durationLabel.append(duration);
    const summary = el('p', '', 'remember-summary', 'rememberSummary');
    summary.setAttribute('role', 'status');
    const refresh = el('button', 'Refresh review', 'link-button', 'refreshDecision');
    refresh.type = 'button';
    refresh.hidden = true;
    panel.append(durationLabel, refresh);
    statusSection.box.append(summary);
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
  statusSection.box.append(note, review, result);
  dock.append(reconcile, future);
  card.append(dock);

  // Details is a separate view: the first view hides while it is open.
  const toggle = (open: boolean) => {
    details.hidden = !open;
    route.hidden = open;
    meta.hidden = open;
    more.setAttribute('aria-expanded', String(open));
  };
  more.onclick = () => {
    toggle(true);
    back.focus({ preventScroll: true });
    o.onDetails?.(true);
  };
  back.onclick = () => {
    toggle(false);
    more.focus({ preventScroll: true });
    o.onDetails?.(false);
  };
  if (o.detailsOpen) toggle(true);
  return nodes;
}

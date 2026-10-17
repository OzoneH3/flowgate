import { ruleStatus, ruleState, ruleDescription } from './rule-status';
import type { Application } from './protocol';
import { TrafficGraph } from './graph';
import { setupWorkflows, updateWorkflows } from './workflows';
import type { ClientState, ViewEvent, Scope } from './protocol';
import {
  hierarchy,
  flatten,
  allRows,
  sum,
  metricLabel,
  endpoint,
  trafficDetails,
  ownershipExplanation,
  type Row,
  type Metric,
} from './model';
const root = document.querySelector<HTMLDivElement>('#app')!;
const promptGeneration = new URL(location.href).searchParams.get('generation');
const promptID = new URL(location.href).searchParams.get('request');
let state: ClientState;
let selected = '';
let graph: TrafficGraph | undefined;
let selectedRequest = promptID ?? '';
let chosenScope: Scope = 'once';
let tab = 'activity';
let sequence = '';
let eventSignature = '';
let detailSignature = '';
let roots: Row[] = [];
let visible: { row: Row; depth: number }[] = [];
let sort = 'name',
  descending = false;
const expanded = new Set<string>();
const localSubmitted = new Set<string>();
let ruleSignature = '';
let lastGeneration = '';
const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;
function element<K extends keyof HTMLElementTagNameMap>(tag: K, text = '', className = '') {
  const e = document.createElement(tag);
  e.textContent = text;
  e.className = className;
  return e;
}
function rowIcon(kind: Row['kind']) {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', '0 0 16 16');
  svg.setAttribute('class', 'row-icon');
  svg.setAttribute('aria-hidden', 'true');
  const path = document.createElementNS(svg.namespaceURI, 'path');
  path.setAttribute(
    'd',
    kind === 'application'
      ? 'M2 2h12v9H2zM5 14h6M8 11v3M2 5h12'
      : kind === 'process'
        ? 'M5 3h6v10H5zM2 5h3m6 0h3M2 8h3m6 0h3M2 11h3m6 0h3'
        : kind === 'socket'
          ? 'M2 5h4v6H2zM10 5h4v6h-4zM6 8h4'
          : 'M3 3h10v10H3zM6 6a2 2 0 1 1 3 2l-1 1M8 11v1',
  );
  svg.append(path);
  return svg;
}

const iconCache = new Map<string, string | null>();
const iconPending = new Set<string>();
let iconScheduled = false;
function installedIcon(app: Application | undefined, kind: Row['kind']) {
  const span = element('span', '', 'application-icon');
  span.append(rowIcon(kind));
  if (!app?.key) return span;
  const key = JSON.stringify([app.key, app.revision, app.executable]);
  span.dataset.iconKey = key;
  const paint = (node: HTMLElement, url: string) => {
    const img = element('img');
    img.src = url;
    img.alt = '';
    img.width = img.height = 14;
    img.onerror = () => {
      if (node.dataset.iconKey) iconCache.set(node.dataset.iconKey, null);
      node.replaceChildren(rowIcon('application'));
    };
    node.replaceChildren(img);
  };
  const url = iconCache.get(key);
  if (url) paint(span, url);
  else if (!iconCache.has(key)) {
    if (iconPending.size < 2048) iconPending.add(key);
    if (!iconScheduled) {
      iconScheduled = true;
      queueMicrotask(async () => {
        const keys = [...iconPending].slice(0, 128);
        keys.forEach((k) => iconPending.delete(k));
        try {
          const result = await window.flowgate.applicationIcons(keys);
          for (const [key, url] of Object.entries(result)) {
            if (iconCache.size >= 2048) iconCache.delete(iconCache.keys().next().value!);
            iconCache.set(key, url);
            if (url)
              for (const node of document.querySelectorAll<HTMLElement>('[data-icon-key]'))
                if (node.dataset.iconKey === key) paint(node, url);
          }
        } catch {
          for (const key of keys) iconCache.set(key, null);
        } finally {
          iconScheduled = false;
        }
      });
    }
  }
  return span;
}
function rowApplication(r: Row) {
  return (
    r.process?.application ||
    r.displayApplication ||
    (r.socket?.owners.length === 1
      ? state.observation.activity?.processes[r.socket.owners[0]]?.application
      : r.socket?.display_application)
  );
}
function ruleIndicators(r: Row) {
  const status = ruleStatus(r, state),
    cell = element('td', '', 'rule-status');
  cell.title = status.reason;
  if (!status.available) {
    cell.append(element('span', '—', 'rule-unavailable'));
    cell.setAttribute('aria-label', status.reason);
    return cell;
  }
  for (const direction of ['incoming', 'outgoing'] as const) {
    const group = element('span', '', 'rule-direction');
    group.append(element('span', direction === 'incoming' ? 'In' : 'Out', 'rule-direction-label'));
    const rules = status[direction];
    for (const type of ['allow', 'block', 'disabled', 'expired', 'unknown'] as const) {
      const matches = rules.filter((rule) => ruleState(rule, status.now) === type);
      if (!matches.length) continue;
      const glyph = { allow: '✓', block: '×', disabled: '○', expired: '◷', unknown: '?' }[type];
      const indicator = element('span', glyph, 'rule-indicator rule-' + type);
      indicator.title =
        `${direction}: ${matches.length} ${type} scoped rule(s)\n` +
        matches.map((rule) => ruleDescription(rule, status.now)).join('\n');
      indicator.setAttribute('aria-label', indicator.title);
      group.append(indicator);
    }
    if (!rules.length) {
      const none = element('span', '·', 'rule-none');
      none.title = direction + ': no listed rules (not an Allow/Block verdict)';
      group.append(none);
    }
    cell.append(group);
  }
  return cell;
}

function field(container: HTMLElement, label: string, value: string) {
  container.append(element('dt', label), element('dd', value || 'Unknown'));
}
function message(text: string) {
  $('feedback').textContent = text;
}
const scopeLabels: Record<Scope, string> = {
  once: 'Once',
  application: 'Remember · 1 hour',
  persistent: 'Persistent until disabled / deleted',
};
if (promptID) {
  root.innerHTML = `<section class="prompt-shell"><header class="prompt-heading"><strong>FlowGate Blocker</strong><span>Pending connection permission</span></header><div id="promptBody"><div id="requestDetails"></div></div><footer><span id="controlStatus"></span><button id="dismiss">Decide later</button></footer><div id="feedback" role="status" aria-live="polite"></div></section>`;
  $('dismiss').onclick = () => void window.flowgate.dismissPrompt();
} else {
  root.innerHTML = `<header class="toolbar"><strong class="brand">▣ FlowGate</strong><span id="observerStatus"></span><span class="separator"></span><span id="controlStatus"></span></header><nav class="tabs" aria-label="Views"><button id="activityTab" aria-selected="true">Activity</button><button id="requestsTab" aria-selected="false">Pending requests <span id="pendingCount">0</span></button></nav><main id="activityView"><section class="activity-main"><div class="filterbar"><input id="search" type="search" aria-label="Search Activity" placeholder="Search application, path, PID or endpoint"><select id="filter" aria-label="Socket filter"><option value="all">All sockets</option><option value="active">Active TCP / connected UDP</option><option value="listening">Listening TCP / bound UDP</option></select><button id="expand">Expand all</button><button id="collapse">Collapse all</button></div><div class="table-scroll"><table id="tree" role="treegrid" tabindex="0" aria-label="Application process socket activity"><thead><tr id="headers"></tr></thead><tbody id="rows"></tbody></table></div><div id="activitySummary" class="summary"></div></section><aside><h2>Info View</h2><h3 id="selectedName">FlowGate Activity</h3><dl id="info"></dl><section id="trafficGraph"></section></aside></main><main id="requestsView" hidden><section class="request-list"><h2>Pending &amp; recent requests</h2><p class="hint">Select a request to decide. Dismissal grants nothing. Closing FlowGate leaves an independent controller running.</p><div class="table-scroll"><table id="requests"><thead><tr><th>Application</th><th>Direction</th><th>Protocol</th><th>Remote endpoint</th><th>State</th></tr></thead><tbody id="requestRows"></tbody></table></div></section><aside class="request-sidebar"><h2>Connection permission</h2><div id="requestDetails"></div></aside></main><footer><span>Activity and firewall control are independent.</span><span id="feedback" role="status" aria-live="polite"></span></footer>`;
  const columns = [
    ['name', 'Application / process / connection'],
    ['download_bps', 'DL rate'],
    ['upload_bps', 'UL rate'],
    ['rules', 'Rule Status'],
    ['count', 'Sockets'],
    ['pid', 'PID'],
    ['downloaded', 'Downloaded'],
    ['uploaded', 'Uploaded'],
    ['protocol', 'Protocol'],
    ['local', 'Local endpoint'],
    ['remote', 'Remote endpoint'],
    ['state', 'State'],
  ];
  for (const [key, title] of columns) {
    const th = element('th');
    th.className = 'col-' + key;
    const b = element('button', title);
    if (key === 'download_bps' || key === 'upload_bps') b.append(element('small', 'Auto units'));
    if (key === 'rules') b.append(element('small', 'Scoped inventory'));
    b.disabled = key === 'rules';
    b.onclick = () => {
      descending = sort === key ? !descending : ['upload_bps', 'download_bps'].includes(key);
      sort = key;
      renderTree();
    };
    th.append(b);
    $('headers').append(th);
  }
  const chooseTab = (next: string) => {
    tab = next;
    if ($('rulesView')) {
      $('rulesView').hidden = next !== 'rules';
      $('rulesTab').setAttribute('aria-selected', String(next === 'rules'));
    }
    $('activityView').hidden = next !== 'activity';
    $('requestsView').hidden = next !== 'requests';
    if (next === 'activity') void graph?.update(selected, sequence + ':shown');
    $('activityTab').setAttribute('aria-selected', String(next === 'activity'));
    $('requestsTab').setAttribute('aria-selected', String(next === 'requests'));
  };
  setupWorkflows(chooseTab);
  graph = new TrafficGraph($('trafficGraph'));
  window.flowgate.onNavigate((v) => {
    chooseTab('requests');
    message(v.message);
  });
  document.addEventListener('keydown', (e) => {
    if (e.ctrlKey && ['1', '2', '3'].includes(e.key)) {
      e.preventDefault();
      chooseTab({ '1': 'activity', '2': 'requests', '3': 'rules' }[e.key]!);
    }
    if (e.ctrlKey && e.key.toLowerCase() === 'p') {
      e.preventDefault();
      const event = currentEvent();
      if (event) void window.flowgate.openPrompt(event.id);
    }
  });
  $('activityTab').onclick = () => chooseTab('activity');
  $('requestsTab').onclick = () => chooseTab('requests');
  $('search').oninput = () => buildTree();
  $('filter').onchange = () => buildTree();
  $('expand').onclick = () => {
    for (const r of allRows(roots)) if (r.children.length) expanded.add(r.id);
    renderTree();
  };
  $('collapse').onclick = () => {
    expanded.clear();
    selected = '';
    renderTree();
    renderInfo();
  };
  $('tree').onkeydown = (e) => {
    if (['ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight'].includes(e.key)) e.preventDefault();
    let index = visible.findIndex((v) => v.row.id === selected);
    const row = visible[index]?.row;
    if (e.key === 'ArrowDown') index = Math.min(index + 1, visible.length - 1);
    else if (e.key === 'ArrowUp') index = Math.max(0, index - 1);
    else if (e.key === 'ArrowRight' && row?.children.length) {
      expanded.add(row.id);
      renderTree();
      return;
    } else if (e.key === 'ArrowLeft' && row) {
      if (expanded.has(row.id)) {
        expanded.delete(row.id);
        renderTree();
        return;
      }
      index = visible.findIndex((v) => v.row.id === row.parent);
    } else return;
    e.preventDefault();
    if (index >= 0) {
      selected = visible[index].row.id;
      renderTree();
      renderInfo();
      document
        .querySelector('tr[aria-selected="true"]')
        ?.scrollIntoView({ block: 'nearest', inline: 'nearest' });
    }
  };
}
function buildTree() {
  const a = state?.observation.activity;
  roots = a
    ? hierarchy(a, $<HTMLInputElement>('search').value, $<HTMLSelectElement>('filter').value)
    : [];
  const all = allRows(roots);
  const r = all.find((r) => r.id === selected);
  if (r) {
    let parent = r.parent;
    while (parent) {
      expanded.add(parent);
      parent = all.find((r) => r.id === parent)?.parent;
    }
  }
  if (expanded.size > 8192) {
    const ids = new Set(all.map((r) => r.id));
    for (const id of expanded) if (id !== 'unidentified' && !ids.has(id)) expanded.delete(id);
  }
  renderTree();
  renderInfo();
  $('activitySummary').textContent = a
    ? `${roots.reduce((n, r) => n + r.rows.length, 0)} / ${a.rows.length} sockets · ${a.complete ? 'Complete census' : 'Partial visibility'} · ${a.collected} · ${a.issues.join('; ')}`
    : state.observation.message;
  $('activitySummary').title = $('activitySummary').textContent || '';
}
function renderTree() {
  visible = flatten(roots, expanded, sort, descending);
  const body = $('rows');
  const fragment = document.createDocumentFragment();
  for (const { row: r, depth } of visible) {
    const tr = element('tr');
    tr.dataset.id = r.id;
    tr.setAttribute('aria-level', String(depth + 1));
    tr.setAttribute('aria-selected', String(selected === r.id));
    if (r.children.length) tr.setAttribute('aria-expanded', String(expanded.has(r.id)));
    tr.onclick = () => {
      selected = r.id;
      renderTree();
      renderInfo();
      $('tree').focus();
    };
    const name = element('td');
    name.className = `name depth-${depth}`;
    const toggle = element(
      'button',
      r.children.length ? (expanded.has(r.id) ? '▾' : '▸') : '·',
      'disclosure',
    );
    toggle.tabIndex = -1;
    toggle.setAttribute('aria-label', (expanded.has(r.id) ? 'Collapse ' : 'Expand ') + r.label);
    toggle.disabled = !r.children.length;
    toggle.onclick = (e) => {
      e.stopPropagation();
      if (expanded.has(r.id)) {
        expanded.delete(r.id);
        if (allRows([r]).some((v) => v.id === selected)) selected = r.id;
      } else expanded.add(r.id);
      renderTree();
      renderInfo();
    };
    name.append(
      toggle,
      installedIcon(r.kind === 'socket' ? undefined : rowApplication(r), r.kind),
      document.createTextNode(r.label),
    );
    name.title = r.process?.executable || r.socket?.socket.remote || r.label;
    tr.append(name);
    for (const key of ['download_bps', 'upload_bps'] as Metric[]) {
      const s = sum(r.rows, key);
      const td = element(
        'td',
        metricLabel(s, true),
        'numeric ' + (s.value && s.value > 0 ? (key === 'download_bps' ? 'down' : 'up') : ''),
      );
      td.title = `${s.known}/${s.count} measured sockets${s.mixed ? ' · incompatible measurement sources' : ''}`;
      tr.append(td);
    }
    tr.append(ruleIndicators(r));
    tr.append(
      element('td', String(r.rows.length), 'numeric'),
      element('td', r.pid === undefined ? '' : String(r.pid), 'numeric'),
    );
    for (const key of ['downloaded', 'uploaded'] as Metric[])
      tr.append(element('td', metricLabel(sum(r.rows, key)), 'numeric'));
    for (const value of [
      r.socket?.socket.protocol,
      r.socket?.socket.local,
      r.socket?.socket.remote,
      r.socket?.state,
    ]) {
      const td = element('td', value ?? '');
      td.title = value ?? '';
      tr.append(td);
    }
    fragment.append(tr);
  }
  body.replaceChildren(fragment);
  for (const th of Array.from($('headers').children)) {
    const key = th.className.slice(4);
    th.setAttribute('aria-sort', key === sort ? (descending ? 'descending' : 'ascending') : 'none');
  }
}
function renderInfo() {
  void graph?.update(selected, sequence);
  const live = $('info');
  const info = element('dl');
  const commit = () => {
    const details = element('details', '', 'info-technical');
    details.open = !!live.querySelector('details[open]');
    details.append(element('summary', 'Identity and measurement details'));
    const technical = element('dl');
    for (const dt of Array.from(info.querySelectorAll('dt'))) {
      if (
        [
          'Executable',
          'Identity',
          'Totals',
          'Evidence',
          'Socket identity',
          'Ownership evidence category',
          'Measurement',
          'Rule inventory',
          'Incoming rule scopes',
          'Outgoing rule scopes',
        ].includes(dt.textContent || '')
      ) {
        const dd = dt.nextElementSibling;
        technical.append(dt);
        if (dd) technical.append(dd);
      }
    }
    if (technical.childElementCount) {
      details.append(technical);
      info.append(details);
    }
    // Preserve text selection and expanded details during unchanged polling.
    if (live.textContent !== info.textContent) live.replaceChildren(...Array.from(info.childNodes));
  };
  const r = allRows(roots).find((r) => r.id === selected);
  const selectedName = $('selectedName');
  if (selectedName.dataset.identity !== (r?.id || '')) {
    selectedName.dataset.identity = r?.id || '';
    selectedName.replaceChildren(
      ...(r ? [installedIcon(rowApplication(r), r.kind)] : []),
      document.createTextNode(r?.label ?? 'FlowGate Activity'),
    );
  }
  if (!r) {
    field(
      info,
      'Selection',
      selected
        ? 'Selected socket is no longer visible.'
        : 'Select an application, process or connection.',
    );
    commit();
    return;
  }
  const inventory = ruleStatus(r, state);
  field(info, 'Rule inventory', inventory.reason);
  for (const direction of ['incoming', 'outgoing'] as const) {
    const rules = inventory[direction];
    field(
      info,
      direction === 'incoming' ? 'Rules · In' : 'Rules · Out',
      !inventory.available
        ? 'Unavailable'
        : ['allow', 'block', 'disabled', 'expired']
            .map(
              (type) =>
                `${rules.filter((rule) => ruleState(rule, inventory.now) === type).length} ${type}`,
            )
            .join(' · '),
    );
  }
  if (inventory.available)
    for (const direction of ['incoming', 'outgoing'] as const)
      field(
        info,
        direction === 'incoming' ? 'Incoming rule scopes' : 'Outgoing rule scopes',
        inventory[direction].map((rule) => ruleDescription(rule, inventory.now)).join('\n') ||
          'No listed rules; not a connection verdict.',
      );
  if (r.displayApplication) {
    field(info, 'Display application', r.displayApplication.executable);
    field(
      info,
      'Observation only',
      'Common application of shared holders. Not a firewall permission target.',
    );
  }
  if (r.process) {
    field(info, 'Executable', r.process.executable);
    field(
      info,
      'Identity',
      `${r.process.application.key}\nRevision: ${r.process.application.revision}`,
    );
    if (r.kind === 'process')
      field(
        info,
        'Process',
        `${r.process.thread_group_pid ? `Worker TID ${r.process.pid} · thread-group PID ${r.process.thread_group_pid}` : r.process.pid} · start ${r.process.start_ticks} · UID ${r.process.uid}`,
      );
  }
  if (r.socket) {
    const s = r.socket;
    for (const [label, value] of [
      ['Protocol', s.socket.protocol],
      ['Local endpoint', s.socket.local],
      ['Remote endpoint', s.socket.remote],
      ['State', s.state],
      ['Initiation', s.direction || 'Unknown'],
      ['Ownership', s.ownership],
      ['Ownership evidence category', ownershipExplanation(s.ownership_category)],
      ['Socket creation UID', String(s.socket.uid)],
      ...(s.display_application
        ? [
            [
              'Display association',
              `${s.display_application.name || s.display_application.executable} · observation only, not a permission target`,
            ],
          ]
        : []),
      ['Evidence', s.evidence],
      ['Measurement', trafficDetails(s.traffic)],
      ['Socket identity', `${s.socket.netns} · ${s.socket.cookie}`],
    ])
      field(info, label, value);
    for (const id of s.owners) {
      const p = state.observation.activity?.processes[id];
      field(
        info,
        'Visible holder',
        p
          ? `${p.thread_group_pid ? `Worker TID ${p.pid} · thread-group PID ${p.thread_group_pid}` : p.pid} · ${p.executable}`
          : id,
      );
    }
  } else {
    field(info, 'Visible sockets', String(r.rows.length));
    field(
      info,
      'Totals',
      'Currently visible socket intervals, not historical bytes exclusively transferred by this owner.',
    );
    const s = sum(r.rows, 'uploaded');
    field(
      info,
      'Coverage',
      `${s.known}/${s.count} supported sockets${s.mixed ? ' · mixed sources are not summed' : ''}`,
    );
    if (r.kind === 'unidentified')
      field(
        info,
        'Ownership',
        'Unresolved and mixed-application shared sockets, counted once. This group is not an application or permission target.',
      );
  }
  commit();
}
function eventName(e: ViewEvent) {
  return (
    e.attribution.application?.name ||
    e.attribution.application?.executable ||
    'Unidentified application'
  );
}
function currentEvent() {
  if (promptID && promptGeneration !== state?.control.generation) return undefined;
  return state?.control.events.find((e) => e.id === selectedRequest);
}
function actionable(e: ViewEvent | undefined) {
  return (
    !!e &&
    state.control.connected &&
    !state.control.readOnly &&
    e.state === 'awaiting-decision' &&
    e.remainingMs > 0 &&
    !e.attempt &&
    !localSubmitted.has(state.control.generation + ':' + e.id) &&
    !!e.scope_previews[chosenScope]
  );
}
function renderRequests() {
  const events = state.control.events;
  const signature = JSON.stringify([
    selectedRequest,
    state.control.generation,
    state.control.connected,
    state.control.readOnly,
    events.map((e) => [e.id, e.state, e.attempt]),
  ]);
  if (!promptID && signature !== eventSignature) {
    eventSignature = signature;
    const body = $('requestRows');
    body.replaceChildren();
    for (const e of events) {
      const tr = element('tr');
      tr.dataset.id = e.id;
      tr.tabIndex = 0;
      tr.setAttribute('aria-selected', String(selectedRequest === e.id));
      for (const v of [eventName(e), e.flow.direction, e.flow.protocol, e.flow.remote, e.state])
        tr.append(element('td', v));
      const select = () => {
        selectedRequest = e.id;
        chosenScope = 'once';
        detailSignature = '';
        renderRequests();
      };
      tr.onclick = select;
      tr.onkeydown = (k) => {
        if (k.key === 'Enter' || k.key === ' ') {
          k.preventDefault();
          select();
        }
      };
      body.append(tr);
    }
    if (!selectedRequest && events.length)
      selectedRequest = events.find((e) => e.state === 'awaiting-decision')?.id ?? events[0].id;
  }
  const e = currentEvent();
  const sig = JSON.stringify([
    selectedRequest,
    state.control.generation,
    e ? { ...e, remainingMs: 0 } : null,
  ]);
  if (sig !== detailSignature) {
    detailSignature = sig;
    const container = $('requestDetails');
    container.replaceChildren();
    if (!e) {
      container.append(
        element(
          'p',
          selectedRequest
            ? 'Request no longer present. It may have expired or been resolved by another client.'
            : 'No pending connection selected.',
          'hint',
        ),
      );
      return;
    }
    container.append(
      element(
        'h3',
        `${e.flow.direction} connection · ${e.flow.protocol.toUpperCase()}`,
        'connection-banner',
      ),
    );
    const route = element('dl', '', 'identity-route');
    const incoming = e.flow.direction === 'incoming';
    field(route, 'From', incoming ? e.flow.remote : eventName(e));
    field(route, 'To', incoming ? eventName(e) : e.flow.remote);
    const applicationRoute = route.querySelectorAll('dd')[incoming ? 1 : 0];
    applicationRoute.classList.add('route-application');
    applicationRoute.prepend(installedIcon(e.attribution.application, 'application'));
    container.append(route);
    const fields = element('dl', '', 'connection-fields');
    field(
      fields,
      'Application',
      e.attribution.application?.executable.split('/').pop() || 'Unavailable',
    );
    field(
      fields,
      'Process ID',
      e.attribution.owners.map((p) => String(p.pid)).join(', ') || 'Unavailable',
    );
    field(fields, 'Local endpoint', e.flow.local);
    field(fields, 'Remote endpoint', e.flow.remote);
    field(fields, 'Deadline', e.deadline.replace(/\.\d+/, ''));
    container.append(fields);
    const technical = element('details', '', 'identity-details');
    technical.append(element('summary', 'Application identity and attribution details'));
    const identity = element('dl', '', 'connection-fields');
    field(identity, 'Exact backend deadline', e.deadline);
    field(identity, 'Executable', e.attribution.application?.executable || 'Unavailable');
    field(
      identity,
      'Process identity',
      e.attribution.owners
        .map((p) => `${p.pid} · start ${p.start_ticks} · UID ${p.uid}`)
        .join('\n') || 'Unavailable',
    );
    field(identity, 'Attribution', `${e.attribution.status}\n${e.attribution.reason}`);
    field(
      identity,
      'Coverage',
      e.attribution.visibility_complete
        ? 'Backend reports complete visibility'
        : 'Limited observation; hidden owners or races may remain',
    );
    technical.append(identity);
    container.append(technical);
    if (!e.attribution.visibility_complete || e.attribution.status !== 'directly-associated')
      container.append(
        element(
          'p',
          `Attribution: ${e.attribution.status}. ${e.attribution.reason}`,
          'attribution-warning',
        ),
      );
    container.append(element('p', '', 'expiry'));
    const preview = element('p', '', 'scope-preview');
    preview.id = 'scopePreview';
    container.append(preview);
    const controls = element('div', '', 'decision-controls');
    for (const [action, label] of [
      ['allow', 'Allow'],
      ['block', 'Block'],
    ] as const) {
      const button = element('button', label, action);
      button.id = action;
      button.onclick = async () => {
        localSubmitted.add(state.control.generation + ':' + e.id);
        updateDecisions();
        message('Submitting decision…');
        try {
          const result = await window.flowgate.decide({
            generation: state.control.generation,
            id: e.id,
            action,
            scope: chosenScope,
          });
          message(result.message);
        } catch (error) {
          message(String(error));
        }
        updateDecisions();
      };
      controls.append(button);
    }
    const scopes = element('select');
    scopes.id = 'scope';
    scopes.setAttribute('aria-label', 'Permission scope');
    const offered = Object.keys(e.scope_previews) as Scope[];
    if (!offered.includes(chosenScope)) chosenScope = offered[0] ?? 'once';
    for (const key of offered) {
      const option = element('option', scopeLabels[key]);
      option.value = key;
      scopes.append(option);
    }
    scopes.value = chosenScope;
    scopes.onchange = () => {
      chosenScope = scopes.value as Scope;
      updateDecisions();
    };
    controls.append(scopes);
    container.insertBefore(controls, preview);
    if (!promptID) {
      const open = element('button', 'Open permission window', 'open-prompt');
      open.onclick = () => void window.flowgate.openPrompt(e.id);
      container.append(open);
    }
    const result = element('p', e.attempt?.message || e.reason, 'request-result');
    result.id = 'requestResult';
    container.append(result);
  }
  updateDecisions();
}
function updateDecisions() {
  const e = currentEvent();
  for (const id of ['allow', 'block']) {
    const b = $<HTMLButtonElement>(id);
    if (b) b.disabled = !actionable(e);
  }
  const scope = $<HTMLSelectElement>('scope');
  if (scope)
    scope.disabled =
      !e ||
      !!e.attempt ||
      localSubmitted.has(state.control.generation + ':' + e.id) ||
      !state.control.connected ||
      state.control.readOnly ||
      e.state !== 'awaiting-decision' ||
      e.remainingMs <= 0;
  if ($('scopePreview'))
    $('scopePreview').textContent =
      e?.scope_previews[chosenScope] || 'Authoritative scope unavailable; decisions disabled.';
  const expiry = document.querySelector('.expiry');
  if (expiry)
    expiry.textContent = e
      ? e.remainingMs > 0 && e.state === 'awaiting-decision'
        ? `${Math.ceil(e.remainingMs / 1000)} seconds remaining`
        : `Request ${e.state === 'awaiting-decision' ? 'expired' : e.state}`
      : '';
}
function consume(next: ClientState) {
  state = next;
  const present = new Set(state.control.events.map((e) => state.control.generation + ':' + e.id));
  for (const key of localSubmitted) if (!present.has(key)) localSubmitted.delete(key);
  $('controlStatus').textContent =
    state.control.message +
    (state.control.connected && state.control.readOnly ? ' · read-only' : '');
  $('controlStatus').title = $('controlStatus').textContent || '';
  if (!promptID) {
    $('observerStatus').textContent = state.observation.message;
    $('observerStatus').title = state.observation.message;
    $('pendingCount').textContent = String(
      state.control.events.filter((e) => e.state === 'awaiting-decision' && e.remainingMs > 0)
        .length,
    );
    const stamp =
      state.observation.generation + ':' + (state.observation.activity?.sequence ?? 'offline');
    if (stamp !== sequence) {
      sequence = stamp;
      buildTree();
    }
    if (lastGeneration && lastGeneration !== state.control.generation) {
      selectedRequest = '';
      chosenScope = 'once';
    }
    lastGeneration = state.control.generation;
    const rulesStamp = JSON.stringify([
      state.control.connected,
      state.control.generation,
      state.control.rules,
      (state.control.rules || []).map((r) => ruleState(r, state.control.serverNow ?? NaN)),
    ]);
    if (ruleSignature !== rulesStamp) {
      ruleSignature = rulesStamp;
      renderTree();
      renderInfo();
    }
  }
  renderRequests();
  if (!promptID) {
    const details = $('requestDetails');
    details.dataset.eventId = currentEvent()?.id || '';
    updateWorkflows(state);
  }
}
window.flowgate.subscribe(consume);
void window.flowgate
  .snapshot()
  .then(consume)
  .catch((e) => {
    root.textContent = 'FlowGate could not initialize: ' + String(e);
  });

document.addEventListener('visibilitychange', () => {
  if (!document.hidden) {
    void window.flowgate.snapshot().then(consume);
    void graph?.update(selected, sequence + ':resume:' + performance.now());
  }
});

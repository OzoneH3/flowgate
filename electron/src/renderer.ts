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
  type Row,
  type Metric,
} from './model';
const root = document.querySelector<HTMLDivElement>('#app')!;
const promptID = new URL(location.href).searchParams.get('request');
let state: ClientState;
let selected = '';
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
let lastGeneration = '';
const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;
function element<K extends keyof HTMLElementTagNameMap>(tag: K, text = '', className = '') {
  const e = document.createElement(tag);
  e.textContent = text;
  e.className = className;
  return e;
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
  root.innerHTML = `<section class="prompt-shell"><header class="prompt-heading"><strong>FlowGate Blocker</strong><span>Connection permission</span></header><div id="promptBody"><div id="requestDetails"></div></div><footer><span id="controlStatus"></span><button id="dismiss">Decide later</button></footer><div id="feedback" role="status" aria-live="polite"></div></section>`;
  $('dismiss').onclick = () => void window.flowgate.dismissPrompt();
} else {
  root.innerHTML = `<header class="toolbar"><strong class="brand">▣ FlowGate</strong><span id="observerStatus"></span><span class="separator"></span><span id="controlStatus"></span></header><nav class="tabs" aria-label="Views"><button id="activityTab" aria-selected="true">Activity</button><button id="requestsTab" aria-selected="false">Pending requests <span id="pendingCount">0</span></button></nav><main id="activityView"><section class="activity-main"><div class="filterbar"><input id="search" type="search" aria-label="Search Activity" placeholder="Search application, path, PID or endpoint"><select id="filter" aria-label="Socket filter"><option value="all">All sockets</option><option value="active">Active TCP / connected UDP</option><option value="listening">Listening TCP / bound UDP</option></select><button id="expand">Expand all</button><button id="collapse">Collapse all</button></div><div class="table-scroll"><table id="tree" role="treegrid" tabindex="0" aria-label="Application process socket activity"><thead><tr id="headers"></tr></thead><tbody id="rows"></tbody></table></div><div id="activitySummary" class="summary"></div></section><aside><h2>Info View</h2><h3 id="selectedName">FlowGate Activity</h3><dl id="info"></dl><section class="measurement-note"><h2>Measurements</h2><p>Observed bytes from currently visible sockets. TCP transport payload and optional UDP API bytes are separate sources.</p><p>— Unavailable &nbsp; * Partial coverage</p><p>Traffic charts are not available in this frontend.</p></section></aside></main><main id="requestsView" hidden><section class="request-list"><h2>Pending &amp; recent requests</h2><p class="hint">Select a request to decide. Dismissal grants nothing. Closing FlowGate leaves an independent controller running.</p><div class="table-scroll"><table id="requests"><thead><tr><th>Application</th><th>Direction</th><th>Protocol</th><th>Remote endpoint</th><th>State</th></tr></thead><tbody id="requestRows"></tbody></table></div></section><aside class="request-sidebar"><h2>Connection permission</h2><div id="requestDetails"></div></aside></main><footer><span>Activity and firewall control are independent.</span><span id="feedback" role="status" aria-live="polite"></span></footer>`;
  const columns = [
    ['name', 'Application / process / connection'],
    ['download_bps', 'DL rate'],
    ['upload_bps', 'UL rate'],
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
    b.onclick = () => {
      descending = sort === key ? !descending : false;
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
    $('activityTab').setAttribute('aria-selected', String(next === 'activity'));
    $('requestsTab').setAttribute('aria-selected', String(next === 'requests'));
  };
  setupWorkflows(chooseTab);
  document.addEventListener('keydown',e=>{
    if(e.ctrlKey && ['1','2','3'].includes(e.key)){e.preventDefault();chooseTab({'1':'activity','2':'requests','3':'rules'}[e.key]!);}
    if(e.ctrlKey&&e.key.toLowerCase()==='p'){e.preventDefault();const event=currentEvent();if(event)void window.flowgate.openPrompt(event.id);}
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
      element(
        'span',
        r.kind === 'socket'
          ? '◇'
          : r.kind === 'unidentified'
            ? '?'
            : r.kind === 'application'
              ? '▣'
              : '▪',
        'row-icon',
      ),
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
  const live = $('info');
  const info = element('dl');
  const commit = () => {
    // Preserve text selection and scroll while an unchanged observation refreshes.
    if (live.textContent !== info.textContent) live.replaceChildren(...Array.from(info.childNodes));
  };
  const r = allRows(roots).find((r) => r.id === selected);
  $('selectedName').textContent = r?.label ?? 'FlowGate Activity';
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
        `${r.process.pid} · start ${r.process.start_ticks} · UID ${r.process.uid}`,
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
      ['Evidence', s.evidence],
      ['Measurement', trafficDetails(s.traffic)],
      ['Socket identity', `${s.socket.netns} · ${s.socket.cookie}`],
    ])
      field(info, label, value);
    for (const id of s.owners) {
      const p = state.observation.activity?.processes[id];
      field(info, 'Visible holder', p ? `${p.pid} · ${p.executable}` : id);
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
        'Unknown and shared sockets, counted once. This group is not an application or permission target.',
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
      element('h3', eventName(e), 'application-name'),
    );
    const fields = element('dl', '', 'connection-fields');
    const [local, localPort] = endpoint(e.flow.local),
      [remote, remotePort] = endpoint(e.flow.remote);
    field(fields, 'Application', e.attribution.application?.executable ?? 'Unavailable');
    field(
      fields,
      'Process',
      e.attribution.owners
        .map((p) => `${p.pid} · start ${p.start_ticks} · UID ${p.uid}`)
        .join('\n') || 'Unavailable',
    );
    field(fields, 'Local address', local);
    field(fields, 'Local port', localPort);
    field(fields, 'Remote address', remote);
    field(fields, 'Remote port', remotePort);
    field(fields, 'Attribution', `${e.attribution.status}\n${e.attribution.reason}`);
    field(
      fields,
      'Coverage',
      e.attribution.visibility_complete
        ? 'Backend reports complete visibility'
        : 'Limited observation; hidden owners or races may remain',
    );
    field(fields, 'Deadline', e.deadline);
    container.append(fields, element('p', '', 'expiry'));
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
    container.append(controls);
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
  if (!promptID) {
    $('observerStatus').textContent = state.observation.message;
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

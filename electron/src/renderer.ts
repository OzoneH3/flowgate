import {
  POLICY_CAPABILITY,
  authoritativePolicy,
  policyLabel,
  policyRuleDescription,
} from './policy';
import { ruleStatus, ruleState, ruleDescription, configuredPolicy } from './rule-status';
import { canDecide, canManageRules } from './protocol';
import type { Application } from './protocol';
import { TrafficGraph } from './graph';
import { setupWorkflows, updateWorkflows, openRule, confirmRuleDelete } from './workflows';
import { setupDecisionLog, showDecisionLog, updateDecisionLog } from './decision-log-view';
import type { ClientState, ViewEvent, Scope } from './protocol';
import {
  hierarchy,
  overview,
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
let selected = 'overview';
let measurementSource: 'tcp' | 'udp' = 'tcp';
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
const expanded = new Set<string>(['overview']);
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
    kind === 'application' || kind === 'overview'
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
  if (r.displayApplication || (r.socket && r.socket.owners.length > 1)) return undefined;
  return (
    r.process?.application ||
    r.displayApplication ||
    (r.socket?.owners.length === 1
      ? state.observation.activity?.processes[r.socket.owners[0]]?.application
      : r.socket?.display_application)
  );
}
type PolicyDirection = 'incoming' | 'outgoing';
let policySelection: { id: string; direction: PolicyDirection } | undefined;
let policySignature = '';
function policyCell(r: Row, direction: PolicyDirection) {
  const status = ruleStatus(r, state),
    cell = element('td', '', 'rule-status');
  const rules = status[direction];
  const authoritative = state.control.capabilities?.includes(POLICY_CAPABILITY);
  const result = authoritative ? authoritativePolicy(r, state) : undefined;
  const summary = result?.application?.[direction];
  const label = authoritative
    ? summary
      ? policyLabel(summary)
      : 'Unavailable'
    : status.available
      ? configuredPolicy(rules, status.now)
      : 'Unavailable';
  const button = element(
    'button',
    r.kind === 'overview' ? '—' : label === 'No explicit rule' ? 'Not set' : label,
    'policy-cell',
  );
  button.disabled = r.kind === 'overview';
  button.dataset.direction = direction;
  button.title =
    `${direction}: configured policy. ${status.reason}\n${state.control.enforcement?.state === 'stopped' ? 'Stored only; enforcement stopped.\n' : ''}` +
    rules.map((rule) => ruleDescription(rule, status.now)).join('\n');
  if (authoritative)
    button.title = summary
      ? `Backend summary · ${summary.reason}\nEnforcement: ${summary.enforcement.state} · ${summary.enforcement.reason}\nCurrent policy, not a historical verdict.`
      : result!.reason;
  else
    button.title =
      'Compatibility inventory (locally grouped listed rules; not a backend summary).\n' +
      button.title;
  button.setAttribute('aria-label', `${r.label} · ${direction} · ${label} · configured policy`);
  if (authoritative ? !summary : !status.available) button.classList.add('rule-unavailable');
  else if (authoritative && summary?.configured === 'uniform')
    button.classList.add('policy-' + summary.action);
  else if (authoritative && summary?.rules.length === 1) {
    const ref = summary.rules[0];
    button.classList.add(
      'policy-' +
        (ref.expired ? 'expired' : ref.disabled ? 'disabled' : ref.active ? ref.action : 'unknown'),
    );
  } else if (!authoritative && rules.length === 1)
    button.classList.add('policy-' + ruleState(rules[0], status.now));
  button.onclick = (event) => {
    event.stopPropagation();
    selected = r.id;
    policySelection = { id: r.id, direction };
    policySignature = '';
    renderTree();
    renderInfo();
    renderPolicyList();
    $('closePolicy').focus();
  };
  cell.append(button);
  return cell;
}
function closePolicyList() {
  const selection = policySelection;
  policySelection = undefined;
  $('policyList')?.remove();
  for (const row of document.querySelectorAll<HTMLElement>('#rows tr'))
    if (selection && row.dataset.id === selection.id)
      row
        .querySelector<HTMLButtonElement>(`.policy-cell[data-direction="${selection.direction}"]`)
        ?.focus({ preventScroll: true });
}
function renderPolicyList() {
  if (!policySelection || promptID) return;
  const row = allRows(roots).find((r) => r.id === policySelection!.id);
  const inventory = row ? ruleStatus(row, state) : undefined;
  const rules = inventory?.[policySelection.direction] || [];
  const authoritative = !!state.control.capabilities?.includes(POLICY_CAPABILITY);
  const result = row && authoritative ? authoritativePolicy(row, state) : undefined;
  const summary = result?.application?.[policySelection.direction];
  const signature = JSON.stringify([
    policySelection,
    authoritative,
    summary,
    result?.reason,
    state.control.generation,
    inventory?.available,
    inventory?.reason,
    row?.label,
    rules,
    rules.map((r) => ruleState(r, inventory!.now)),
    canManageRules(state.control),
    state.control.enforcement?.state,
  ]);
  if (signature === policySignature) return;
  policySignature = signature;
  let panel = $('policyList');
  if (!panel) {
    panel = element('section', '', 'policy-list');
    panel.id = 'policyList';
    panel.setAttribute('role', 'dialog');
    panel.setAttribute('aria-label', 'Configured policy');
    root.append(panel);
    panel.onkeydown = (e) => {
      if (e.key === 'Escape') {
        e.stopPropagation();
        closePolicyList();
      }
    };
  }
  const heading = element('header'),
    title = element(
      'strong',
      `${policySelection.direction === 'incoming' ? 'Incoming' : 'Outgoing'} configured policy`,
    ),
    close = element('button', 'Close');
  close.id = 'closePolicy';
  close.onclick = closePolicyList;
  heading.append(title, close);
  const content = element('div', '', 'policy-list-content');
  content.append(element('p', row?.label || 'Selection no longer visible', 'policy-identity'));
  content.append(
    element(
      'p',
      state.control.enforcement?.state === 'stopped'
        ? 'Stored policy only · enforcement stopped.'
        : 'Configured inventory, not an effective connection verdict.',
      'hint',
    ),
  );
  if (state.control.permissions)
    content.append(
      element(
        'p',
        `${state.control.permissions.role} · ${state.control.permissions.policy_scope} policy · ${canManageRules(state.control) ? 'editing permitted' : 'read-only'}`,
        'hint',
      ),
    );
  if (authoritative) {
    content.append(
      element(
        'p',
        'Backend-authoritative configured policy · current explanation, not a historical verdict.',
        'hint',
      ),
    );
    if (state.control.policy && !state.control.policy.complete)
      content.append(
        element(
          'p',
          'Partial policy batch · ' +
            (state.control.policy.reason || 'Activity visibility is partial.'),
          'hint',
        ),
      );
    if (summary) {
      content.append(element('p', policyLabel(summary) + ' · ' + summary.reason));
      content.append(
        element(
          'p',
          `Enforcement: ${summary.enforcement.state} · ${summary.enforcement.covered ? 'direction covered' : 'direction not confirmed covered'} · ${summary.enforcement.reason}`,
        ),
      );
      for (const [label, d] of [
        ['Configured default', summary.configured_default],
        ['Runtime default', summary.runtime_default],
      ] as const)
        content.append(
          element('p', `${label}: ${d.known ? d.action : 'unknown'} · ${d.reason}`, 'hint'),
        );
      if (summary.potential_overlapping_actions)
        content.append(
          element(
            'p',
            'Potentially overlapping actions; Go resolves precedence for a concrete context.',
          ),
        );
      for (const ref of summary.rules) {
        const item = element('section', '', 'policy-rule');
        item.append(element('p', policyRuleDescription(ref)));
        const rule = state.control.rules?.find(
          (r) => r.id === ref.id && String(r.version) === ref.version,
        );
        if (canManageRules(state.control) && rule) appendPolicyActions(item, rule);
        else if (canManageRules(state.control))
          item.append(
            element(
              'p',
              'Refresh required before editing: listed version differs or is not losslessly representable.',
              'hint',
            ),
          );
        content.append(item);
      }
    } else content.append(element('p', result?.reason || 'No supported observation identity.'));
  } else
    content.append(
      element(
        'p',
        'Compatibility inventory · locally grouped listed rules, not a backend-authoritative summary. Enforcement coverage and defaults are not inferred.',
        'hint',
      ),
    );
  if (!authoritative && !inventory?.available)
    content.append(element('p', inventory?.reason || 'No current observation identity.'));
  else if (!authoritative && !rules.length)
    content.append(element('p', 'No explicit rule listed. No default action is inferred.'));
  else if (!authoritative) {
    content.append(
      element(
        'p',
        rules.length > 1
          ? 'Multiple scopes; precedence remains in Go.'
          : 'Scope and expiry below are the stored backend values.',
        'hint',
      ),
    );
    for (const rule of rules) {
      const item = element('section', '', 'policy-rule');
      item.append(element('p', ruleDescription(rule, inventory!.now)));
      if (canManageRules(state.control)) appendPolicyActions(item, rule);
      content.append(item);
    }
  }
  const create = element('button', `New ${policySelection.direction} rule…`);
  create.id = 'newActivityRule';
  const application = row ? authoritativePolicy(row, state).application : undefined;
  const candidate = row?.rows.find(
    (socket) =>
      socket.owners.length === 1 &&
      socket.ownership_category === 'visible-holder' &&
      application?.process_ids.includes(socket.owners[0]) &&
      (!row.process || row.kind === 'application' || row.process.id === socket.owners[0]),
  );
  const source = candidate
    ? {
        generation: state.control.generation,
        row_id: candidate.id,
        process_id: candidate.owners[0],
        direction: policySelection.direction,
      }
    : undefined;
  const creationReason = !canManageRules(state.control)
    ? 'Rule management is read-only or unavailable.'
    : !state.control.capabilities?.includes('observed-rule-create-v1')
      ? 'Backend update required for creation from Activity (observed-rule-create-v1). Pending-request creation remains available.'
      : !source
        ? result?.reason ||
          'A live supported single-holder native process is required; shared or unresolved observations cannot create rules.'
        : 'Preview will verify this live process. Direction is connection initiation, not upload/download.';
  create.disabled =
    !source ||
    !canManageRules(state.control) ||
    !state.control.capabilities?.includes('observed-rule-create-v1');
  create.title = creationReason;
  create.onclick = () => {
    if (source) {
      closePolicyList();
      void openRule({ observed: source });
    }
  };
  const creation = element('div', '', 'policy-create');
  creation.append(create);
  if (create.disabled) creation.append(element('p', creationReason, 'hint'));
  content.insertBefore(creation, content.children[1] || null);
  content.append(
    element(
      'p',
      'Incoming/outgoing refers to connection initiation, not download/upload. Rule changes may not disconnect existing approved TCP sessions.',
      'hint',
    ),
  );
  if (!canManageRules(state.control))
    content.append(element('p', 'Rule management is unavailable or read-only.', 'hint'));
  const technical = element('details', '', 'policy-technical');
  technical.append(element('summary', 'Defaults and policy details'));
  for (const hint of Array.from(content.querySelectorAll(':scope > p.hint')))
    technical.append(hint);
  if (technical.childElementCount > 1) content.append(technical);
  panel.replaceChildren(heading, content);
}

function appendPolicyActions(item: HTMLElement, rule: import('./protocol').Rule) {
  const edit = element('button', 'Edit rule');
  edit.dataset.ruleId = rule.id;
  edit.onclick = () => {
    closePolicyList();
    void openRule({ id: rule.id });
  };
  const remove = element('button', 'Delete…');
  remove.disabled = !state.control.capabilities?.includes('conditional-rule-delete-v1');
  remove.title = remove.disabled
    ? 'Safe conditional deletion unsupported by this daemon.'
    : 'Review frozen version before deleting';
  const generation = state.control.generation;
  remove.onclick = () => confirmRuleDelete(rule, generation);
  item.append(edit, remove);
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
  root.innerHTML = `<header class="toolbar"><strong class="brand">▣ FlowGate</strong><input id="search" type="search" aria-label="Search Activity" placeholder="Search"><span id="observerStatus"></span><span class="separator"></span><span id="controlStatus"></span></header><nav class="tabs" aria-label="Views"><button id="activityTab" aria-selected="true">Activity</button><button id="requestsTab" aria-selected="false">Pending requests <span id="pendingCount">0</span></button></nav><main id="activityView"><section class="activity-main"><div class="filterbar"><select id="activitySource" aria-label="Activity measurement source"><option value="tcp">TCP rates</option><option value="udp">UDP rates</option></select><select id="filter" aria-label="Socket filter"><option value="all">All sockets</option><option value="active">Active TCP / connected UDP</option><option value="listening">Listening TCP / bound UDP</option></select><button id="expand">Expand all</button><button id="collapse">Collapse all</button></div><div class="table-scroll"><table id="tree" role="treegrid" tabindex="0" aria-label="Application process socket activity"><thead><tr id="headers"></tr></thead><tbody id="rows"></tbody></table></div><div id="activitySummary" class="summary"></div></section><aside><h2>Info View</h2><h3 id="selectedName">FlowGate Activity</h3><div id="selectedExecutable"></div><div class="info-scroll"><h3 id="infoProperties" class="info-section-title">Overview</h3><dl id="info"></dl><section id="infoRules"></section><section class="info-tools"><h3 class="info-section-title">Tools</h3><button id="infoOpenRules">Rule list</button><button id="infoOpenLog">Decision log</button><button id="infoOpenPending">Pending requests</button></section></div><section id="trafficGraph"></section></aside></main><main id="requestsView" hidden><section class="request-list"><h2>Pending &amp; recent requests</h2><p class="hint">Select a request to decide. Dismissal grants nothing. Closing FlowGate leaves an independent controller running.</p><div class="table-scroll"><table id="requests"><thead><tr><th>Application</th><th>Direction</th><th>Protocol</th><th>Remote endpoint</th><th>State</th></tr></thead><tbody id="requestRows"></tbody></table></div></section><aside class="request-sidebar"><h2>Connection permission</h2><div id="requestDetails"></div></aside></main><footer><span>Activity and firewall control are independent.</span><span id="feedback" role="status" aria-live="polite"></span></footer>`;
  const columns = [
    ['name', 'Name'],
    ['download_bps', 'DL rate'],
    ['upload_bps', 'UL rate'],
    ['incoming_policy', 'In Blocker'],
    ['outgoing_policy', 'Out Blocker'],
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
    if (key.endsWith('_policy')) b.append(element('small', 'Configured policy'));
    b.disabled = key.endsWith('_policy');
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
    if ($('decisionLogView')) {
      $('decisionLogView').hidden = next !== 'log';
      $('decisionLogTab').setAttribute('aria-selected', String(next === 'log'));
      void showDecisionLog(next === 'log');
    }
    $('activityView').hidden = next !== 'activity';
    $('requestsView').hidden = next !== 'requests';
    if (next === 'activity') void graph?.update(selected, sequence + ':shown');
    $('activityTab').setAttribute('aria-selected', String(next === 'activity'));
    $('requestsTab').setAttribute('aria-selected', String(next === 'requests'));
  };
  setupWorkflows(chooseTab);
  $('infoOpenRules').onclick = () => chooseTab('rules');
  $('infoOpenLog').onclick = () => chooseTab('log');
  $('infoOpenPending').onclick = () => chooseTab('requests');
  setupDecisionLog(
    chooseTab,
    (app) => installedIcon(app, 'application'),
    (id) => {
      chooseTab('rules');
      void openRule({ id });
    },
  );
  graph = new TrafficGraph($('trafficGraph'));
  window.flowgate.onNavigate((v) => {
    chooseTab('requests');
    message(v.message);
  });
  document.addEventListener('keydown', (e) => {
    if (e.ctrlKey && ['1', '2', '3', '4'].includes(e.key)) {
      e.preventDefault();
      chooseTab({ '1': 'activity', '2': 'requests', '3': 'rules', '4': 'log' }[e.key]!);
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
  $('activitySource').onchange = () => {
    measurementSource = ($('activitySource') as HTMLSelectElement).value as 'tcp' | 'udp';
    graph?.setSource(measurementSource);
    renderTree();
    renderInfo();
  };
  $('filter').onchange = () => buildTree();
  $('expand').onclick = () => {
    for (const r of allRows(roots)) if (r.children.length) expanded.add(r.id);
    renderTree();
  };
  $('collapse').onclick = () => {
    expanded.clear();
    selected = 'overview';
    expanded.add('overview');
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
  if (a) {
    const children = roots;
    for (const child of children) child.parent = 'overview';
    roots = [overview(a, children)];
  }
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
    ? `${roots[0]?.children.reduce((n, r) => n + r.rows.length, 0) || 0} / ${a.rows.length} sockets · ${a.complete ? 'Complete census' : 'Partial visibility'}`
    : state.observation.message;
  $('activitySummary').title = [a?.collected, ...(a?.issues || [])].filter(Boolean).join(' · ');
}
function renderTree() {
  const focused = document.activeElement as HTMLElement;
  const focusedPolicy = focused?.classList.contains('policy-cell')
    ? { id: focused.closest('tr')?.dataset.id, direction: focused.dataset.direction }
    : undefined;
  visible = flatten(roots, expanded, sort, descending, measurementSource);
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
      const s = sum(r.rows, key, measurementSource);
      const td = element(
        'td',
        metricLabel(s, true),
        'numeric ' + (s.value && s.value > 0 ? (key === 'download_bps' ? 'down' : 'up') : ''),
      );
      const rateText = td.textContent || '';
      td.replaceChildren(element('span', rateText, 'rate-value'));
      td.title = `${measurementSource.toUpperCase()} · ${s.known}/${s.count} measured sockets${s.mixed ? ' · incompatible measurement sources' : ''}`;
      tr.append(td);
    }
    tr.append(policyCell(r, 'incoming'), policyCell(r, 'outgoing'));
    tr.append(
      element('td', String(r.rows.length), 'numeric'),
      element('td', r.pid === undefined ? '' : String(r.pid), 'numeric'),
    );
    for (const key of ['downloaded', 'uploaded'] as Metric[])
      tr.append(element('td', metricLabel(sum(r.rows, key, measurementSource)), 'numeric'));
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
  if (focusedPolicy)
    for (const row of body.querySelectorAll<HTMLElement>('tr'))
      if (row.dataset.id === focusedPolicy.id)
        row
          .querySelector<HTMLButtonElement>(
            `.policy-cell[data-direction="${focusedPolicy.direction}"]`,
          )
          ?.focus({ preventScroll: true });
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
    const rulesHost = $('infoRules');
    const matrix = element('table', '', 'info-rule-matrix');
    const cols = element('colgroup');
    for (const width of ['65px', '95px', 'auto']) {
      const col = element('col');
      col.style.width = width;
      cols.append(col);
    }
    matrix.append(cols);
    const heading = element('tr');
    for (const text of ['Type', 'In', 'Out']) heading.append(element('th', text));
    matrix.append(heading);
    const cells = element('tr');
    cells.append(element('td', 'Blocker'));
    for (const label of ['Rules · In', 'Rules · Out']) {
      const dt = [...info.querySelectorAll('dt')].find((n) => n.textContent === label);
      const dd = dt?.nextElementSibling;
      const cell = element('td');
      if (dd) {
        cell.append(...dd.childNodes);
        dd.remove();
      }
      dt?.remove();
      cells.append(cell);
    }
    matrix.append(cells);
    const sectionTitle = element('h3', 'Rules', 'info-section-title');
    if (
      rulesHost.dataset.selection !== selected ||
      rulesHost.textContent !== sectionTitle.textContent + matrix.textContent
    )
      rulesHost.replaceChildren(sectionTitle, matrix);
    rulesHost.dataset.selection = selected;
    rulesHost.hidden = !info.dataset.policy;
    // Preserve text selection and expanded details during unchanged polling.
    if (live.textContent !== info.textContent) live.replaceChildren(...Array.from(info.childNodes));
  };
  const r = allRows(roots).find((r) => r.id === selected);
  $('infoProperties').textContent =
    r?.kind === 'socket'
      ? 'Connection properties'
      : r?.kind === 'process'
        ? 'Process properties'
        : r?.kind === 'application'
          ? 'Application properties'
          : 'Overview';
  const pathText = r?.process?.executable || r?.displayApplication?.executable || '';
  if ($('selectedExecutable').textContent !== pathText)
    $('selectedExecutable').textContent = pathText;
  $('selectedExecutable').title = pathText;
  $('selectedExecutable').hidden = !pathText;
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
  if (r.kind === 'overview') {
    field(
      info,
      'Scope',
      state.control.permissions?.observation_scope === 'machine'
        ? 'Machine · current network namespace'
        : 'Visible sockets · current network namespace',
    );
    field(info, 'Applications', String(r.children.filter((c) => c.kind === 'application').length));
    field(info, 'Sockets', String(r.rows.length));
    field(
      info,
      'Measurement',
      'TCP transport payload and UDP API-reported payload are shown separately. Socket sums include local perspectives; they are not deduplicated internet usage.',
    );
    field(
      info,
      'Coverage',
      state.observation.activity?.complete ? 'Complete visible census' : 'Partial visibility',
    );
    commit();
    return;
  }
  info.dataset.policy = 'true';
  const inventory = ruleStatus(r, state);
  field(
    info,
    'Rule inventory',
    state.control.capabilities?.includes(POLICY_CAPABILITY)
      ? authoritativePolicy(r, state).reason
      : 'Compatibility inventory · ' + inventory.reason,
  );
  for (const direction of ['incoming', 'outgoing'] as const) {
    const rules = inventory[direction];
    const authoritative = state.control.capabilities?.includes(POLICY_CAPABILITY);
    const summary = authoritative
      ? authoritativePolicy(r, state).application?.[direction]
      : undefined;
    field(
      info,
      direction === 'incoming' ? 'Rules · In' : 'Rules · Out',
      authoritative
        ? summary
          ? policyLabel(summary)
          : 'Unavailable'
        : !inventory.available
          ? 'Unavailable'
          : ['allow', 'block', 'disabled', 'expired']
              .map(
                (type) =>
                  `${rules.filter((rule) => ruleState(rule, inventory.now) === type).length} ${type}`,
              )
              .join(' · '),
    );
    const value = info.lastElementChild as HTMLElement;
    const link = element('button', value.textContent || '', 'sidebar-policy');
    link.title = `Open ${direction} configured policy`;
    link.onclick = () => {
      policySelection = { id: r.id, direction };
      policySignature = '';
      renderPolicyList();
      $('closePolicy').focus();
    };
    value.replaceChildren(link);
  }
  if (inventory.available && !state.control.capabilities?.includes(POLICY_CAPABILITY))
    for (const direction of ['incoming', 'outgoing'] as const)
      field(
        info,
        direction === 'incoming' ? 'Incoming rule scopes' : 'Outgoing rule scopes',
        inventory[direction].map((rule) => ruleDescription(rule, inventory!.now)).join('\n') ||
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
    field(info, 'User ID', String(r.process.uid));
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
    canDecide(state.control) &&
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
    state.control.permissions,
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
      !canDecide(state.control) ||
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
  $('controlStatus').title = [
    $('controlStatus').textContent,
    state.control.enforcement?.detail,
    state.control.permissions
      ? `${state.control.permissions.role} · ${state.control.permissions.policy_scope} policy · rule management ${state.control.permissions.can_manage_rules ? 'permitted' : 'denied'} · decisions ${state.control.permissions.can_decide ? 'permitted' : 'denied'}`
      : 'Legacy permission contract',
  ]
    .filter(Boolean)
    .join('\n');
  if (!promptID) {
    for (const label of document.querySelectorAll<HTMLElement>(
      '.col-incoming_policy small,.col-outgoing_policy small',
    ))
      label.textContent = state.control.capabilities?.includes(POLICY_CAPABILITY)
        ? 'Backend policy'
        : 'Listed · legacy';
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
      state.control.permissions,
      state.control.enforcement?.state,
      state.control.rules,
      state.control.policy
        ? [
            state.control.policy.snapshot.token,
            state.control.policy.applications.map((a) => [a.ref, a.process_ids]),
            state.control.policy.rows,
          ]
        : state.control.policyError,
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
    updateDecisionLog(state);
    renderPolicyList();
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

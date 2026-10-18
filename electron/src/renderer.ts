import { replaceKeyedRow } from './keyed-rows';
import { rowStructure } from './row-structure';
import { acceptsPublication } from './publication';
import { PROTECTION_CAPABILITY, stateProtection } from './protection-model';
import { advanceClock } from './state-clock';
import { REMEMBER_ZONE_CAPABILITY, type DecisionPreview } from './decision-remember';
import { applicationHeading } from './application-heading';
import { connectionPresentation, permissionTarget } from './connection-presentation';
import { ZONE_CAPABILITY, zoneLabel } from './network-zones';
import type { Presentation, PaneFrame } from './pane-model';
import { DISPLAY_UNITS, displayAmount, isDisplayUnit, type DisplayUnit } from './display-units';
import { initiationPresentation } from './initiation';
import { ActivityPolicy, STATUS_SLOTS, blockerGlyph } from './activity-policy';
import { ruleChip, type RuleChip } from './rule-chip';
import {
  POLICY_CAPABILITY,
  authoritativePolicy,
  authoritativeZonePolicy,
  authoritativeProcessPolicy,
} from './policy';
import { ruleStatus, ruleState, ruleDescription, configuredPolicy } from './rule-status';
import { canDecide } from './protocol';
import type { Application } from './protocol';
import { TrafficGraph } from './graph';
import { setupWorkflows, updateWorkflows, openRule, resumeRuleEditor } from './workflows';
import { setupDecisionLog, showDecisionLog, updateDecisionLog } from './decision-log-view';
import type { ClientState, ViewEvent, Scope } from './protocol';
import {
  hierarchy,
  hasObservedConnection,
  overview,
  networkOverviews,
  NETWORK_UNAVAILABLE,
  flatten,
  allRows,
  sum,
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
let presentation: Presentation | undefined;
let selectionPending = '';
function syncSelection() {
  if (
    !state ||
    selectionPending === selected ||
    (presentation?.selection === selected &&
      presentation.generation === state.observation.generation)
  )
    return;
  selectionPending = selected;
  const pending = selected;
  void window.flowgate
    .paneUpdate({ selection: selected, generation: state.observation.generation })
    .catch(() => {})
    .finally(() => {
      if (selectionPending === pending) selectionPending = '';
    });
}
// Declared before the init code below: esbuild hoists top-level lets, so order matters.
let displayUnit: DisplayUnit = 'autoByte';
let rateMode: 'rate' | 'total' = 'rate';
// Retain only the selected context, not a second inventory. Never rebind by PID/name.
let retainedSelection: { generation: string; row: Row } | undefined;
let measurementSource: 'tcp' | 'udp' = 'tcp';
let graph: TrafficGraph | undefined;
let activityPolicy: ActivityPolicy | undefined;
let selectedRequest = promptID ?? '';
let chosenScope: Scope = 'once';
let decisionZone: 'any' | 'local' | 'internet' = 'any';
let decisionReviews: Partial<Record<'allow' | 'block', DecisionPreview>> = {};
let reviewSequence = 0,
  reviewChecking = false,
  reviewMessage = '',
  reviewFor = '';
function needsDecisionReview() {
  return chosenScope !== 'once' && !!state.control.capabilities?.includes(REMEMBER_ZONE_CAPABILITY);
}
function reviewKey() {
  return JSON.stringify([
    state.control.generation,
    selectedRequest,
    chosenScope,
    decisionZone,
    state.control.networkZones?.revision,
  ]);
}
async function prepareDecisions() {
  const e = currentEvent();
  const seq = ++reviewSequence,
    key = reviewKey();
  decisionReviews = {};
  reviewMessage = '';
  reviewChecking = false;
  if (!e || !needsDecisionReview() || !actionable(e)) {
    updateDecisions();
    return;
  }
  reviewChecking = true;
  updateDecisions();
  try {
    const entries = await Promise.all(
      (['allow', 'block'] as const).map(
        async (action) =>
          [
            action,
            await window.flowgate.decisionPreview({
              generation: state.control.generation,
              id: e.id,
              action,
              scope: chosenScope,
              network_zone: decisionZone,
              zone_revision: state.control.networkZones?.revision || '',
            }),
          ] as const,
      ),
    );
    if (seq === reviewSequence && key === reviewKey()) {
      decisionReviews = Object.fromEntries(entries);
      reviewFor = key;
    }
  } catch (error) {
    if (seq === reviewSequence && key === reviewKey()) reviewMessage = String(error);
  } finally {
    if (seq === reviewSequence) {
      reviewChecking = false;
      updateDecisions();
    }
  }
}
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

const appNames = new Map<string, string>();
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
    img.width = img.height = 16;
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
          const result = await window.flowgate.applicationMetadata(keys);
          for (const [key, metadata] of Object.entries(result)) {
            const url = metadata.icon;
            if (metadata.name) {
              if (appNames.size >= 2048) appNames.delete(appNames.keys().next().value!);
              appNames.set(key, metadata.name);
              for (const label of document.querySelectorAll<HTMLElement>('[data-display-key]'))
                if (label.dataset.displayKey === key) label.textContent = metadata.name;
            }
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

// Seven-slot Rule Status strip. Slots 4/5 are the In/Out Blocker state for the
// row's own target (a process without its own rule shows its application fallback dimmed). The
// other slots are explicitly unavailable rule families, never controls.
function showFloatingRuleStatus() {
  let floating = $('floatingRuleStatus');
  if (!floating) {
    floating = element('section', '', 'floating-rule-status');
    floating.id = 'floatingRuleStatus';
    floating.setAttribute('aria-label', 'Activity rule status');
    const title = element('header', 'Rule Status · actions reviewed in Activity');
    const close = element('button', '✕');
    close.setAttribute('aria-label', 'Close floating rule status');
    title.append(close);
    floating.append(title);
    document.body.append(floating);
    const anchor = document.createComment('Info rule host');
    $('infoRules').before(anchor);
    close.onclick = () => {
      anchor.after($('infoRules'));
      floating.remove();
      anchor.remove();
    };
  }
  floating.append($('infoRules'));
}
function statusFamilyGlyph(key: string) {
  const span = element('span', '', 'slot-icon family-' + key);
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', '0 0 16 16');
  svg.setAttribute('aria-hidden', 'true');
  const path = document.createElementNS(svg.namespaceURI, 'path');
  path.setAttribute(
    'd',
    key === 'in-blocker' || key === 'out-blocker'
      ? 'M3.5 7.5L6.2 10.2L12 4.4'
      : key.includes('quota')
        ? 'M8 1l6 3v8l-6 3-6-3V4zM8 1v14M2 4l6 4 6-4'
        : key === 'dl-limit'
          ? 'M8 3v10M4 9l4 4 4-4'
          : 'M8 13V3M4 7l4-4 4 4',
  );
  path.setAttribute('fill', 'none');
  path.setAttribute('stroke', 'currentColor');
  path.setAttribute('stroke-width', key === 'in-blocker' || key === 'out-blocker' ? '2.2' : '1.3');
  path.setAttribute('stroke-linecap', 'round');
  path.setAttribute('stroke-linejoin', 'round');
  svg.append(path);
  span.append(svg);
  return span;
}
function statusStrip(r: Row) {
  const cell = element('td', '', 'rule-status');
  const strip = element('span', '', 'status-strip');
  strip.setAttribute('role', 'group');
  strip.setAttribute('aria-label', r.label + ' rule status');
  const status = ruleStatus(r, state);
  const authoritative = state.control.capabilities?.includes(POLICY_CAPABILITY);
  const result = authoritative ? authoritativePolicy(r, state) : undefined;
  const processPolicy = authoritativeProcessPolicy(r, state);
  for (const slot of STATUS_SLOTS) {
    if (!slot.direction) {
      const dot = element('span', '', 'status-slot unavailable');
      dot.append(element('span', '·', 'slot-dot'), statusFamilyGlyph(slot.key));
      dot.title = `${slot.label}: not a FlowGate feature`;
      strip.append(dot);
      continue;
    }
    const direction = slot.direction;
    const button = element('button', '', 'policy-cell status-slot');
    button.dataset.direction = direction;
    button.disabled =
      r.kind === 'overview' ||
      (r.kind === 'network' && !state.control.capabilities?.includes(ZONE_CAPABILITY));
    let chip: RuleChip = { glyph: '', text: 'Not set', tone: 'none', detail: '' };
    let fallbackShown = false;
    let title = '';
    if (r.kind === 'network' && state.control.capabilities?.includes(ZONE_CAPABILITY)) {
      const zone = authoritativeZonePolicy(r, state);
      chip = ruleChip(zone?.[direction], false, true);
      title = `${r.label} · all programs · ${direction}\n${zone?.[direction].reason || 'Policy unavailable'}`;
    } else if (r.kind === 'overview' || r.kind === 'network') {
      chip = { glyph: '', text: '', tone: 'none', detail: '' };
      title = r.kind === 'network' ? NETWORK_UNAVAILABLE : 'Machine: no rules at this level.';
    } else if (r.kind === 'socket') {
      chip = { glyph: '', text: '', tone: 'none', detail: '' };
      title = `${slot.label}: connections carry no rules; see the holder process.`;
    } else if (authoritative) {
      const summary = processPolicy?.[direction] || result?.application?.[direction];
      const fallback =
        processPolicy && !processPolicy[direction].rules.length
          ? processPolicy[
              direction === 'incoming' ? 'application_incoming' : 'application_outgoing'
            ]
          : undefined;
      const shown = fallback?.rules.length ? fallback : summary;
      fallbackShown = !!fallback?.rules.length;
      chip = ruleChip(shown, processPolicy?.state === 'inactive' && shown === summary, true);
      title = summary
        ? `${slot.label}: ${chip.text}${fallbackShown ? ' (application fallback; no own rule)' : ''}\n${chip.detail}\n${summary.reason}\nEnforcement: ${summary.enforcement.state} · ${summary.enforcement.reason}`
        : `${slot.label}: ${result?.reason || 'unavailable'}`;
      if (!summary) chip = { glyph: '', text: 'Unavailable', tone: 'unavailable', detail: '' };
    } else if (status.available) {
      const rules = status[direction];
      chip = {
        glyph: '',
        text: rules.length ? configuredPolicy(rules, status.now) : 'Not set',
        tone:
          rules.length === 1
            ? (ruleState(rules[0], status.now) as RuleChip['tone'])
            : rules.length
              ? 'mixed'
              : 'none',
        detail: rules.map((rule) => ruleDescription(rule, status.now)).join('\n'),
      };
      title = `${slot.label} (compatibility inventory): ${chip.text}\n${chip.detail}`;
    } else title = `${slot.label}: ${status.reason}`;
    if (['allow', 'block', 'mixed', 'off'].includes(chip.tone)) button.append(blockerGlyph(chip));
    else button.append(element('span', '·', 'slot-dot'), statusFamilyGlyph(slot.key));
    button.classList.add('tone-' + chip.tone);
    if (fallbackShown) button.classList.add('policy-fallback');
    button.title =
      title +
      (state.control.enforcement?.state === 'stopped' ? '\nStored only; enforcement stopped.' : '');
    button.setAttribute('aria-label', `${r.label} · ${slot.label} · ${chip.text || 'none'}`);
    button.onclick = (event) => {
      event.stopPropagation();
      selected = r.id;
      void window.flowgate.paneUpdate({
        selection: selected,
        generation: state.observation.generation,
      });
      for (const tr of document.querySelectorAll<HTMLElement>('#rows tr'))
        tr.setAttribute('aria-selected', String(tr.dataset.id === selected));
      renderInfo();
      if (presentation?.panes.info !== 'docked') showFloatingRuleStatus();
      activityPolicy?.activate(direction, undefined, button);
    };
    strip.append(button);
  }
  cell.append(strip);
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
  persistent: 'Remember · persistent',
};
if (promptID) {
  root.innerHTML = `<section class="prompt-shell"><header class="prompt-heading"><strong>FlowGate Blocker</strong><span id="promptPending">Connection permission</span><button id="closePrompt" aria-label="Dismiss permission window">×</button></header><div id="promptBody"><div id="requestDetails"></div></div><footer><span id="controlStatus"></span><button id="dismiss">Decide later</button></footer><div id="feedback" role="status" aria-live="polite"></div></section>`;
  $('dismiss').onclick = () => void window.flowgate.dismissPrompt();
  $('closePrompt').onclick = () => void window.flowgate.dismissPrompt();
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') {
      event.preventDefault();
      void window.flowgate.dismissPrompt();
    }
  });
} else {
  root.innerHTML = `<header class="toolbar"><strong class="brand">FLOWGATE</strong><span id="toolbarUnits" class="toolbar-units"><label for="displayUnits">Units</label><select id="displayUnits" aria-label="Display units" title="Display only: bytes or bits, decimal SI prefixes (1 KB = 1000 B). Accounting sources stay separate."></select></span><span id="observerStatus" class="toolbar-status"></span><span id="controlStatus" class="toolbar-status"></span><span class="toolbar-layout"><select id="layoutPreset" aria-label="Window layout"><option value="chart">Default with Chart</option><option value="plain">Default</option><option value="activity">Activity only</option></select></span><input id="search" type="search" aria-label="Search Activity" placeholder="Search"></header><nav class="tabs" aria-label="Views"><button id="activityTab" aria-selected="true">Activity</button><button id="requestsTab" aria-selected="false">Pending requests <span id="pendingCount">0</span></button><span id="tabsPaneControls" class="pane-controls"></span></nav><main id="activityView"><section class="activity-main"><div class="filterbar"><select id="activitySource" aria-label="Activity measurement source"><option value="tcp">TCP</option><option value="udp">UDP</option></select><button id="rateMode" aria-pressed="false" title="Switch the two traffic columns between current rate and total transferred">Rate</button><select id="columnPreset" aria-label="Column preset"><option value="status">Status</option><option value="details">Details</option></select><select id="filter" aria-label="Socket filter"><option value="all">All sockets</option><option value="active">Active TCP / connected UDP</option><option value="listening">Listening TCP / bound UDP</option></select><span class="filterbar-icons"><button id="expand" class="icon-button" title="Expand all" aria-label="Expand all">⊞</button><button id="collapse" class="icon-button" title="Collapse all" aria-label="Collapse all">⊟</button><button id="refreshNow" class="icon-button" title="Refresh now" aria-label="Refresh now">↻</button></span></div><div class="table-scroll"><table id="tree" role="treegrid" tabindex="0" aria-label="Application process socket activity"><thead><tr id="headers"></tr></thead><tbody id="rows"></tbody></table></div><div id="activitySummary" class="summary"></div></section><aside><h2>Info View<span id="infoPaneControls" class="pane-controls"></span></h2><h3 id="selectedName">FlowGate Activity</h3><div id="selectedExecutable"></div><div class="info-scroll"><h3 id="infoProperties" class="info-section-title">Overview</h3><dl id="info"></dl><section id="infoRules"></section><section class="info-tools"><h3 class="info-section-title">Tools</h3><button id="infoOpenRules">Rule list</button><button id="infoOpenLog">Decision log</button><button id="infoOpenPending">Pending requests</button></section></div><section id="trafficGraph"></section></aside></main><main id="requestsView" hidden><section class="request-list"><h2>Pending &amp; recent requests</h2><p class="hint">Select a request to decide. Dismissal grants nothing. Closing FlowGate leaves an independent controller running.</p><div class="table-scroll"><table id="requests"><thead><tr><th>Application</th><th>Direction</th><th>Protocol</th><th>Remote endpoint</th><th>State</th></tr></thead><tbody id="requestRows"></tbody></table></div></section><aside class="request-sidebar"><h2>Connection permission</h2><div id="requestDetails"></div></aside></main><footer><span id="footerSummary"></span><span id="feedback" role="status" aria-live="polite"></span></footer>`;
  const columns = [
    ['name', 'Name'],
    ['download_bps', 'DL Rate'],
    ['upload_bps', 'UL Rate'],
    ['rule_status', 'Rule Status'],
    ['count', 'Sockets'],
    ['pid', 'PID'],
    ['downloaded', 'Downloaded'],
    ['uploaded', 'Uploaded'],
    ['protocol', 'Protocol'],
    ['local', 'Local endpoint'],
    ['remote', 'Remote endpoint'],
    ['state', 'State'],
    ['filler', ''],
  ];
  for (const [key, title] of columns) {
    const th = element('th');
    th.className = 'col-' + key;
    const b = element('button', title);
    if (key === 'download_bps' || key === 'upload_bps') {
      b.classList.add('rate-header');
      b.append(element('small', 'autoByte (def)'));
    }
    b.disabled = key === 'rule_status';
    b.onclick = () => {
      const actual =
        key === 'download_bps' ? rateKeys()[0] : key === 'upload_bps' ? rateKeys()[1] : key;
      descending = sort === actual ? !descending : /bps|loaded/.test(actual);
      sort = actual;
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
  graph = new TrafficGraph($('trafficGraph'), {
    change: (chart) => void window.flowgate.paneUpdate({ chart }).catch(message),
    source: (source) => void window.flowgate.paneUpdate({ source }).catch(message),
  });
  setupPaneControls();
  activityPolicy = new ActivityPolicy($('infoRules'));
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
    void window.flowgate.paneUpdate({ source: measurementSource }).catch(message);
    renderTree();
    renderInfo();
  };
  $('filter').onchange = () => {
    syncFilterGroup();
    buildTree();
  };
  // Reference-style All / Active / Listening toggle strip; the select stays as the accessible model.
  const filterGroup = element('div', '', 'filter-group');
  filterGroup.setAttribute('role', 'radiogroup');
  filterGroup.setAttribute('aria-label', 'Socket filter');
  for (const [value, label] of [
    ['all', 'All'],
    ['active', 'Active'],
    ['listening', 'Listening'],
  ]) {
    const b = element('button', label);
    b.dataset.value = value;
    b.setAttribute('role', 'radio');
    b.onclick = () => {
      $<HTMLSelectElement>('filter').value = value;
      syncFilterGroup();
      buildTree();
    };
    filterGroup.append(b);
  }
  $('filter').after(filterGroup);
  $('filter').classList.add('visually-hidden');
  function syncFilterGroup() {
    for (const b of filterGroup.querySelectorAll<HTMLElement>('button'))
      b.setAttribute(
        'aria-checked',
        String(b.dataset.value === $<HTMLSelectElement>('filter').value),
      );
  }
  syncFilterGroup();
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
    const children = [...networkOverviews(), ...roots];
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
  $('footerSummary').textContent = $('activitySummary').textContent = a
    ? `${roots[0]?.children.reduce((n, r) => n + r.rows.length, 0) || 0} / ${a.rows.length} sockets · ${a.complete ? 'Complete census' : 'Partial visibility'}`
    : state.observation.message;
  $('activitySummary').title = $('footerSummary').title = [a?.collected, ...(a?.issues || [])]
    .filter(Boolean)
    .join(' · ');
}
// Reference dock controls (▾ menu: Open Window ▸ / Close; ✕: Close) for the Info View and the
// Traffic chart. The Activity list itself cannot be closed, so its strip only offers Open Window.
// Reference control row: Rate/Total toggle and column preset (Status = the four reference columns).
const rateKeys = (): Metric[] =>
  rateMode === 'rate' ? ['download_bps', 'upload_bps'] : ['downloaded', 'uploaded'];
function applyRateMode() {
  $('rateMode').textContent = rateMode === 'rate' ? 'Rate' : 'Total';
  $('rateMode').setAttribute('aria-pressed', String(rateMode === 'total'));
  for (const [key, label] of [
    ['download_bps', 'DL'],
    ['upload_bps', 'UL'],
  ]) {
    const b = document.querySelector<HTMLElement>(`.col-${key} button`);
    if (b) b.childNodes[0].textContent = `${label} ${rateMode === 'rate' ? 'Rate' : 'Total'}`;
  }
}
function applyColumnPreset() {
  document.body.classList.toggle(
    'preset-status',
    $<HTMLSelectElement>('columnPreset').value === 'status',
  );
}
function paneList(): { key: 'info' | 'chart'; label: string }[] {
  return [
    { key: 'info', label: 'Info View' },
    { key: 'chart', label: 'Traffic chart' },
  ];
}
function paneState(): Record<'info' | 'chart', boolean> {
  return {
    info: presentation?.panes.info !== 'hidden',
    chart: presentation?.panes.chart !== 'hidden',
  };
}
function applyPanes() {
  const info = presentation?.panes.info || 'docked',
    chart = presentation?.panes.chart || 'docked';
  document.body.classList.toggle('hide-sidebar', info !== 'docked' && chart !== 'docked');
  document.body.classList.toggle('hide-info', info !== 'docked');
  document.body.classList.toggle('hide-chart', chart !== 'docked');
  document.body.classList.toggle('info-detached', info === 'detached');
  document.body.classList.toggle('chart-detached', chart === 'detached');
  for (const item of document.querySelectorAll<HTMLButtonElement>('.pane-menu button[data-pane]')) {
    const key = item.dataset.pane as 'info' | 'chart';
    item.setAttribute('aria-checked', String(paneState()[key]));
    item.title =
      presentation?.panes[key] === 'detached'
        ? 'Detached — click to dock'
        : paneState()[key]
          ? 'Close pane'
          : 'Open pane';
  }
  const layout = $<HTMLSelectElement>('layoutPreset');
  if (layout)
    layout.value = info !== 'docked' ? 'activity' : chart === 'docked' ? 'chart' : 'plain';
  void graph?.update(selected, sequence + ':panes');
}
function setPane(key: 'info' | 'chart', open: boolean) {
  void window.flowgate.paneControl(key, open ? 'dock' : 'close').catch(message);
}
function paneControls(self?: 'info' | 'chart', summaryText = '▾') {
  const wrap = element('span', '', 'pane-controls-inner');
  const menu = element('details', '', 'desktop-menu pane-menu');
  const summary = element('summary', summaryText);
  summary.title = 'Window menu';
  summary.setAttribute(
    'aria-label',
    (self ? paneList().find((p) => p.key === self)!.label : 'Activity') + ' window menu',
  );
  const panel = element('div', '', 'menu-panel');
  panel.append(element('div', 'Open Window', 'menu-heading'));
  for (const pane of paneList()) {
    const item = element('button', pane.label);
    item.dataset.pane = pane.key;
    item.setAttribute('role', 'menuitemcheckbox');
    item.onclick = () => {
      setPane(pane.key, presentation?.panes[pane.key] === 'detached' || !paneState()[pane.key]);
      menu.open = false;
    };
    panel.append(item);
  }
  if (self) {
    const undock = element('button', 'Undock');
    undock.dataset.undock = self;
    undock.onclick = () => {
      void window.flowgate.paneControl(self, 'undock').catch(message);
      menu.open = false;
    };
    panel.prepend(undock, element('hr'));
    const close = element('button', 'Close');
    close.onclick = () => {
      setPane(self, false);
      menu.open = false;
    };
    panel.append(element('hr'), close);
  }
  menu.append(summary, panel);
  wrap.append(menu);
  if (self) {
    const x = element('button', '✕', 'pane-close');
    x.title =
      'Close ' + paneList().find((p) => p.key === self)!.label + ' (reopen from any ▾ window menu)';
    x.setAttribute('aria-label', x.title);
    x.onclick = () => setPane(self, false);
    wrap.append(x);
  }
  return wrap;
}
function updateFirewallStatus() {
  const status = document.getElementById('firewallMenuStatus');
  if (!status) return;
  const summary = document.querySelector('#controlMenu > summary');
  status.textContent = state?.control.capabilities?.includes(PROTECTION_CAPABILITY)
    ? stateProtection(state)
    : state?.control.capabilities?.includes('daemon-evaluation-v1')
      ? summary?.textContent || 'Firewall · unknown'
      : !state?.control.connected
        ? 'Firewall · unavailable'
        : `Firewall · ${state.control.enforcement?.state || 'unknown'}`;
  status.title =
    document.getElementById('controlStatus')?.title ||
    'Enforcement state unavailable. Monitoring never implies protection.';
}
function setupMainMenus(windowMenu: HTMLElement) {
  const toolbar = document.querySelector('.toolbar')!;
  const make = (id: string, title: string) => {
    const menu = element('details', '', 'desktop-menu');
    menu.id = id;
    menu.append(element('summary', title), element('div', '', 'menu-panel'));
    return menu;
  };
  const file = make('fileMenu', 'File'),
    tools = make('toolsMenu', 'Tools'),
    help = make('helpMenu', 'Help');
  const exit = element('button', 'Exit FlowGate…');
  exit.onclick = () => void window.flowgate.quit();
  file.lastElementChild!.append(exit);
  const control = $('controlMenu'),
    options = $('optionsMenu');
  // The stateful controls keep their existing IDs and authorization paths, inside Tools.
  const controlTitle = control.querySelector('summary')!;
  controlTitle.dataset.menuLabel = 'Firewall';
  tools.lastElementChild!.append(control, element('hr'), options);
  const about = element('button', 'About FlowGate');
  const dialog = element('dialog');
  dialog.id = 'aboutFlowGate';
  dialog.append(
    element('h2', 'FlowGate'),
    element(
      'p',
      'Activity, stored firewall policy and explicit bounded evaluation. Monitoring and firewall enforcement are separate.',
    ),
  );
  const close = element('button', 'Close');
  close.onclick = () => dialog.close();
  dialog.append(close);
  document.body.append(dialog);
  about.onclick = () => {
    (help as HTMLDetailsElement).open = false;
    dialog.showModal();
  };
  help.lastElementChild!.append(about);
  const windowPanel = windowMenu.querySelector('.menu-panel')!;
  for (const [label, id] of [
    ['Activity', 'activityTab'],
    ['Rule list', 'rulesTab'],
    ['Pending requests', 'requestsTab'],
    ['Decision log', 'decisionLogTab'],
  ]) {
    const b = element('button', label);
    b.onclick = () => {
      $(id).click();
      const details = windowMenu.querySelector('details');
      if (details) details.open = false;
    };
    windowPanel.append(b);
  }
  $('toolbarUnits').before(file, tools, windowMenu, help);
  // Preserve an obvious state entry point; text is updated by the existing evaluation state.
  const status = element('button', 'Firewall controls', 'firewall-state');
  status.id = 'firewallMenuStatus';
  status.onclick = () => {
    (tools as HTMLDetailsElement).open = true;
    (control as HTMLDetailsElement).open = true;
  };
  $('toolbarUnits').after(status);
  new MutationObserver(updateFirewallStatus).observe(controlTitle, {
    childList: true,
    characterData: true,
    subtree: true,
    attributes: true,
  });
  updateFirewallStatus();
  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;
    const open = [...toolbar.querySelectorAll<HTMLDetailsElement>('.desktop-menu[open]')];
    if (!open.length) return;
    for (const menu of open) menu.open = false;
    open[0].querySelector<HTMLElement>('summary')?.focus();
  });
  for (const menu of toolbar.querySelectorAll<HTMLDetailsElement>('.desktop-menu'))
    menu.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        e.stopPropagation();
        menu.open = false;
        menu.querySelector<HTMLElement>('summary')?.focus();
      }
    });
}
function displayMetric(s: ReturnType<typeof sum>, rate = false) {
  return s.mixed
    ? 'Mixed sources'
    : displayAmount(s.value, rate, displayUnit) + (s.value !== undefined && s.partial ? ' *' : '');
}
function setupPaneControls() {
  $('infoPaneControls').append(paneControls('info'));
  $('tabsPaneControls').append(paneControls());
  // Toolbar "Window" menu (reference: Window menu lists dockable windows).
  const windowMenu = paneControls(undefined, 'Window');
  windowMenu.classList.add('toolbar-window-menu');
  (document.getElementById('controlMenu') || document.querySelector('.brand'))!.after(windowMenu);
  // Display units never change the chosen accounting source or numeric sorting.
  const units = $<HTMLSelectElement>('displayUnits');
  for (const value of DISPLAY_UNITS) units.add(new Option(value, value));
  const applyUnit = (value: DisplayUnit) => {
    displayUnit = value;
    units.value = value;
    for (const small of document.querySelectorAll('.rate-header small'))
      small.textContent = value + ' (def)';
    graph?.setUnit(value);
    if (state) renderTree();
  };
  units.onchange = () => {
    if (!isDisplayUnit(units.value)) return;
    applyUnit(units.value);
    void window.flowgate.paneUpdate({ unit: displayUnit }).catch(message);
  };
  void window.flowgate
    .preferences()
    .then((p) => applyUnit(isDisplayUnit(p.displayUnit) ? p.displayUnit : 'autoByte'));
  const sourceLabel = element('label', 'Accounting source ', 'source-control');
  sourceLabel.append($('activitySource'));
  document.querySelector('#controlMenu .menu-panel')!.prepend(sourceLabel);
  setupMainMenus(windowMenu);
  $<HTMLSelectElement>('layoutPreset').onchange = () => {
    const v = $<HTMLSelectElement>('layoutPreset').value;
    void window.flowgate.paneControl('info', v === 'activity' ? 'close' : 'dock');
    void window.flowgate.paneControl('chart', v === 'chart' ? 'dock' : 'close');
  };
  const chartHead = document.querySelector('#trafficGraph .graph-heading');
  if (chartHead) {
    const c = element('span', '', 'pane-controls');
    const controls = paneControls('chart');
    // Chart source / window options live in the chart's ▾ menu (reference header has no selects).
    const panel = controls.querySelector('.menu-panel')!;
    for (const [id, heading] of [
      ['graphSource', 'Source'],
      ['graphWindow', 'Window'],
    ]) {
      const select = document.getElementById(id) as HTMLSelectElement;
      panel.append(element('hr'), element('div', heading, 'menu-heading'));
      for (const option of Array.from(select.options)) {
        const item = element('button', option.textContent || '');
        item.setAttribute('role', 'menuitemradio');
        const sync = () => item.setAttribute('aria-checked', String(select.value === option.value));
        sync();
        select.addEventListener('change', sync);
        item.onclick = () => {
          select.value = option.value;
          select.dispatchEvent(new Event('change'));
          (controls.querySelector('details') as HTMLDetailsElement).open = false;
        };
        panel.append(item);
      }
    }
    c.append(controls);
    chartHead.append(c);
  }
  $('rateMode').onclick = () => {
    const was = rateKeys();
    rateMode = rateMode === 'rate' ? 'total' : 'rate';
    if (was.includes(sort as Metric)) sort = rateKeys()[was.indexOf(sort as Metric)];
    applyRateMode();
    renderTree();
  };
  $('columnPreset').onchange = applyColumnPreset;
  $('refreshNow').onclick = () => void window.flowgate.snapshot().then(consume);
  applyRateMode();
  applyColumnPreset();
  document.addEventListener('pointerdown', (event) => {
    for (const menu of document.querySelectorAll<HTMLDetailsElement>('.pane-menu[open]'))
      if (!menu.contains(event.target as Node)) menu.open = false;
  });
  applyPanes();
}
const renderedRows = new Map<
  string,
  { signature: string; presentation: string; policyRevision: number; node: HTMLTableRowElement }
>();
let treePolicyRevision = 0;
function renderTree() {
  for (const th of document.querySelectorAll<HTMLElement>('#headers th')) {
    const key = th.className.replace('col-', '');
    const actual =
      key === 'download_bps' ? rateKeys()[0] : key === 'upload_bps' ? rateKeys()[1] : key;
    th.setAttribute(
      'aria-sort',
      actual === sort ? (descending ? 'descending' : 'ascending') : 'none',
    );
  }
  const focused = document.activeElement as HTMLElement;
  const focusedPolicy = focused?.classList.contains('policy-cell')
    ? { id: focused.closest('tr')?.dataset.id, direction: focused.dataset.direction }
    : undefined;
  visible = flatten(roots, expanded, sort, descending, measurementSource);
  const body = $('rows');
  const ordered: HTMLTableRowElement[] = [];
  const liveIds = new Set<string>();
  for (const { row: r, depth } of visible) {
    liveIds.add(r.id);
    const rowSignature = rowStructure(r, depth, selected === r.id, expanded.has(r.id));
    const rateValues = rateKeys().map((key) => sum(r.rows, key, measurementSource));
    const totalValues = (['downloaded', 'uploaded'] as Metric[]).map((key) =>
      sum(r.rows, key, measurementSource),
    );
    const cellPresentation = JSON.stringify([
      measurementSource,
      displayUnit,
      rateMode,
      rateValues,
      totalValues,
    ]);
    const cached = renderedRows.get(r.id);
    if (cached?.signature === rowSignature) {
      if (cached.presentation !== cellPresentation) {
        for (const [index, key] of rateKeys().entries()) {
          const value = rateValues[index],
            cell = cached.node.cells[index + 1];
          const className =
            'numeric ' +
            (value.value && value.value > 0 ? (key.startsWith('download') ? 'down' : 'up') : '');
          if (cell.className !== className) cell.className = className;
          const text = displayMetric(value, rateMode === 'rate'),
            span = cell.querySelector('.rate-value')!;
          if (span.textContent !== text) span.textContent = text;
          cell.title = `${measurementSource.toUpperCase()} · ${value.known}/${value.count} measured sockets${value.mixed ? ' · incompatible measurement sources' : ''}`;
        }
        for (const [index, key] of (['downloaded', 'uploaded'] as Metric[]).entries()) {
          const cell = cached.node.cells[index + 6],
            text = displayMetric(totalValues[index]);
          if (cell.textContent !== text) cell.textContent = text;
        }
        cached.presentation = cellPresentation;
      }
      if (cached.policyRevision !== treePolicyRevision) {
        const policy = statusStrip(r),
          previous = cached.node.querySelector('.rule-status')!;
        // Keep unchanged controls/focus. Handlers capture only the stable row ID;
        // current row identity is resolved by renderInfo and the main rule service.
        if (previous.innerHTML !== policy.innerHTML) previous.replaceWith(policy);
        cached.policyRevision = treePolicyRevision;
      }
      ordered.push(cached.node);
      continue;
    }
    const tr = element('tr');
    tr.dataset.id = r.id;
    tr.setAttribute('aria-level', String(depth + 1));
    tr.setAttribute('aria-selected', String(selected === r.id));
    if (r.children.length) tr.setAttribute('aria-expanded', String(expanded.has(r.id)));
    tr.onclick = () => {
      selected = r.id;
      for (const row of document.querySelectorAll<HTMLElement>('#rows tr'))
        row.setAttribute('aria-selected', String(row.dataset.id === selected));
      renderInfo();
      $('tree').focus();
    };
    tr.ondblclick = (event) => {
      if ((event.target as HTMLElement).closest('button,input,select')) return;
      if (r.children.length) {
        if (expanded.has(r.id)) expanded.delete(r.id);
        else expanded.add(r.id);
        renderTree();
        renderInfo();
      } else void window.flowgate.paneControl('info', 'open').catch(message);
    };
    const name = element('td');
    name.className = `name depth-${depth}`;
    const toggle = element(
      'button',
      r.children.length ? (expanded.has(r.id) ? '◢' : '▷') : '',
      'disclosure',
    );
    toggle.tabIndex = -1;
    toggle.setAttribute('aria-label', (expanded.has(r.id) ? 'Collapse ' : 'Expand ') + r.label);
    toggle.disabled = !r.children.length;
    toggle.onclick = (e) => {
      e.stopPropagation();
      if (expanded.has(r.id)) {
        expanded.delete(r.id);
        const current = allRows(roots).find((v) => v.id === r.id) || r;
        if (allRows([current]).some((v) => v.id === selected)) selected = r.id;
      } else expanded.add(r.id);
      renderTree();
      renderInfo();
    };
    const displayApp = r.process?.application || r.displayApplication;
    const displayKey =
      displayApp && JSON.stringify([displayApp.key, displayApp.revision, displayApp.executable]);
    let rowLabel =
      r.kind === 'application' && displayKey ? appNames.get(displayKey) || r.label : r.label;
    let icon: HTMLElement = installedIcon(
      r.kind !== 'application' ? undefined : r.displayApplication || rowApplication(r),
      r.kind,
    );
    if (r.socket) {
      const direction = initiationPresentation(r.socket);
      icon = element('span', direction.glyph, 'connection-direction ' + direction.className);
      icon.title = direction.title;
      icon.setAttribute('role', 'img');
      icon.setAttribute('aria-label', direction.label);
      if (direction.state === 'listening') rowLabel = r.socket.socket.local;
      if (direction.state === 'unconnected') rowLabel = r.socket.socket.local;
    }
    // A dot is a connected-peer observation, not simply a row-exists indicator.
    const connected = hasObservedConnection(r);
    const led = element('span', '', 'online-dot' + (connected ? ' on' : ''));
    led.title = connected
      ? 'Contains an observed established TCP or connected UDP socket. Not a firewall, delivery or reachability verdict.'
      : 'No observed connected peer; listening/bound sockets do not light this indicator.';
    led.setAttribute('aria-hidden', 'true');
    const textLabel = element('span', rowLabel, 'row-name-text');
    if (r.kind === 'application' && displayKey) textLabel.dataset.displayKey = displayKey;
    name.append(led, toggle, icon, textLabel);
    name.title = r.process?.executable || r.socket?.socket.remote || r.label;
    tr.append(name);
    for (const key of rateKeys()) {
      const s = sum(r.rows, key, measurementSource);
      const td = element(
        'td',
        displayMetric(s, rateMode === 'rate'),
        'numeric ' + (s.value && s.value > 0 ? (key.startsWith('download') ? 'down' : 'up') : ''),
      );
      const rateText = td.textContent || '';
      td.replaceChildren(element('span', rateText, 'rate-value'));
      td.title = `${measurementSource.toUpperCase()} · ${s.known}/${s.count} measured sockets${s.mixed ? ' · incompatible measurement sources' : ''}`;
      tr.append(td);
    }
    tr.append(statusStrip(r));
    tr.append(
      element('td', String(r.rows.length), 'numeric'),
      element('td', r.pid === undefined ? '' : String(r.pid), 'numeric'),
    );
    for (const key of ['downloaded', 'uploaded'] as Metric[])
      tr.append(element('td', displayMetric(sum(r.rows, key, measurementSource)), 'numeric'));
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
    tr.append(element('td', '', 'filler'));
    // Replace the old keyed node in place before ordering. Leaving it in tbody
    // shifts every following sibling and turns one selection change into N moves.
    replaceKeyedRow(cached?.node, tr);
    renderedRows.set(r.id, {
      signature: rowSignature,
      presentation: cellPresentation,
      policyRevision: treePolicyRevision,
      node: tr,
    });
    ordered.push(tr);
  }
  for (const [id, cached] of renderedRows)
    if (!liveIds.has(id)) {
      cached.node.remove();
      renderedRows.delete(id);
    }
  for (let i = 0; i < ordered.length; i++)
    if (body.children[i] !== ordered[i]) body.insertBefore(ordered[i], body.children[i] || null);
  while (body.children.length > ordered.length) body.lastElementChild!.remove();
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
  syncSelection();
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
          'Executable status',
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
  const liveRow = allRows(roots).find((r) => r.id === selected);
  if (liveRow && ['process', 'socket'].includes(liveRow.kind))
    retainedSelection = { generation: state.control.generation, row: liveRow };
  else if (
    liveRow ||
    retainedSelection?.row.id !== selected ||
    retainedSelection.generation !== state.control.generation
  )
    retainedSelection = undefined;
  const retained = !liveRow && retainedSelection?.row;
  const r = liveRow || (retained ? { ...retained, rows: [], children: [] } : undefined);
  activityPolicy?.update(r, state);
  $('infoProperties').textContent =
    r?.kind === 'socket'
      ? 'Connection properties'
      : r?.kind === 'process'
        ? 'Process properties'
        : r?.kind === 'application'
          ? 'Application properties'
          : 'Overview';
  const selectedApp = r?.process?.application || r?.displayApplication;
  const rawPath = r?.process?.executable || r?.displayApplication?.executable || '';
  const pathText = selectedApp?.display_executable || rawPath.replace(/ \(deleted\)$/, '');
  if ($('selectedExecutable').textContent !== pathText)
    $('selectedExecutable').textContent = pathText;
  $('selectedExecutable').title =
    rawPath +
    (rawPath.endsWith(' (deleted)')
      ? ' · Running replaced/deleted executable; original identity retained.'
      : '');
  $('selectedExecutable').hidden = !pathText;
  const selectedName = $('selectedName');
  if (selectedName.dataset.identity !== (r?.id || '')) {
    selectedName.dataset.identity = r?.id || '';
    // The chart legend names the selected entity (reference), not the type word shown as title.
    selectedName.dataset.label = r?.label || '';
    selectedName.replaceChildren(
      ...(r ? [installedIcon(r.displayApplication || rowApplication(r), r.kind)] : []),
      document.createTextNode(
        !r
          ? 'FlowGate Activity'
          : r.kind === 'application'
            ? 'Application'
            : r.kind === 'process'
              ? `Process ${r.pid ?? ''}`.trim()
              : r.kind === 'socket'
                ? 'Connection'
                : r.kind === 'unidentified'
                  ? 'Unidentified'
                  : r.label,
      ),
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
  if (retained)
    field(
      info,
      'Observation',
      'Selected instance is no longer visible. No target is rebound; reselect a live instance to create a rule.',
    );
  if (r.kind === 'network') {
    field(info, 'Network', r.label);
    const config = state.control.networkZones;
    field(info, 'Target', 'All programs · configured ' + r.label + ' policy zone');
    field(
      info,
      'Coverage',
      config
        ? 'Traffic totals unavailable; UDP socket totals may span peers.'
        : NETWORK_UNAVAILABLE,
    );
    if (config) {
      field(info, 'Definition', config.model);
      field(
        info,
        'Prefixes',
        (r.id === 'network:local' ? config.local_prefixes : config.internet_prefixes).join(', ') ||
          'No configured prefixes',
      );
    }

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
    const evidence = state.observation.activity?.tcp_initiation;
    field(
      info,
      'TCP initiation',
      evidence
        ? evidence.state + ' · ' + evidence.reason
        : 'Snapshot evidence only; established direction may be unknown.',
    );
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
  if (r.displayApplication) {
    field(info, 'Display application', r.displayApplication.executable);
    field(
      info,
      'Observation only',
      'Common application of shared holders. Not a firewall permission target.',
    );
  }
  if (r.kind === 'application' || r.kind === 'process')
    field(
      info,
      'Name',
      r.process?.application
        ? appNames.get(
            JSON.stringify([
              r.process.application.key,
              r.process.application.revision,
              r.process.application.executable,
            ]),
          ) ||
            r.process.application.display_name ||
            r.process.application.name.replace(/ \(deleted\)$/, '')
        : r.label,
    );
  if (r.process) {
    if (
      r.process.application.executable_status === 'deleted' ||
      r.process.executable.endsWith(' (deleted)')
    )
      field(
        info,
        'Executable status',
        'Replaced/deleted on disk; this running image retains its original identity. Installed icon/name are display metadata only.',
      );
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
      ['Initiation', initiationPresentation(s).title],
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
      [
        'Network zone',
        s.network_scope?.state === 'known'
          ? zoneLabel(s.network_scope.zone) + ' · configured policy zone'
          : s.network_scope?.reason || 'Classification unavailable',
      ],
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
    e.attribution.application?.display_name ||
    e.attribution.application?.name.replace(/ \(deleted\)$/, '') ||
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
        decisionZone = 'any';
        decisionReviews = {};
        ++reviewSequence;
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
    e ? [e.id, e.flow, e.attribution, e.deadline, e.scope_previews] : null,
  ]);
  if (sig !== detailSignature) {
    detailSignature = sig;
    const container = $('requestDetails');
    container.replaceChildren();
    if (!e) {
      container.append(
        element(
          'p',
          promptID && promptGeneration !== state.control.generation
            ? 'Daemon session changed. This old request is no longer actionable.'
            : selectedRequest
              ? 'Request no longer present. It may have expired or been resolved by another client.'
              : 'No pending connection selected.',
          'hint',
        ),
      );
      return;
    }
    container.tabIndex = -1;
    container.onkeydown = (event) => {
      if (event.key === 'Enter' && event.target === container) event.preventDefault();
    };
    const presentation = connectionPresentation(e.flow);
    const route = element('div', '', 'connection-route');
    route.append(
      element(
        'h3',
        `${presentation.direction} connection · ${e.flow.protocol.toUpperCase()}`,
        'connection-banner',
      ),
      applicationHeading(e.attribution.application, eventName(e)),
      element('strong', e.flow.remote, 'remote-endpoint'),
    );
    route.title = presentation.relation;
    container.append(route);
    container.append(element('p', presentation.relation, 'connection-relation'));
    const fields = element('dl', '', 'connection-fields');
    field(fields, 'Local', e.flow.local);
    field(fields, 'Protocol', e.flow.protocol.toUpperCase());
    field(fields, 'Network', presentation.zone);
    fields.title = e.flow.network_scope?.reason || 'Classification unavailable';
    container.append(fields);
    const technical = element('details', '', 'identity-details');
    technical.append(element('summary', 'Details'));
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
    field(identity, 'Network classification', e.flow.network_scope?.reason || 'Unavailable');
    const preview = element('p', '', 'scope-preview');
    preview.id = 'scopePreview';
    technical.append(identity, preview);
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
    const scopeTarget = element('p', '', 'permission-target');
    scopeTarget.id = 'permissionTarget';
    container.append(scopeTarget);
    const controls = element('div', '', 'decision-controls');
    for (const [action, label] of [
      ['allow', 'Allow'],
      ['block', 'Deny'],
    ] as const) {
      const button = element('button', label, action);
      button.id = action;
      button.onclick = async () => {
        if (!actionable(currentEvent()) || currentEvent()?.id !== e.id) return;
        const generation = state.control.generation,
          scope = chosenScope;
        const preview = decisionReviews[action];
        if (
          needsDecisionReview() &&
          (reviewFor !== reviewKey() ||
            !preview ||
            Date.parse(preview.expires_at) <= (state.control.serverNow || Date.now()))
        )
          return;
        localSubmitted.add(generation + ':' + e.id);
        updateDecisions();
        message('Submitting decision…');
        try {
          const result = await window.flowgate.decide({
            generation,
            id: e.id,
            action,
            scope,
            ...(needsDecisionReview()
              ? {
                  network_zone: decisionZone,
                  zone_revision: preview!.zone_revision,
                  preview_token: preview!.token,
                }
              : {}),
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
      void prepareDecisions();
    };
    controls.append(scopes);
    container.append(controls);
    const networks = element('div', '', 'decision-network');
    const networkLabel = element('label', 'Remember on ');
    const zone = element('select');
    zone.id = 'decisionZone';
    zone.setAttribute('aria-label', 'Remember network scope');
    zone.append(new Option('Any network', 'any'));
    if (
      state.control.capabilities?.includes(REMEMBER_ZONE_CAPABILITY) &&
      e.flow.network_scope?.state === 'known' &&
      e.flow.network_scope.revision === state.control.networkZones?.revision
    )
      zone.append(new Option(zoneLabel(e.flow.network_scope.zone), e.flow.network_scope.zone));
    zone.value = decisionZone;
    if (!zone.value) {
      decisionZone = 'any';
      zone.value = 'any';
      decisionReviews = {};
    }
    zone.onchange = () => {
      decisionZone = zone.value as typeof decisionZone;
      void prepareDecisions();
    };
    networkLabel.append(zone);
    networks.append(networkLabel);
    const refresh = element('button', 'Refresh review', 'link-button');
    refresh.id = 'refreshDecision';
    refresh.onclick = () => void prepareDecisions();
    networks.append(refresh);
    container.append(networks);
    const reviewStatus = element('p', '', 'decision-review');
    reviewStatus.id = 'decisionReview';
    reviewStatus.setAttribute('role', 'status');
    container.append(reviewStatus);
    const reconcile = element('button', 'Check result', 'link-button');
    reconcile.id = 'decisionReconcile';
    reconcile.onclick = async () => {
      const current = currentEvent(),
        token = current?.attempt?.reconcile;
      if (!current || !token) return;
      reconcile.disabled = true;
      try {
        const result = await window.flowgate.decisionReconcile({
          generation: state.control.generation,
          id: current.id,
          preview_token: token,
        });
        message(result.message);
      } catch (error) {
        message(String(error));
      } finally {
        updateDecisions();
      }
    };
    container.append(reconcile);
    if (!promptID) {
      const open = element('button', 'Open permission window', 'open-prompt');
      open.onclick = () => void window.flowgate.openPrompt(e.id);
      container.append(open);
    }
    const result = element('p', e.attempt?.message || e.reason, 'request-result');
    result.id = 'requestResult';
    container.append(result);
    if (promptID && !container.dataset.focused) {
      container.focus({ preventScroll: true });
      container.dataset.focused = 'true';
    }
  }
  updateDecisions();
}
function updateDecisions() {
  const e = currentEvent();
  if (promptID && $('dismiss')) {
    const other = state.control.connected
      ? state.control.events.filter(
          (r) =>
            r.id !== promptID && r.state === 'awaiting-decision' && r.remainingMs > 0 && !r.attempt,
        ).length
      : 0;
    $('dismiss').textContent = other
      ? `Next request (${other})`
      : e?.state === 'awaiting-decision' && e.remainingMs > 0
        ? 'Decide later'
        : 'Close';
    $('dismiss').title =
      'Dismiss this view without Allow or Deny. Unanswered requests retain their original deadlines.';
  }
  if ($('promptPending'))
    $('promptPending').textContent =
      `Pending connections (${state.control.events.filter((e) => e.state === 'awaiting-decision' && e.remainingMs > 0).length})`;
  for (const id of ['allow', 'block']) {
    const b = $<HTMLButtonElement>(id);
    const review = decisionReviews[id as 'allow' | 'block'];
    if (b) {
      b.disabled =
        !actionable(e) ||
        (needsDecisionReview() &&
          (reviewFor !== reviewKey() ||
            !review ||
            Date.parse(review.expires_at) <= (state.control.serverNow || Date.now())));
      b.title = needsDecisionReview()
        ? review?.scope_preview || 'Review required'
        : e?.scope_previews[chosenScope] || '';
    }
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
    $('scopePreview').textContent = needsDecisionReview()
      ? Object.entries(decisionReviews)
          .map(([action, p]) => `${action === 'allow' ? 'Allow' : 'Deny'}: ${p.scope_preview}`)
          .join('\n') || 'Review required'
      : e?.scope_previews[chosenScope] || 'Authoritative scope unavailable; decisions disabled.';
  const zone = $<HTMLSelectElement>('decisionZone');
  if (zone) {
    zone.disabled = !!scope?.disabled || !needsDecisionReview();
    zone.title = needsDecisionReview()
      ? 'Scope of the remembered rule'
      : 'Any network · backend upgrade required for remembered zone rules';
    zone.parentElement!.parentElement!.hidden = chosenScope === 'once';
  }
  if ($('refreshDecision')) {
    const refresh = $<HTMLButtonElement>('refreshDecision');
    refresh.hidden = !needsDecisionReview();
    refresh.disabled = reviewChecking || !actionable(e);
  }
  if ($('decisionReview'))
    $('decisionReview').textContent = reviewChecking
      ? 'Checking remembered scope…'
      : reviewMessage ||
        (needsDecisionReview() && !decisionReviews.allow
          ? 'Choose scope, then refresh review.'
          : needsDecisionReview() &&
              Date.parse(decisionReviews.allow?.expires_at || '') <=
                (state.control.serverNow || Date.now())
            ? 'Review expired · refresh to decide.'
            : '');
  if ($('decisionReconcile')) {
    const reconcile = $<HTMLButtonElement>('decisionReconcile');
    reconcile.hidden = !e?.attempt?.reconcile;
    reconcile.disabled = !state.control.connected;
  }
  if ($('requestResult') && e)
    $('requestResult').textContent = !state.control.connected
      ? 'Disconnected · decisions unavailable. Request details retained; no retry sent.'
      : e.attempt?.phase === 'unknown' && e.state !== 'awaiting-decision'
        ? `Backend now reports ${e.state}. Original acknowledgement remains unknown; no retry sent. ${e.reason}`
        : e.attempt?.message || e.reason;
  if ($('permissionTarget'))
    $('permissionTarget').textContent = permissionTarget(
      chosenScope,
      e?.flow.protocol || '',
      needsDecisionReview() ? decisionZone : 'any',
    );
  if (
    $('permissionTarget') &&
    needsDecisionReview() &&
    reviewFor === reviewKey() &&
    decisionReviews.allow
  ) {
    const until = decisionReviews.allow.rule.expires;
    $('permissionTarget').textContent =
      `Application + peer/service · ${decisionZone === 'any' ? 'Any network' : zoneLabel(decisionZone)} · ${until.startsWith('0001-') ? 'persistent' : 'until ' + new Date(until).toLocaleTimeString()}`;
  }
  const expiry = document.querySelector('.expiry');
  if (expiry)
    expiry.textContent = e
      ? e.remainingMs > 0 && e.state === 'awaiting-decision'
        ? `${Math.ceil(e.remainingMs / 1000)} seconds remaining`
        : `Request ${e.state === 'awaiting-decision' ? 'expired' : e.state}`
      : '';
}
function consume(next: ClientState) {
  if (!acceptsPublication(state, next)) return;
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
    updateFirewallStatus();
    for (const th of document.querySelectorAll<HTMLElement>('.col-rule_status button'))
      th.title = state.control.capabilities?.includes(POLICY_CAPABILITY)
        ? 'Priority · DL Limit · UL Limit · In Blocker · Out Blocker · In Quota · Out Quota. Only Blocker is a FlowGate feature; backend policy summary.'
        : 'Compatibility inventory (listed rules; no backend summary).';
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
      state.control.rule_states,
      state.control.policy
        ? [
            state.control.policy.snapshot.token,
            state.control.policy.applications.map((a) => [a.ref, a.process_ids]),
            state.control.policy.rows,
            state.control.policy.processes,
          ]
        : state.control.policyError,
      (state.control.rules || []).map((r) => ruleState(r, state.control.serverNow ?? NaN)),
    ]);
    if (ruleSignature !== rulesStamp) {
      ruleSignature = rulesStamp;
      treePolicyRevision++;
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
  }
}
function consumePresentation(frame: PaneFrame) {
  if (promptID || (presentation && frame.presentation.revision < presentation.revision)) return;
  const old = presentation;
  presentation = frame.presentation;
  if (!$('activityView')) return;
  const p = presentation;
  const nextSelection =
    selectionPending && selectionPending !== p.selection ? selected : p.selection;
  const selectionChanged = selected !== nextSelection;
  selected = nextSelection;
  measurementSource = p.source;
  displayUnit = p.unit;
  $<HTMLSelectElement>('displayUnits').value = p.unit;
  $<HTMLSelectElement>('activitySource').value = p.source;
  for (const small of document.querySelectorAll('.rate-header small'))
    small.textContent = p.unit + ' (def)';
  graph?.setSource(p.source);
  graph?.setUnit(p.unit);
  graph?.setPresentation(p.chart);
  applyPanes();
  if (state && (selectionChanged || old?.source !== p.source || old?.unit !== p.unit)) {
    renderTree();
    renderInfo();
  }
}
if (!promptID) {
  window.flowgate.onPaneFrame(consumePresentation);
  void window.flowgate.paneSnapshot().then(consumePresentation);
  window.flowgate.onPaneRule((action) => {
    if (
      !state ||
      action.selection !== selected ||
      action.generation !== state.observation.generation
    ) {
      message('Selection changed; review the current Activity target.');
      return;
    }
    if (activityPolicy?.hasOutstandingAction()) {
      message('Resolve the current quick action before opening another rule action.');
      return;
    }
    if (resumeRuleEditor()) {
      message('Finish the existing editor before opening another rule action.');
      return;
    }
    if (($('confirmation') as HTMLDialogElement)?.open) {
      message('Finish the current confirmation first.');
      return;
    }
    const editor = $('ruleEditor');
    if (editor && !editor.hidden) {
      editor.querySelector<HTMLElement>('input,button')?.focus();
      message('Finish the open editor before opening another rule action.');
      return;
    }
    $('activityTab').click();
    if (action.kind === 'quick' && presentation?.panes.info !== 'docked') {
      showFloatingRuleStatus();
    }
    const focus =
      action.kind === 'quick'
        ? `cell:${action.tier}:${action.direction}`
        : action.kind === 'new'
          ? 'add-rule'
          : `list:${action.id}:${action.kind === 'edit' ? 'advanced' : 'delete'}`;
    const button = document.querySelector<HTMLButtonElement>(
      `#infoRules [data-focus="${CSS.escape(focus)}"]`,
    );
    if (!button || button.disabled) {
      message('Rule entry is unavailable for the current target.');
      return;
    }
    const details = button.closest('details');
    if (details) details.open = true;
    button.click();
  });
}
window.flowgate.subscribe(consume);
window.flowgate.onClock((clock) => {
  const next = advanceClock(state, clock);
  if (next && next !== state) consume(next);
});
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

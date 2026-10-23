import type { ClientState } from './protocol';
import type { DisplayUnit } from './display-units';
import type { UsageState } from './observed-usage-client';
import { formatUsage, USAGE_CAPABILITY, type UsageEntry } from './observed-usage';

const $ = (id: string) => document.getElementById(id)!;
const el = <K extends keyof HTMLElementTagNameMap>(tag: K, text = '', className = '') => {
  const node = document.createElement(tag);
  node.textContent = text;
  node.className = className;
  return node;
};
let visible = false;
let flight = false;
let revision = 0;
let context = '';
let current: UsageState | undefined;
let unit: DisplayUnit = 'autoByte';
let rendered = '';

export function setupObservedUsage(chooseTab: (tab: string) => void) {
  const tab = el('button', 'Observed usage');
  tab.id = 'observedUsageTab';
  tab.setAttribute('aria-selected', 'false');
  tab.onclick = () => chooseTab('usage');
  $('decisionLogTab').after(tab);
  const view = el('main');
  view.id = 'observedUsageView';
  view.hidden = true;
  view.innerHTML = `<section class="rules-main usage-main">
    <div class="filterbar"><input id="usageSearch" type="search" aria-label="Search observed usage" placeholder="Search recorded applications">
    <select id="usageSource" aria-label="Observed usage source"><option value="all">TCP and UDP (separate)</option><option value="tcp">TCP payload</option><option value="udp">UDP API bytes</option></select>
    <button id="usageRefresh">Refresh</button></div>
    <p id="usageStatus" class="summary" role="status" aria-live="polite"></p>
    <p class="usage-explanation">Accumulated observations, including entries whose sockets have closed. Kept in memory for this observation interval only. Short connections and final bytes can be missed. Ownership is sampled, not continuously proven. TCP payload includes retransmissions; UDP counts API-return bytes. Neither measures remote delivery.</p>
    <p id="usageCoverage" class="usage-coverage"></p>
    <div class="table-scroll"><table id="usageTable" aria-label="Accumulated observed usage"><thead><tr><th>Application</th><th>User ID</th><th>Source</th><th>Downloaded</th><th>Uploaded</th><th>Coverage</th></tr></thead><tbody id="usageRows"></tbody></table>
    <p id="usageEmpty" class="log-empty"></p></div>
  </section>`;
  $('decisionLogView').after(view);
  $('usageSearch').oninput = render;
  $('usageSource').onchange = render;
  $('usageRefresh').onclick = () => void poll();
  setInterval(() => { if (visible) void poll(); }, 2000);
}

export function showObservedUsage(show: boolean) {
  visible = show;
  if (!$('observedUsageView')) return;
  $('observedUsageView').hidden = !show;
  $('observedUsageTab').setAttribute('aria-selected', String(show));
  if (show) { render(); void poll(); }
}

export function updateObservedUsage(state: ClientState, displayUnit: DisplayUnit) {
  unit = displayUnit;
  const { control: c, observation: o } = state;
  const next = JSON.stringify([c.connected, c.generation, c.permissions, c.capabilities?.includes(USAGE_CAPABILITY),
    o.connected, o.generation, o.permissions, o.capabilities?.includes(USAGE_CAPABILITY)]);
  if (context !== next) {
    context = next;
    revision++;
    current = undefined;
    render();
    if (visible) void poll();
  } else if (visible) render();
}

async function poll() {
  if (!visible || flight) return;
  flight = true;
  const started = revision;
  try {
    const value = await window.flowgate.observedUsage();
    if (started === revision) current = value;
  } catch (error) {
    if (started === revision) current = { supported: true, message: String(error) };
  } finally {
    flight = false;
    render();
  }
}

function row(entry: UsageEntry): HTMLTableRowElement {
  const tr = el('tr');
  const app = el('td', entry.name || entry.executable || entry.application || 'Unattributed');
  app.title = [entry.executable, entry.application, entry.id].filter(Boolean).join('\n');
  tr.append(app, el('td', entry.uid === undefined ? '—' : String(entry.uid)),
    el('td', entry.source === 'tcp' ? 'TCP payload' : 'UDP API bytes'));
  for (const value of [entry.downloaded, entry.uploaded]) {
    const cell = el('td', formatUsage(value, unit), 'usage-amount');
    cell.title = `${value} observed bytes`;
    tr.append(cell);
  }
  tr.append(el('td', entry.coverage || 'Sampled ownership; incomplete coverage'));
  return tr;
}

function render() {
  if (!$('observedUsageView')) return;
  const source = ($('usageSource') as HTMLSelectElement).value;
  const search = ($('usageSearch') as HTMLInputElement).value.toLocaleLowerCase();
  const signature = JSON.stringify([current, unit, source, search]);
  if (signature === rendered) return;
  rendered = signature;
  const snapshot = current?.snapshot;
  const status = $('usageStatus');
  $('usageRows').replaceChildren();
  $('usageCoverage').textContent = '';
  if (!snapshot) {
    status.textContent = current?.message || 'Reading observed usage…';
    $('usageEmpty').textContent = current?.supported === false
      ? 'This daemon does not advertise accumulated observed usage. Live Activity remains available.'
      : 'No current accumulated observations available.';
    return;
  }
  status.textContent = `${snapshot.scope === 'machine' ? 'Machine' : 'Your applications'} · Observations since ${new Date(snapshot.startedAt).toLocaleString()} · ${snapshot.observedAt ? 'Sampled ' + new Date(snapshot.observedAt).toLocaleString() : 'Waiting for the first observation'}`;
  status.title = `Observation interval: ${snapshot.epoch}`;
  $('usageCoverage').textContent = snapshot.coverage;
  const entries = snapshot.entries.filter((entry) => (source === 'all' || source === entry.source) &&
    [entry.name, entry.executable, entry.application, entry.uid].join(' ').toLocaleLowerCase().includes(search));
  const fragment = document.createDocumentFragment();
  for (const entry of entries) fragment.append(row(entry));
  $('usageRows').append(fragment);
  $('usageEmpty').textContent = entries.length ? '' : snapshot.entries.length
    ? 'No recorded entries match these filters.'
    : 'No attributable usage recorded yet. Unavailable or missed observations are not zero usage.';
}

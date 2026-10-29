import { accountLabel } from './accounts';
import type { ClientState } from './protocol';
import type { DisplayUnit } from './display-units';
import type { HistoryState } from './usage-history-client';
import { HISTORY_CAPABILITY, type HistoryQuery, type HistorySnapshot } from './usage-history';
import { formatUsage } from './observed-usage';
const $ = (id: string) => document.getElementById(id)!;
let shown = false,
  flight = false,
  settingsDirty = false,
  draftRevision: string | undefined,
  revision = 0,
  context = '',
  current: HistoryState | undefined,
  unit: DisplayUnit = 'autoByte';
const element = (tag: string, text = '') => {
  const e = document.createElement(tag);
  e.textContent = text;
  return e;
};
export function setupUsageHistory(parent: HTMLElement) {
  const view = element('section');
  view.id = 'usageHistoryView';
  view.hidden = true;
  view.innerHTML = `<div class="filterbar history-filters"><select id="historyRange" aria-label="History range"><option value="1h">Last hour</option><option value="24h" selected>Last 24 hours</option><option value="7d">Last 7 days</option><option value="30d">Last 30 days</option></select><select id="historySource" aria-label="History source"><option value="tcp-transport-payload">TCP payload</option><option value="udp-api-reported">UDP API bytes</option></select><select id="historyApplication" aria-label="Recorded application"><option value="">All recorded applications</option></select><button id="historyRefresh">Refresh / check settings</button></div>
 <p id="historyStatus" role="status" class="summary"></p>
 <p class="usage-explanation">Durable sampled observations, separate from the live interval. Each bar shows observed checkpoint bytes, not current speed or delivered traffic. Missing buckets stay blank and are not zero activity. TCP includes upload retransmissions; UDP uses API-return bytes. Historical names never grant permission.</p>
 <p id="historyCoverage"></p><div id="historyChart" aria-label="Recorded checkpoint bytes" class="history-chart"></div><p id="historyTotals"></p>
 <details id="historySettings"><summary>History recording and retention</summary><p>Opt-in machine-wide storage includes application names, identities, user IDs and sampled totals in a private database. Disabled recording keeps existing history until retention expires. Shorter retention deletes older records. First checkpoint after enabling or restarting establishes a baseline; it does not backfill the prior interval.</p><div class="history-settings-controls"><label><input id="historyEnabled" type="checkbox"> Record observed usage</label><label>Keep <select id="historyRetention"><option value="1">1 day</option><option value="7">7 days</option><option value="30">30 days</option></select></label></div><p>Limits: 1,024 application/source identities, 128 recording intervals, 50,000 rows; 32 MiB database plus bounded rollback journal. Storage pressure pauses recording explicitly. Commits normally run every 30 seconds; crashes may lose uncommitted observations, with no fixed time-loss guarantee.</p><label><input id="historyConsent" type="checkbox"> I reviewed the machine-wide privacy and retention scope.</label><button id="historySave">Save history settings</button><p id="historyAuthority"></p></details>`;
  parent.append(view);
  for (const id of ['historyRange', 'historySource', 'historyApplication'])
    $(id).onchange = () => {
      if (id === 'historySource') ($('historyApplication') as HTMLSelectElement).value = '';
      revision++;
      current = undefined;
      render();
      void poll();
    };
  $('historyRefresh').onclick = () => void poll();
  for (const id of ['historyEnabled', 'historyRetention'])
    $(id).onchange = () => {
      if (!settingsDirty) draftRevision = current?.snapshot?.settings.revision;
      settingsDirty = true;
      ($('historyConsent') as HTMLInputElement).checked = false;
      configureControls();
    };
  $('historyConsent').onchange = configureControls;
  $('historySave').onclick = () => void save();
  setInterval(() => {
    if (shown) void poll();
  }, 10000);
}
if (typeof window !== 'undefined') window.addEventListener('flowgate-account-name', () => { if (shown) render(); });
export function showUsageHistory(value: boolean) {
  shown = value;
  $('usageHistoryView').hidden = !value;
  if (value) {
    render();
    void poll();
  }
}
export function updateUsageHistory(s: ClientState, displayUnit: DisplayUnit) {
  unit = displayUnit;
  const c = s.control,
    o = s.observation;
  const next = JSON.stringify([
    c.connected,
    c.generation,
    c.permissions,
    c.readOnly,
    c.capabilities?.includes(HISTORY_CAPABILITY),
    o.connected,
    o.generation,
    o.permissions,
    o.capabilities?.includes(HISTORY_CAPABILITY),
  ]);
  if (context !== next) {
    context = next;
    settingsDirty = false;
    draftRevision = undefined;
    revision++;
    current = undefined;
    ($('historyApplication') as HTMLSelectElement).replaceChildren(
      new Option('All recorded applications', ''),
    );
    ($('historyConsent') as HTMLInputElement).checked = false;
    render();
    if (shown) void poll();
  } else if (shown) render();
}
function query(): HistoryQuery {
  const selected = ($('historyApplication') as HTMLSelectElement).value;
  return {
    range: ($('historyRange') as HTMLSelectElement).value as HistoryQuery['range'],
    source: ($('historySource') as HTMLSelectElement).value as HistoryQuery['source'],
    ...(selected === 'unattributed'
      ? { unattributed: true }
      : selected
        ? { entry_id: selected }
        : {}),
  };
}
async function poll() {
  if (!shown || flight) return;
  flight = true;
  const start = revision;
  try {
    const result = await window.flowgate.usageHistory(query());
    if (start === revision) {
      if (current?.pending && !result.pending) {
        settingsDirty = false;
        draftRevision = undefined;
      }
      current = result;
    }
  } catch (e) {
    if (start === revision)
      current = { supported: true, message: String(e), canConfigure: false, pending: false };
  } finally {
    flight = false;
    render();
    if (start !== revision && shown) void poll();
  }
}
async function save() {
  if (
    !current?.canConfigure ||
    current.pending ||
    !($('historyConsent') as HTMLInputElement).checked ||
    !current.snapshot
  )
    return;
  const start = revision;
  const previous = current;
  current = { ...previous, canConfigure: false, message: 'Saving history settings…' };
  configureControls();
  try {
    const value = await window.flowgate.usageHistoryConfigure({
      enabled: ($('historyEnabled') as HTMLInputElement).checked,
      retention_days: Number(($('historyRetention') as HTMLSelectElement).value),
      expected_revision: draftRevision || previous.snapshot!.settings.revision,
    });
    if (start !== revision) return;
    current = { ...value, snapshot: previous.snapshot };
    if (!value.pending) {
      settingsDirty = false;
      draftRevision = undefined;
    }
    ($('historyConsent') as HTMLInputElement).checked = false;
    render();
    if (!value.pending) void poll();
  } catch (e) {
    if (start === revision) {
      current = {
        supported: true,
        message: 'Settings outcome unknown; refresh to check. No automatic retry.',
        pending: true,
        canConfigure: false,
        snapshot: previous.snapshot,
      };
      render();
    }
  }
}
function configureControls() {
  const allowed = !!current?.canConfigure && !current.pending;
  for (const id of ['historyEnabled', 'historyRetention', 'historyConsent'])
    ($(`${id}`) as HTMLInputElement).disabled = !allowed;
  ($('historySave') as HTMLButtonElement).disabled =
    !allowed || !($('historyConsent') as HTMLInputElement).checked;
  $('historyAuthority').textContent = current?.pending
    ? 'Settings outcome unknown. Use Refresh to check; saving is locked and will not be retried automatically.'
    : allowed
      ? 'Administrator on primary endpoint. These settings do not change traffic permissions.'
      : 'Settings require an authenticated administrator on the writable primary endpoint.';
}
function chart(s: HistorySnapshot) {
  const container = $('historyChart');
  container.replaceChildren();
  if (!s.points.length) {
    container.append(
      element(
        'p',
        'No recorded observations in this range. Blank history does not prove zero traffic.',
      ),
    );
    return;
  }
  const ns = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(ns, 'svg');
  svg.setAttribute('viewBox', '0 0 800 190');
  svg.setAttribute('role', 'img');
  svg.setAttribute(
    'aria-label',
    'Observed checkpoint bytes, blue download and orange upload; missing intervals are blank',
  );
  const maximum = s.points.reduce(
    (m, p) => [BigInt(p.uploaded), BigInt(p.downloaded)].reduce((a, b) => (a > b ? a : b), m),
    1n,
  );
  const start = Date.parse(s.from),
    span = Math.max(1, Date.parse(s.until) - start);
  const barWidth = Math.max(1, Math.min(12, (760 * s.resolution_seconds * 1000) / span / 2));
  for (const p of s.points) {
    const x = 20 + Math.max(0, (Date.parse(p.at) - start) / span) * 760;
    for (const [index, counter] of [p.downloaded, p.uploaded].entries()) {
      const height = Number((BigInt(counter) * 14000n) / maximum) / 100;
      const bar = document.createElementNS(ns, 'rect');
      bar.setAttribute('x', String(Math.min(790 - barWidth, x + index * barWidth)));
      bar.setAttribute('y', String(155 - height));
      bar.setAttribute('width', String(barWidth));
      bar.setAttribute('height', String(Math.max(height, counter === '0' ? 0 : 1)));
      bar.setAttribute('fill', index ? '#e5a854' : '#56b9e5');
      const title = document.createElementNS(ns, 'title');
      title.textContent = `${new Date(p.at).toLocaleString()} · ${index ? 'Uploaded' : 'Downloaded'} ${counter} observed bytes · ${p.observed_buckets} five-minute buckets with observations · ${p.epoch_count} recording intervals · partial${p.flags & 1 ? ' · source unavailable at checkpoint' : ''}${p.flags & 2 ? ' · live ledger capacity limited' : ''}${p.flags & 4 ? ' · saturated' : ''}`;
      bar.append(title);
      svg.append(bar);
    }
  }
  const label = document.createElementNS(ns, 'text');
  label.setAttribute('x', '20');
  label.setAttribute('y', '180');
  label.setAttribute('fill', 'currentColor');
  label.textContent = `Scale ${formatUsage(maximum.toString(), unit)} · download (blue) / upload (orange) · ${s.resolution_seconds / 60}-minute bins`;
  svg.append(label);
  container.append(svg);
}
function render() {
  if (!$('usageHistoryView')) return;
  const s = current?.snapshot;
  $('historyStatus').textContent =
    current?.message ||
    (!s
      ? 'Reading history…'
      : `${s.scope === 'machine' ? 'Machine' : 'Your applications'} · ${s.state} · ${new Date(s.from).toLocaleString()} – ${new Date(s.until).toLocaleString()}`);
  if (!s) {
    $('historyChart').replaceChildren();
    $('historyTotals').textContent = '';
    $('historyCoverage').textContent = '';
    configureControls();
    return;
  }
  const select = $('historyApplication') as HTMLSelectElement,
    selected = select.value;
  const options = [
    ['', 'All recorded applications'],
    ...(s.scope === 'machine' ? [['unattributed', 'Unattributed / shared observations']] : []),
    ...s.entries.map((e) => [e.id, `${e.name || e.key} · ${accountLabel(e.uid)}`]),
  ];
  select.replaceChildren(
    ...options.map(([value, label]) => {
      const o = document.createElement('option');
      o.value = value;
      o.textContent = label;
      return o;
    }),
  );
  select.value = options.some(([v]) => v === selected) ? selected : '';
  if (selected && select.value !== selected) {
    revision++;
    current = undefined;
    void poll();
    return;
  }
  // Settings are refreshed only from this principal's authoritative snapshot.
  if (!current?.pending && !settingsDirty) {
    ($('historyEnabled') as HTMLInputElement).checked = s.settings.enabled;
    ($('historyRetention') as HTMLSelectElement).value = String(s.settings.retention_days);
  }
  $('historyCoverage').textContent =
    `All history is partial. ${s.resolution_seconds / 60}-minute bins; recording intervals are retained independently (${s.epochs.length} in this graph). Missing samples, short connections and closure tails remain unmeasured.${s.last_commit_at ? ' Last committed ' + new Date(s.last_commit_at).toLocaleString() + '.' : ''}${s.error ? ' Storage diagnostic: ' + s.error : ''}`;
  let up = 0n,
    down = 0n;
  for (const p of s.points) {
    up += BigInt(p.uploaded);
    down += BigInt(p.downloaded);
  }
  $('historyTotals').textContent =
    `${s.points.some((p) => p.flags & 4) ? 'Saturated observations: at least ' : 'Range observations: '} downloaded ${historyTotal(down)} · uploaded ${historyTotal(up)}. ${s.source === 'tcp-transport-payload' ? 'TCP payload only.' : 'UDP API-return bytes only.'}`;
  chart(s);
  configureControls();
}

function historyTotal(value: bigint) {
  return value <= 18446744073709551615n
    ? formatUsage(value.toString(), unit)
    : value.toString() + ' B (exact range sum)';
}

import {
  LOG_SOURCES,
  directionLabel,
  healthSummary,
  outcomeLabel,
  reasonSummary,
  scopeLabel,
  sourceLabel,
  verdictLabel,
  type LogFilter,
  type LogRecord,
} from './decision-log';
import type { DecisionLogState } from './decision-log-client';
import type { Application, ClientState } from './protocol';
import { canManageRules } from './protocol';
// Decision Log tab: presents backend-recorded decision-time evidence only.
const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;
const el = <K extends keyof HTMLElementTagNameMap>(tag: K, text = '', cls = '') => {
  const n = document.createElement(tag);
  n.textContent = text;
  if (cls) n.className = cls;
  return n;
};
let current: DecisionLogState | undefined;
let client: ClientState | undefined;
let selected = '';
let visible = false;
let signature = '';
let detailFor = '';
let newAbove = 0;
let polling = false;
let iconFor: (app: Application) => HTMLElement = () => el('span');
let openCurrentRule: (id: string) => void = () => {};
const RANGES: [string, string, number][] = [
  ['any', 'Any time', 0],
  ['15m', 'Last 15 minutes', 15 * 60e3],
  ['1h', 'Last hour', 3600e3],
  ['24h', 'Last 24 hours', 86400e3],
  ['7d', 'Last 7 days', 7 * 86400e3],
];
let application: LogFilter['application'];

export function setupDecisionLog(
  chooseTab: (tab: string) => void,
  icon: (app: Application) => HTMLElement,
  viewRule: (id: string) => void,
) {
  iconFor = icon;
  openCurrentRule = viewRule;
  const tab = el('button', 'Decision log');
  tab.id = 'decisionLogTab';
  tab.setAttribute('aria-selected', 'false');
  tab.onclick = () => chooseTab('log');
  $('rulesTab').after(tab);
  const view = el('main');
  view.id = 'decisionLogView';
  view.hidden = true;
  const option = (v: string, t: string) => `<option value="${v}">${t}</option>`;
  view.innerHTML = `<section class="rules-main log-main"><div class="filterbar">
<select id="logRange" aria-label="Time range">${RANGES.map(([v, t]) => option(v, t)).join('')}</select>
<select id="logDirection" aria-label="Direction">${option('', 'Any direction')}${option('incoming', 'Incoming')}${option('outgoing', 'Outgoing')}</select>
<select id="logAction" aria-label="Outcome">${option('', 'Any outcome')}${option('allow', 'Allowed')}${option('block', 'Blocked')}${option('pending', 'Awaiting decision')}</select>
<select id="logSource" aria-label="Decision source">${option('', 'Any source')}${LOG_SOURCES.map((s) => option(s, sourceLabel(s))).join('')}</select>
<button id="logApplication" hidden title="Remove application filter"></button>
<span class="log-spacer"></span>
<button id="logNew" hidden></button>
<button id="logLive" aria-pressed="true"></button>
</div><div class="table-scroll" id="logScroll"><table id="logTable" tabindex="0" aria-label="Firewall decision log"><thead><tr><th>Time</th><th>Application</th><th>Direction</th><th>Protocol</th><th>Local endpoint</th><th>Remote endpoint</th><th>Decision</th><th>Reason / source</th></tr></thead><tbody id="logRows"></tbody></table><p id="logEmpty" class="log-empty" hidden></p><div class="log-more"><button id="logOlder">Load older</button></div></div>
<div id="logStatus" class="summary"></div></section><aside><h2>Decision details</h2><div id="logDetails" class="log-details"><p class="hint">Select a record.</p></div></aside>`;
  $('rulesView').after(view);
  const change = () => void applyFilter();
  for (const id of ['logRange', 'logDirection', 'logAction', 'logSource']) $(id).onchange = change;
  $('logApplication').onclick = () => {
    application = undefined;
    change();
  };
  $('logLive').onclick = async () => {
    current = await window.flowgate.decisionLogLive(!current?.live);
    render();
  };
  $('logNew').onclick = async () => {
    newAbove = 0;
    $('logScroll').scrollTop = 0;
    if (!current?.live) current = await window.flowgate.decisionLogLive(true);
    render();
  };
  $('logOlder').onclick = async () => {
    current = await window.flowgate.decisionLogOlder();
    render();
  };
  $('logScroll').onscroll = () => {
    if ($('logScroll').scrollTop === 0 && newAbove) {
      newAbove = 0;
      render(true);
    }
  };
  $('logRows').onclick = (e) => {
    const tr = (e.target as HTMLElement).closest('tr');
    if (tr?.dataset.id) select(tr.dataset.id);
  };
  $('logTable').onkeydown = (e) => {
    if (!['ArrowDown', 'ArrowUp'].includes(e.key) || !current?.records.length) return;
    e.preventDefault();
    const i = current.records.findIndex((r) => r.id === selected);
    const next =
      current.records[
        Math.max(0, Math.min(current.records.length - 1, i + (e.key === 'ArrowDown' ? 1 : -1)))
      ];
    select(next.id);
    document
      .querySelector(`#logRows tr[data-id="${CSS.escape(next.id)}"]`)
      ?.scrollIntoView({ block: 'nearest' });
  };
  setInterval(() => void poll(), 1000);
}

function filter(): LogFilter {
  const f: LogFilter = {};
  const range = RANGES.find(([v]) => v === $<HTMLSelectElement>('logRange').value);
  if (range?.[2]) f.since = new Date(Date.now() - range[2]).toISOString();
  const d = $<HTMLSelectElement>('logDirection').value,
    a = $<HTMLSelectElement>('logAction').value,
    s = $<HTMLSelectElement>('logSource').value;
  if (d) f.direction = d as LogFilter['direction'];
  if (a) f.action = a as LogFilter['action'];
  if (s) f.source = s;
  if (application) f.application = application;
  return f;
}
async function applyFilter() {
  selected = '';
  detailFor = '';
  newAbove = 0;
  $('logDetails').replaceChildren(el('p', 'Select a record.', 'hint'));
  current = await window.flowgate.decisionLogFilter(filter());
  render();
}
export async function showDecisionLog(show: boolean) {
  if (visible === show) return;
  visible = show;
  await window.flowgate.decisionLogVisible(show);
  if (show) await poll();
}
export function updateDecisionLog(state: ClientState) {
  client = state;
  if (visible && detailFor) renderRuleComparison();
}
async function poll() {
  if (!visible || polling) return;
  polling = true;
  try {
    current = await window.flowgate.decisionLog();
    render();
  } finally {
    polling = false;
  }
}

const time = (iso: string) => {
  const d = new Date(iso);
  if (!Number.isFinite(d.getTime())) return iso || '—';
  const today = new Date().toDateString() === d.toDateString();
  return d.toLocaleString('en-GB', {
    ...(today ? {} : { day: '2-digit', month: 'short' }),
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
};
const protocolLabel = (r: LogRecord) =>
  r.flow
    ? `${r.flow.protocol.toUpperCase()}${r.flow.family === 'ipv6' ? '6' : r.flow.family === 'ipv4' ? '4' : ''}`
    : '—';
const appName = (r: LogRecord) =>
  r.application?.name || r.application?.executable.split('/').pop() || 'Unidentified';

function row(r: LogRecord) {
  const tr = el('tr');
  tr.dataset.id = r.id;
  tr.setAttribute('aria-selected', String(r.id === selected));
  const t = el('td', time(r.time));
  t.title = r.time;
  if (r.kind === 'gap') {
    tr.className = 'log-gap';
    const cell = el(
      'td',
      `Records lost${r.gap?.dropped ? ': ' + r.gap.dropped : ''} — ${r.gap?.reason || 'not recorded'}. History in this interval is incomplete.`,
    );
    cell.colSpan = 7;
    tr.append(t, cell);
    return tr;
  }
  const name = el('td');
  if (r.application?.key)
    name.append(
      iconFor({
        key: r.application.key,
        revision: r.application.revision,
        name: r.application.name,
        executable: r.application.executable,
      }),
    );
  name.append(document.createTextNode(appName(r)));
  name.title =
    r.application?.executable || r.attribution?.reason || 'No application attribution recorded';
  const outcome = el(
    'td',
    outcomeLabel(r),
    'log-outcome ' + (r.kind === 'pending' ? 'pending' : r.decision?.action || ''),
  );
  const reason = el('td', reasonSummary(r));
  reason.title = r.decision?.reason || '';
  tr.append(
    t,
    name,
    el('td', directionLabel(r.flow?.direction)),
    el('td', protocolLabel(r)),
    el('td', r.flow?.local || '—'),
    el('td', r.flow?.remote || '—'),
    outcome,
    reason,
  );
  return tr;
}

function emptyText(s: DecisionLogState) {
  if (!s.connected) return 'Disconnected from the daemon. No records can be retrieved.';
  if (!s.supported)
    return 'This daemon does not provide a decision log (decision-log-v1 not advertised).';
  if (s.status === 'error')
    return s.error?.code === 'forbidden'
      ? 'Permission denied: this connection may not read the decision log.'
      : `Decision log unavailable: ${s.error?.message || s.error?.code}`;
  if (s.status === 'loading' || s.status === 'idle') return 'Loading decision log…';
  if (s.status === 'disconnected') return 'Connection lost. No records can be retrieved.';
  if (s.filtered) return 'No stored records match these filters.';
  const idle =
    s.enforcement && s.enforcement !== 'active'
      ? ' Firewall enforcement is not active, so FlowGate is not deciding connections. Traffic monitoring does not create decision records.'
      : '';
  return 'No firewall decisions recorded yet.' + idle;
}

function render(force = false) {
  const s = current;
  if (!s) return;
  const live = $('logLive');
  live.textContent = s.live ? '● Live' : '❚❚ Paused';
  live.setAttribute('aria-pressed', String(s.live));
  live.title = s.live
    ? 'Following new records. Click to pause.'
    : 'Paused: the list does not change. Click to follow new records.';
  const appButton = $('logApplication');
  appButton.hidden = !application;
  appButton.textContent = application
    ? `Application: ${application.name || application.key} ✕`
    : '';
  const sig = JSON.stringify([
    s.session,
    s.status,
    s.records.length,
    s.records[0]?.id,
    s.records.at(-1)?.id,
    selected,
  ]);
  const scroll = $('logScroll');
  if (sig !== signature || force) {
    // Keep the inspected position: compensate for rows inserted above.
    const before = scroll.scrollHeight,
      top = scroll.scrollTop,
      firstBefore = signature ? $('logRows').firstElementChild?.getAttribute('data-id') : '';
    const rows = $('logRows');
    rows.replaceChildren(...s.records.map(row));
    if (top > 0 && firstBefore && s.records[0]?.id !== firstBefore) {
      const index = s.records.findIndex((r) => r.id === firstBefore);
      if (index > 0) newAbove += index;
      scroll.scrollTop = top + (scroll.scrollHeight - before);
    }
    signature = sig;
  }
  const empty = $('logEmpty');
  empty.hidden = s.records.length > 0 && s.status !== 'error';
  empty.textContent = emptyText(s);
  const older = $<HTMLButtonElement>('logOlder');
  older.hidden = !s.hasOlder && !s.retainedLimit;
  older.disabled = s.busy || s.retainedLimit;
  older.textContent = s.retainedLimit
    ? `Showing the newest ${s.records.length} matching records; narrow the filters to see older ones`
    : 'Load older';
  const indicator = $('logNew');
  indicator.hidden = !(newAbove > 0 || (!s.live && s.newAvailable));
  indicator.textContent = newAbove > 0 ? `↑ ${newAbove} new` : 'New records — show';
  const health = healthSummary(s.health);
  const status = $('logStatus');
  status.className = 'summary log-health ' + health.level;
  const scope =
    s.scope === 'self' ? 'Your decisions only' : s.scope === 'machine' ? 'All users' : '';
  status.textContent = [
    s.supported ? health.text : '',
    scope,
    `${s.records.length} loaded`,
    s.status === 'disconnected' ? 'disconnected — loaded records shown' : '',
    s.notice,
    ...s.limitations,
    'Firewall decisions only; not a complete connection history',
  ]
    .filter(Boolean)
    .join(' · ');
  status.title = status.textContent;
}

function select(id: string) {
  selected = id;
  for (const tr of document.querySelectorAll<HTMLElement>('#logRows tr'))
    tr.setAttribute('aria-selected', String(tr.dataset.id === id));
  signature = '';
  void showDetail(id);
}

const field = (dl: HTMLElement, label: string, value: string | number | null | undefined) => {
  if (value === undefined || value === null || value === '') return;
  dl.append(el('dt', label), el('dd', String(value)));
};
async function showDetail(id: string) {
  detailFor = id;
  const { record: r, note } = await window.flowgate.decisionLogDetail(id);
  if (detailFor !== id) return;
  const box = $('logDetails');
  if (!r) {
    box.replaceChildren(el('p', note || 'Record unavailable.', 'hint'));
    return;
  }
  const parts: HTMLElement[] = [el('h3', `${outcomeLabel(r)} · ${time(r.time)}`)];
  if (note) parts.push(el('p', note, 'hint'));
  const section = (title: string) => {
    parts.push(el('h4', title));
    const dl = el('dl');
    parts.push(dl);
    return dl;
  };
  if (r.kind === 'gap') {
    const g = section('Lost records');
    field(g, 'Dropped', r.gap?.dropped);
    field(g, 'Reason', r.gap?.reason);
    parts.push(
      el('p', 'Decisions in this interval were not stored; history is incomplete.', 'hint'),
    );
  } else {
    const d = section('Decision (recorded at decision time)');
    field(d, 'Outcome', outcomeLabel(r));
    field(d, 'Source', r.decision ? sourceLabel(r.decision.source) : 'Not decided yet');
    field(d, 'Scope', scopeLabel(r.decision?.scope));
    field(d, 'Reason', r.decision?.reason);
    field(d, 'Decided by UID', r.decision?.decided_by_uid);
    field(
      d,
      'Record type',
      r.kind === 'pending' ? 'Request awaiting an answer' : 'Final disposition',
    );
    if (r.kind === 'pending')
      parts.push(
        el(
          'p',
          'A later record with the same request ID holds the outcome, if one was recorded.',
          'hint',
        ),
      );
    const v = section('Kernel verdict');
    field(v, 'Verdict', verdictLabel(r.verdict?.state));
    field(v, 'Detail', r.verdict?.detail);
    field(v, 'Delivery', 'Not observed by FlowGate');
    const c = section('Connection');
    field(c, 'Direction', directionLabel(r.flow?.direction));
    field(c, 'Protocol', `${r.flow?.protocol.toUpperCase() || '—'} · ${r.flow?.family || ''}`);
    field(c, 'Local', r.flow?.local);
    field(c, 'Remote', r.flow?.remote);
    field(c, 'Interface index', r.flow?.interface_index);
    const a = section('Application at decision time');
    field(a, 'Name', r.application?.name || 'Unidentified');
    field(a, 'Executable', r.application?.executable);
    field(a, 'Revision', r.application?.revision);
    field(
      a,
      'Attribution',
      [r.attribution?.status, r.attribution?.reason].filter(Boolean).join(' · '),
    );
    field(a, 'Principal UID', r.principal_uid);
    parts.push(
      el('p', 'Recorded identity; not matched against currently running processes.', 'hint'),
    );
    const rule = r.decision?.rule;
    if (rule) {
      const s = section('Rule at decision time');
      field(s, 'Rule ID', rule.id);
      field(s, 'Version', rule.version);
      field(s, 'Action', rule.action);
      field(s, 'Priority', rule.priority);
      field(s, 'Expires', rule.expires || 'Never');
      field(s, 'Disabled', rule.disabled ? 'Yes' : '');
      const pre = el('pre', JSON.stringify(rule.filter, null, 1));
      pre.className = 'log-filter';
      parts.push(pre);
      const compare = el('div');
      compare.id = 'logRuleCompare';
      parts.push(compare);
    }
    if (r.decision?.matching_rules.length) {
      const m = section('Matching rules');
      field(m, 'IDs', r.decision.matching_rules.join(', '));
    }
  }
  const meta = section('Record');
  field(meta, 'Sequence', r.sequence);
  field(meta, 'Record ID', r.id);
  field(meta, 'Request ID', r.request_id);
  field(meta, 'Daemon generation', r.generation);
  field(meta, 'Mode', r.mode);
  const actions = el('div', '', 'log-actions');
  const copy = el('button', 'Copy record');
  copy.onclick = async () => {
    await window.flowgate.decisionLogCopy(r.id);
    copy.textContent = 'Copied';
    setTimeout(() => (copy.textContent = 'Copy record'), 1500);
  };
  actions.append(copy);
  if (r.application?.key) {
    const only = el('button', 'Only this application');
    only.onclick = () => {
      application = { key: r.application!.key, name: appName(r) };
      void applyFilter();
    };
    actions.append(only);
  }
  parts.push(actions);
  box.replaceChildren(...parts);
  renderRuleComparison(r);
}

// Current rule state is shown separately from the decision-time snapshot.
function renderRuleComparison(record?: LogRecord) {
  const box = $('logRuleCompare');
  if (!box) return;
  const r = record || current?.records.find((x) => x.id === detailFor);
  const snapshot = r?.decision?.rule;
  if (!snapshot) return;
  const c = client?.control;
  if (!c?.connected || !c.rules) {
    box.replaceChildren(el('p', 'Current rules are unavailable on this connection.', 'hint'));
    return;
  }
  const now = c.rules.find((x) => x.id === snapshot.id);
  if (!now) {
    box.replaceChildren(el('p', 'This rule no longer exists (deleted or expired since).', 'hint'));
    return;
  }
  const same = String(now.version) === snapshot.version;
  const text = el(
    'p',
    same
      ? `The current rule is still version ${now.version}.`
      : `The rule has changed since: current version ${now.version}. The snapshot above is what was evaluated.`,
    'hint',
  );
  const view = el('button', 'View current rule…');
  view.disabled = !canManageRules(c);
  view.title = view.disabled ? 'Rule management is read-only on this connection' : '';
  view.onclick = () => openCurrentRule(now.id);
  box.replaceChildren(text, view);
}

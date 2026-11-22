import { accountLabel } from './accounts';
import { ENDPOINT_SCOPE, ENDPOINT_PRECEDENCE } from './endpoint-policy';
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
import { attributionReasonLabel } from './attribution-reason';
// Decision Log tab: presents backend-recorded decision-time evidence only.
const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;
const el = <K extends keyof HTMLElementTagNameMap>(tag: K, text = '', cls = '') => {
  const n = document.createElement(tag);
  n.textContent = text;
  if (cls) n.className = cls;
  return n;
};
let current: DecisionLogState | undefined;
let accessRevision = 0;
let client: ClientState | undefined;
let selected = '';
let visible = false;
let signature = '';
let detailVersion = 0;
let shownDetail: { record: LogRecord; note: string; outcomeOf?: string } | undefined;
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
<span id="logOutcomeAction"></span>
<select id="logRange" aria-label="Time range">${RANGES.map(([v, t]) => option(v, t)).join('')}</select>
<select id="logDirection" aria-label="Direction">${option('', 'Any direction')}${option('incoming', 'Incoming')}${option('outgoing', 'Outgoing')}</select>
<select id="logAction" aria-label="Outcome">${option('', 'Any outcome')}${option('allow', 'Allowed')}${option('block', 'Blocked')}${option('pending', 'Pending records')}</select>
<select id="logSource" aria-label="Decision source">${option('', 'Any source')}${LOG_SOURCES.map((s) => option(s, sourceLabel(s))).join('')}</select>
<button id="logApplication" hidden title="Remove application filter"></button>
<button id="logClear" hidden>Clear filters</button>
<span class="log-spacer"></span>
<button id="logLatest">Jump to latest</button>
<button id="logNew" hidden></button>
<button id="logLive" aria-pressed="true"></button>
</div><div class="table-scroll" id="logScroll"><table id="logTable" tabindex="0" aria-label="Firewall decision log"><thead><tr><th>Time</th><th>Application</th><th>Decision</th><th>Source</th><th>Direction</th><th>Protocol</th><th>Local endpoint</th><th>Remote endpoint</th></tr></thead><tbody id="logRows"></tbody></table><p id="logEmpty" class="log-empty" hidden></p><div class="log-more"><button id="logOlder">Load older</button></div></div>
<div id="logStatus" class="summary"></div></section><aside><h2>Decision details</h2><div id="logDetails" class="log-details" tabindex="0" aria-label="Decision details"><p class="hint">Select a record.</p></div></aside>`;
  $('rulesView').after(view);
  const change = () => void applyFilter();
  for (const id of ['logRange', 'logDirection', 'logAction', 'logSource']) $(id).onchange = change;
  $('logApplication').onclick = () => {
    application = undefined;
    change();
  };
  $('logClear').onclick = () => {
    application = undefined;
    for (const id of ['logDirection', 'logAction', 'logSource'])
      $<HTMLSelectElement>(id).value = '';
    $<HTMLSelectElement>('logRange').value = 'any';
    change();
  };
  $('logLive').onclick = async () => {
    acceptState(await window.flowgate.decisionLogLive(!current?.live));
  };
  const latest = async () => {
    if (!current) return;
    // Explicit user navigation: reuse the same server filter and newest-page operation.
    // Preserve Live/Paused rather than silently resuming follow.
    if (!acceptState(await window.flowgate.decisionLogFilter(current.filter))) return;
    newAbove = 0;
    render();
    $('logScroll').scrollTop = 0;
    render();
  };
  $('logLatest').onclick = () => void latest();
  $('logNew').onclick = () => void latest();
  $('logOlder').onclick = async () => {
    acceptState(await window.flowgate.decisionLogOlder());
  };
  $('logScroll').onscroll = () => {
    if ($('logScroll').scrollTop === 0 && newAbove) {
      newAbove = 0;
      render();
    }
  };
  $('logRows').onclick = (e) => {
    const tr = (e.target as HTMLElement).closest('tr');
    if (tr?.dataset.id) {
      select(tr.dataset.id);
      $('logTable').focus({ preventScroll: true });
    }
  };
  $('logDetails').onkeydown = (e) => {
    if (e.key === 'Escape') $('logTable').focus({ preventScroll: true });
  };
  $('logTable').onkeydown = (e) => {
    if (e.key === 'Enter' && selected) {
      e.preventDefault();
      $('logDetails').focus({ preventScroll: true });
      return;
    }
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
  window.flowgate.onDecisionLogAccessReset((revision) => {
    clearAccess(revision);
    void poll();
  });
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
function clearSelection() {
  selected = '';
  detailVersion++;
  shownDetail = undefined;
  $('logTable').removeAttribute('aria-activedescendant');
  $('logOutcomeAction').replaceChildren();
  $('logDetails').replaceChildren(el('p', 'Select a record.', 'hint'));
  for (const row of $('logRows').children) row.setAttribute('aria-selected', 'false');
}
function clearAccess(revision: number) {
  if (revision <= accessRevision) return;
  accessRevision = revision;
  current = undefined;
  application = undefined;
  signature = '';
  newAbove = 0;
  clearSelection();
  $('logRows').replaceChildren();
  $('logScroll').scrollTop = 0;
  for (const id of ['logOlder', 'logNew', 'logApplication', 'logClear', 'logEmpty'])
    $(id).hidden = true;
  $('logApplication').textContent = $('logApplication').title = '';
  $('logStatus').textContent = $('logStatus').title = '';
  for (const id of ['logDirection', 'logAction', 'logSource'])
    $<HTMLSelectElement>(id).value = '';
  $<HTMLSelectElement>('logRange').value = 'any';
}
function acceptState(next: DecisionLogState) {
  if (next.accessRevision < accessRevision || (current && next.session < current.session)) return false;
  clearAccess(next.accessRevision);
  if (current && next.session !== current.session) {
    clearSelection();
    newAbove = 0;
  }
  current = next;
  render();
  return true;
}
async function applyFilter() {
  clearSelection();
  newAbove = 0;
  if (acceptState(await window.flowgate.decisionLogFilter(filter())))
    $('logScroll').scrollTop = 0;
}
if (typeof window !== 'undefined') {
  window.addEventListener('flowgate-account-name', () => {
    if (visible && shownDetail) {
      renderDetail(shownDetail.record, shownDetail.note, shownDetail.outcomeOf);
    }
  });
}
export async function showDecisionLog(show: boolean) {
  if (visible === show) return;
  visible = show;
  await window.flowgate.decisionLogVisible(show);
  if (show) await poll();
}
export function updateDecisionLog(state: ClientState) {
  client = state;
  if (visible && shownDetail) renderRuleComparison(shownDetail.record);
}
async function poll() {
  if (!visible || polling) return;
  polling = true;
  try {
    const previous = current;
    const next = await window.flowgate.decisionLog();
    if (!acceptState(next)) return;
    if (shownDetail?.record.kind === 'pending' &&
        (previous?.supported !== next.supported || previous?.outcomeLookup !== next.outcomeLookup)) {
      renderDetail(shownDetail.record, shownDetail.note);
    }
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
  tr.id = 'log-record-' + r.id;
  tr.setAttribute('aria-selected', String(r.id === selected));
  const t = el('td', time(r.time));
  t.title = r.time;
  if (r.kind === 'gap') {
    tr.className = 'log-gap';
    const dropped = r.gap?.dropped;
    const cell = el(
      'td',
      `Records lost · ${dropped === undefined ? 'Count withheld' : `${dropped} dropped`} — ${r.gap?.reason || 'not recorded'}. History in this interval is incomplete.`,
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
  const reason = el('td', sourceLabel(r.decision?.source || ''));
  reason.title = r.decision ? reasonSummary(r) : '';
  const endpoint = (value: string | undefined) => {
    const cell = el('td', value || '—');
    cell.title = value || '';
    return cell;
  };
  tr.append(
    t,
    name,
    outcome,
    reason,
    el('td', directionLabel(r.flow?.direction)),
    el('td', protocolLabel(r)),
    endpoint(r.flow?.local),
    endpoint(r.flow?.remote),
  );
  return tr;
}

function emptyText(s: DecisionLogState) {
  if (s.activityPreview)
    return 'Connect to an installed FlowGate daemon to view recorded decisions.';
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

function render() {
  const s = current;
  if (!s) return;
  const live = $('logLive');
  live.textContent = (s.live ? '● Live' : '❚❚ Paused') + (s.filtered ? ' · filtered' : '');
  $('logClear').hidden = !s.filtered;
  $<HTMLButtonElement>('logLatest').disabled = !s.connected || !s.supported || s.busy;
  live.setAttribute('aria-pressed', String(s.live));
  live.title = s.live
    ? 'Pause new records'
    : 'Follow new records';
  const appButton = $('logApplication');
  appButton.hidden = !application;
  appButton.textContent = application
    ? `Application: ${application.name || application.key} ✕`
    : '';
  appButton.title = application
    ? `Remove application filter: ${application.name || application.key}`
    : '';
  const sig = JSON.stringify([s.session, s.records.map((r) => r.id)]);
  const scroll = $('logScroll');
  if (sig !== signature) {
    // Anchor the first visible row, not total height: a bounded page can insert
    // above and evict below without changing its height. Disable browser anchoring.
    const top = scroll.scrollTop;
    const firstBefore = $('logRows').firstElementChild?.getAttribute('data-id');
    const edge =
      scroll.getBoundingClientRect().top +
      $('logTable').querySelector('thead')!.getBoundingClientRect().height;
    const anchor = Array.from($('logRows').children).find(
      (r) => r.getBoundingClientRect().bottom > edge,
    ) as HTMLElement | undefined;
    const anchorId = anchor?.dataset.id;
    const anchorTop = anchor?.getBoundingClientRect().top;
    $('logRows').replaceChildren(...s.records.map(row));
    if (top > 0 && anchorId && anchorTop !== undefined) {
      const replacement = document.getElementById('log-record-' + anchorId);
      if (replacement) scroll.scrollTop = top + replacement.getBoundingClientRect().top - anchorTop;
      if (firstBefore) {
        const index = s.records.findIndex((r) => r.id === firstBefore);
        if (index > 0) newAbove += index;
      }
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
  indicator.textContent = newAbove > 0 ? `↑ ${newAbove} new — latest` : 'New records — latest';
  const health = healthSummary(s.health);
  const status = $('logStatus');
  status.className = 'summary log-health ' + health.level;
  const scope =
    s.scope === 'self' ? 'Your decisions only' : s.scope === 'machine' ? 'All users' : '';
  status.textContent = [
    s.supported ? health.text : '',
    scope,
    `${s.records.length} loaded`,
    !s.connected || s.status === 'disconnected'
      ? 'Disconnected — loaded history; reconnect using Control'
      : '',
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
  $('logTable').setAttribute('aria-activedescendant', 'log-record-' + id);
  void showDetail(id);
}

const field = (dl: HTMLElement, label: string, value: string | number | null | undefined, title?: string) => {
  if (value === undefined || value === null || value === '') return;
  const detail = el('dd', String(value));
  if (title) detail.title = title;
  dl.append(el('dt', label), detail);
};
async function showDetail(id: string, outcome = false) {
  const version = ++detailVersion;
  shownDetail = undefined;
  const box = $('logDetails');
  const action = $('logOutcomeAction');
  action.replaceChildren();
  box.replaceChildren(el('p', outcome ? 'Looking up recorded outcome…' : 'Loading record…', 'hint'));
  const { record, note } = outcome
    ? await window.flowgate.decisionLogOutcome(id)
    : await window.flowgate.decisionLogDetail(id);
  if (version !== detailVersion) return;
  if (!record) {
    box.replaceChildren(el('p', note || 'Record unavailable.', 'hint'));
    if (outcome) action.append(backToPending(id));
    return;
  }
  const outcomeOf = outcome ? id : undefined;
  shownDetail = { record, note, outcomeOf };
  renderDetail(record, note, outcomeOf);
}

function backToPending(id: string) {
  const back = el('button', 'Back to pending record');
  back.onclick = () => select(id);
  return back;
}

function renderDetail(r: LogRecord, note: string, outcomeOf?: string) {
  const box = $('logDetails');
  const action = $('logOutcomeAction');
  action.replaceChildren();
  const parts: HTMLElement[] = [el('h3', `${outcomeLabel(r)} · ${time(r.time)}`)];
  if (outcomeOf) action.append(backToPending(outcomeOf));
  if (note) parts.push(el('p', note, 'hint'));
  const section = (title: string) => {
    parts.push(el('h4', title));
    const dl = el('dl');
    parts.push(dl);
    return dl;
  };
  if (r.kind === 'gap') {
    const g = section('Lost records');
    field(g, 'Dropped', r.gap?.dropped ?? 'Count withheld');
    field(g, 'Reason', r.gap?.reason);
    parts.push(
      el('p', 'Decisions in this interval were not stored; history is incomplete.', 'hint'),
    );
  } else {
    const d = section('Decision (recorded at decision time)');
    field(d, 'Outcome', outcomeLabel(r));
    field(
      d,
      'Source',
      r.decision ? sourceLabel(r.decision.source) : 'No decision at this record time',
    );
    field(d, 'Scope', scopeLabel(r.decision?.scope));
    field(d, 'Reason', r.decision?.reason);
    field(d, 'Decided by', r.decision?.decided_by_uid == null ? undefined : accountLabel(r.decision.decided_by_uid));
    field(
      d,
      'Record type',
      r.kind === 'pending'
        ? 'Historical pending request; not an actionable prompt'
        : 'Final disposition',
    );
    if (r.kind === 'pending') {
      if (current?.supported && !current.outcomeLookup) {
        parts.push(el('p', 'Linked outcomes require a newer daemon.', 'hint'));
      } else if (!r.request_id || !r.generation) {
        parts.push(el('p', 'No recorded outcome available.', 'hint'));
      } else if (current?.outcomeLookup) {
        const link = el('button', 'Open recorded outcome');
        link.onclick = () => void showDetail(r.id, true);
        action.append(link);
      } else {
        parts.push(el('p', 'Outcome lookup unavailable.', 'hint'));
      }
    }
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
    const endpoints = el('div', '', 'log-actions');
    for (const side of ['local', 'remote'] as const) {
      if (!r.flow?.[side]) continue;
      const copy = el('button', `Copy ${side} endpoint`);
      copy.title = r.flow[side];
      copy.onclick = async () => {
        try {
          await window.flowgate.decisionLogCopy(r.id, side, outcomeOf);
          copy.textContent = 'Copied';
        } catch {
          copy.textContent = 'Copy unavailable';
        }
      };
      endpoints.append(copy);
    }
    parts.push(endpoints);
    const a = section('Application at decision time');
    field(a, 'Name', r.application?.name || 'Unidentified');
    field(a, 'Executable', r.application?.executable);
    field(a, 'Revision', r.application?.revision);
    if (r.attribution?.reason_code)
      field(a, 'Attribution category', attributionReasonLabel(r.attribution.reason_code), r.attribution.reason_code);
    field(
      a,
      'Attribution',
      [r.attribution?.status, r.attribution?.reason].filter(Boolean).join(' · '),
    );
    field(a, 'Principal', r.principal_uid == null ? undefined : accountLabel(r.principal_uid));
    parts.push(
      el('p', 'Recorded identity; not matched against currently running processes.', 'hint'),
    );
    const rule = r.decision?.rule;
    if (rule) {
      const s = section('Rule at decision time');
      field(s, 'Rule ID', rule.id);
      if (rule.target_scope === 'network-endpoint') {
        field(s, 'Target scope', ENDPOINT_SCOPE);
        field(s, 'Precedence', ENDPOINT_PRECEDENCE);
      }
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
  if (r.aggregation) {
    const a = section('Aggregated observations');
    field(a, 'Observations', r.aggregation.observations);
    field(a, 'Window', `${r.aggregation.window_ms} ms`);
    field(a, 'First seen', time(r.aggregation.first_seen));
    field(a, 'Last seen', time(r.aggregation.last_seen));
  }
  const meta = section('Record');
  field(meta, 'Sequence', r.sequence);
  field(meta, 'Record ID', r.id);
  field(meta, 'Request ID', r.request_id);
  field(meta, 'Related request ID', r.related_request_id);
  field(meta, 'Daemon generation', r.generation);
  field(meta, 'Mode', r.mode);
  const actions = el('div', '', 'log-actions');
  const copy = el('button', 'Copy record');
  copy.onclick = async () => {
    try {
      await window.flowgate.decisionLogCopy(r.id, undefined, outcomeOf);
      copy.textContent = 'Copied';
    } catch {
      copy.textContent = 'Copy unavailable';
    }
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
function renderRuleComparison(record: LogRecord) {
  const box = $('logRuleCompare');
  if (!box) return;
  const snapshot = record.decision?.rule;
  if (!snapshot) return;
  const c = client?.control;
  // Only a rule-managing connection returns the full inventory; elsewhere an absent rule
  // proves nothing (e.g. lab memory rules, read-only peers).
  if (!c?.connected || !c.rules || !canManageRules(c)) {
    box.replaceChildren(el('p', 'Current rule state is not available on this connection.', 'hint'));
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

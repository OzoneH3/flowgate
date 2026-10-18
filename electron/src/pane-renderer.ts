import { ActivityPolicy } from './activity-policy';
import { TrafficGraph } from './graph';
import { DISPLAY_UNITS } from './display-units';
import type { PaneFrame, PolicyEntry } from './pane-model';
import { initiationPresentation } from './initiation';
import { trafficDetails, sum } from './model';
const kind = new URL(location.href).searchParams.get('pane') === 'info' ? 'info' : 'chart';
const root = document.getElementById('app')!;
const el = (tag: string, text = '', cls = '') => {
  const e = document.createElement(tag);
  e.textContent = text;
  e.className = cls;
  return e;
};
root.innerHTML =
  '<header class="detached-heading"><h2></h2><button id="dockPane">Dock</button><button id="closePane" aria-label="Close pane">✕</button></header><div class="pane-presentation"><label>Units <select id="paneUnits" aria-label="Display units"></select></label><label>Source <select id="paneSource" aria-label="Accounting source"><option value="tcp">TCP</option><option value="udp">UDP</option></select></label></div><p id="paneEnforcement" class="pane-action-hint"></p><p id="paneMessage" role="status"></p><section id="paneContent"></section>';
root.querySelector('h2')!.textContent = kind === 'info' ? 'Info View' : 'Traffic chart';
const message = (e: unknown) => {
  document.getElementById('paneMessage')!.textContent = String(e);
};
(document.getElementById('dockPane') as HTMLButtonElement).onclick = () =>
  void window.flowgate.paneControl(kind, 'dock').catch(message);
(document.getElementById('closePane') as HTMLButtonElement).onclick = () =>
  void window.flowgate.paneControl(kind, 'close').catch(message);
const units = document.getElementById('paneUnits') as HTMLSelectElement,
  source = document.getElementById('paneSource') as HTMLSelectElement;
for (const u of DISPLAY_UNITS) units.add(new Option(u, u));
units.onchange = () =>
  void window.flowgate
    .paneUpdate({ unit: units.value as PaneFrame['presentation']['unit'] })
    .catch(message);
source.onchange = () =>
  void window.flowgate.paneUpdate({ source: source.value as 'tcp' | 'udp' }).catch(message);
const content = document.getElementById('paneContent')!;
let frame: PaneFrame | undefined,
  graph: TrafficGraph | undefined,
  policy: ActivityPolicy | undefined;
if (kind === 'chart') {
  const windowSelect = document.createElement('select');
  windowSelect.id = 'paneWindow';
  windowSelect.setAttribute('aria-label', 'History window');
  for (const n of [60, 300, 600]) windowSelect.add(new Option(n / 60 + ' min', String(n)));
  document.querySelector('.pane-presentation')!.append(windowSelect);
  windowSelect.onchange = () =>
    void window.flowgate
      .paneUpdate({ chart: { seconds: Number(windowSelect.value), end: undefined, paused: false } })
      .catch(message);
  graph = new TrafficGraph(content, {
    change: (chart) => void window.flowgate.paneUpdate({ chart }).catch(message),
    source: (source) => void window.flowgate.paneUpdate({ source }).catch(message),
  });
} else {
  content.innerHTML =
    '<h3 id="selectedName"></h3><div id="selectedExecutable"></div><div class="info-scroll"><h3 class="info-section-title">Properties</h3><dl id="info"></dl><section id="infoRules"></section></div><p class="pane-action-hint">Quick actions use the shared rule service. Advanced editing opens in Activity.</p>';
  const delegate = (action: PolicyEntry) => {
    if (!frame) return;
    void window.flowgate
      .paneRule({
        ...action,
        selection: frame.presentation.selection,
        generation: frame.presentation.generation,
      })
      .then(() => message('Opened in Activity — review and act there.'))
      .catch(message);
  };
  policy = new ActivityPolicy(document.getElementById('infoRules')!, delegate);
}
let signature = '';
function consume(next: PaneFrame) {
  if (frame && next.presentation.revision < frame.presentation.revision) return;
  frame = next;
  const p = next.presentation,
    s = next.state,
    r = p.row;
  document.getElementById('paneEnforcement')!.textContent = !s.control.connected
    ? 'Firewall · disconnected / unknown'
    : `Firewall · ${s.control.enforcement?.state || 'unknown'}${s.control.enforcement?.state === 'active' ? ' · ' + s.control.enforcement.profile : ''}`;
  units.value = p.unit;
  source.value = p.source;
  if (graph) {
    const windows = document.getElementById('paneWindow') as HTMLSelectElement;
    for (const option of [...windows.options]) if (option.dataset.zoom) option.remove();
    if (![60, 300, 600].includes(p.chart.seconds)) {
      const option = new Option(Math.round(p.chart.seconds) + ' s (zoom)', String(p.chart.seconds));
      option.dataset.zoom = 'true';
      windows.add(option);
    }
    windows.value = String(p.chart.seconds);
    graph.setUnit(p.unit);
    graph.setSource(p.source);
    graph.setPresentation(p.chart);
    void graph.update(p.selection, `${p.revision}`);
    return;
  }
  const fields: [string, string][] = [];
  if (r) {
    fields.push(['Name', r.kind === 'process' ? r.process?.application.name || r.label : r.label]);
    if (r.process)
      fields.push(
        ['User ID', String(r.process.uid)],
        ...(r.kind === 'process' || r.kind === 'socket'
          ? [['Process', `${r.process.pid} · start ${r.process.start_ticks}`] as [string, string]]
          : []),
        ['Application identity', `${r.process.application.key}\n${r.process.application.revision}`],
      );
    fields.push(['Visible sockets', String(r.rows.length)]);
    const count = sum(r.rows, 'uploaded', p.source);
    fields.push([
      'Coverage',
      `${count.known}/${count.count} supported ${p.source.toUpperCase()} sockets`,
    ]);
    if (r.socket)
      fields.push(
        ['Local endpoint', r.socket.socket.local],
        ['Remote endpoint', r.socket.socket.remote],
        ['Initiation', initiationPresentation(r.socket).title],
        ['Ownership', r.socket.ownership],
        ['Measurements', trafficDetails(r.socket.traffic)],
      );
    if (r.kind === 'network')
      fields.push([
        'Coverage',
        'Classification unavailable. No configured network-zone attribution; totals are unknown, not zero. Not a firewall target.',
      ]);
    if (!r.rows.length && r.kind !== 'network')
      fields.push([
        'Observation',
        'Selected item is no longer visible. No process or application target is rebound.',
      ]);
  } else fields.push(['Selection', 'Select an application, process or connection in Activity.']);
  const stamp = JSON.stringify([p.selection, fields, r?.process?.executable]);
  if (stamp !== signature) {
    signature = stamp;
    const title = document.getElementById('selectedName')!;
    title.textContent =
      r?.kind === 'application'
        ? 'Application'
        : r?.kind === 'process'
          ? `Process ${r.pid}`
          : r?.kind === 'socket'
            ? 'Connection'
            : r?.label || 'FlowGate Activity';
    const executable = r?.process?.executable || r?.displayApplication?.executable || '';
    document.getElementById('selectedExecutable')!.textContent = executable;
    const dl = document.getElementById('info')!;
    dl.replaceChildren();
    const technical = document.createElement('details');
    technical.className = 'info-technical';
    technical.append(el('summary', 'Identity details'));
    const inner = document.createElement('dl');
    for (const [k, v] of fields)
      if (k === 'Application identity') inner.append(el('dt', k), el('dd', v));
      else dl.append(el('dt', k), el('dd', v));
    if (inner.childElementCount) {
      technical.append(inner);
      dl.append(technical);
    }
    const app =
      r && !r.displayApplication && (!r.socket || r.socket.owners.length === 1)
        ? r.process?.application
        : undefined;
    if (app) {
      const key = JSON.stringify([app.key, app.revision, app.executable]);
      void window.flowgate
        .applicationIcons([key])
        .then((icons) => {
          if (frame?.presentation.selection !== p.selection) return;
          const url = icons[key];
          if (url) {
            const img = document.createElement('img');
            img.src = url;
            img.alt = '';
            img.width = img.height = 16;
            title.prepend(img);
          }
        })
        .catch(() => {});
    }
  }
  policy?.update(r, s);
}
window.flowgate.onPaneFrame(consume);
void window.flowgate.paneSnapshot().then(consume).catch(message);

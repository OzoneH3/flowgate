import {
  CONNECTION_ANALYSIS_CAPABILITY,
  type ConnectionAnalysis,
  type ConnectionAnalysisMode,
  type ConnectionObservation,
} from './connection-analysis';
import type { ClientState } from './protocol';

export const connectionAnalysisPanel = `
<section id="connectionAnalysis" aria-labelledby="connectionAnalysisTitle" hidden>
  <div class="analysis-header">
    <h3 id="connectionAnalysisTitle">Analyze connections</h3>
    <button id="closeConnectionAnalysis" type="button">Close</button>
  </div>
  <div class="analysis-actions">
    <button id="recheckConnections" type="button">Recheck Unidentified</button>
    <button id="watchConnections" type="button">Watch for 10 seconds</button>
  </div>
  <p id="connectionAnalysisStatus" role="status"></p>
  <div id="connectionAnalysisResults" role="region" aria-label="Connection analysis results" tabindex="0" hidden></div>
</section>`;

function node<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  label: string,
): HTMLElementTagNameMap[K] {
  const element = document.createElement(tag);
  element.textContent = label;
  return element;
}

const observationTime = new Intl.DateTimeFormat(undefined, {
  dateStyle: 'medium',
  timeStyle: 'medium',
});

function time(at: string): string {
  return observationTime.format(new Date(at));
}

function applicationLabel(app: NonNullable<ConnectionObservation['application']>): string {
  const executable =
    app.executable ||
    (app.name ? `${app.name} (executable unavailable)` : 'Executable unavailable');
  return app.pid === undefined ? executable : `${executable} · PID ${app.pid}`;
}

function holderDetails(holder: ConnectionObservation['holders'][number]): HTMLElement {
  const row = document.createElement('li');
  const image = holder.windowsImage;
  const name = image?.name || holder.executable.split('/').at(-1);
  row.append(node('strong', name ? `${name} · PID ${holder.pid}` : `PID ${holder.pid}`));

  const details = document.createElement('dl');
  if (image)
    details.append(
      node('dt', 'Windows executable'),
      node('dd', image.executable || 'Unavailable'),
      node('dt', 'Wine prefix'),
      node('dd', image.prefix || 'Unavailable'),
    );
  details.append(node('dt', 'Native executable'), node('dd', holder.executable || 'Unavailable'));
  row.append(details);
  if (holder.windowsImageReason) row.append(node('p', holder.windowsImageReason));
  return row;
}

function observationDetails(observation: ConnectionObservation, expandable = true): HTMLElement {
  const shared = observation.category === 'shared' || observation.holders.length > 1;
  const body = document.createElement(shared && expandable ? 'details' : 'div');
  if (shared && expandable) {
    body.className = 'analysis-shared';
    const count = observation.holders.length;
    const suffix = observation.holdersTruncated ? ' reported' : '';
    body.append(
      node('summary', `Shared socket · ${count} ${count === 1 ? 'process' : 'processes'}${suffix}`),
    );
  }
  if (observation.application)
    body.append(node('p', `Verified · ${applicationLabel(observation.application)}`));
  if (!observation.application) {
    const reason =
      observation.reason ||
      observation.category.replaceAll('-', ' ') ||
      'No ownership evidence reported';
    body.append(node('p', `Unresolved · ${reason}`));
  }
  if (
    observation.holders.length &&
    (shared ||
      observation.application?.pid === undefined ||
      observation.holders.some((holder) => holder.windowsImage || holder.windowsImageReason))
  ) {
    const holders = document.createElement('ul');
    holders.className = 'analysis-holders';
    for (const holder of observation.holders) holders.append(holderDetails(holder));
    body.append(holders);
  }
  if (observation.holdersTruncated) body.append(node('p', 'Only some holders could be reported.'));
  return body;
}

function renderResults(target: HTMLElement, result: ConnectionAnalysis): void {
  const fragment = document.createDocumentFragment();
  if (result.partial) fragment.append(node('p', 'Some Activity samples were incomplete.'));
  if (result.truncated)
    fragment.append(node('p', 'The daemon reached its limit for sockets or observation history.'));
  for (const connection of result.connections) {
    const latest = connection.observations.at(-1)!;
    const previous = connection.observations.slice(0, -1).reverse();
    const earlierVerified = previous.find((entry) => entry.application);
    const row = document.createElement('article');
    const endpoints = `${latest.local || connection.local} → ${latest.remote || connection.remote}`;
    row.append(
      node('h4', `${connection.protocol.toUpperCase()} ${endpoints}`),
      node(
        'p',
        `${connection.fromActivity ? 'From Unidentified' : 'New during watch'} · ${time(latest.at)}`,
      ),
      observationDetails(latest),
    );
    if (!latest.application && earlierVerified?.application)
      row.append(
        node(
          'p',
          `Previously verified · ${applicationLabel(earlierVerified.application)} · observed ${time(earlierVerified.at)}`,
        ),
      );
    if (previous.length) {
      const history = document.createElement('details');
      history.append(node('summary', 'Earlier observations'));
      for (const entry of previous) {
        const observation = document.createElement('div');
        observation.className = 'analysis-history-entry';
        observation.append(node('p', time(entry.at)), observationDetails(entry, false));
        history.append(observation);
      }
      row.append(history);
    }
    fragment.append(row);
  }
  target.replaceChildren(fragment);
  target.hidden = !target.childElementCount;
}

export function setupConnectionAnalysis() {
  const opener = document.querySelector<HTMLButtonElement>('#openConnectionAnalysis')!;
  const panel = document.querySelector<HTMLElement>('#connectionAnalysis')!;
  const close = document.querySelector<HTMLButtonElement>('#closeConnectionAnalysis')!;
  const recheck = document.querySelector<HTMLButtonElement>('#recheckConnections')!;
  const watch = document.querySelector<HTMLButtonElement>('#watchConnections')!;
  const status = document.querySelector<HTMLElement>('#connectionAnalysisStatus')!;
  const results = document.querySelector<HTMLElement>('#connectionAnalysisResults')!;
  let context: string | undefined;
  let request = 0;
  let busy = false;

  function updateActions() {
    recheck.disabled = watch.disabled = !context || busy;
  }

  function toggle(open: boolean) {
    panel.hidden = !open;
    opener.setAttribute('aria-expanded', String(open));
    (open ? close : opener).focus();
  }

  async function run(mode: ConnectionAnalysisMode) {
    if (busy || !context) return;
    const id = ++request;
    busy = true;
    updateActions();
    results.replaceChildren();
    results.hidden = true;
    status.textContent =
      mode === 'watch'
        ? 'Watching for 10 seconds. Launch the app now.'
        : 'Rechecking the current Unidentified connections…';
    try {
      const result = await window.flowgate.analyzeConnections(mode);
      if (id !== request) return;
      const total = result.connections.length;
      status.textContent = total
        ? `${total} ${total === 1 ? 'socket' : 'sockets'} analyzed · ${result.baselineCount} Unidentified at start · finished ${time(result.finished)}`
        : mode === 'watch'
          ? 'No new or Unidentified connections were observed during the watch.'
          : 'No Unidentified connections were available to recheck.';
      renderResults(results, result);
    } catch (error) {
      if (id === request)
        status.textContent =
          error instanceof Error
            ? error.message.replace(
                /^Error invoking remote method '[^']+': (?:BackendCallError|Error): /,
                '',
              )
            : 'Connection analysis failed.';
    } finally {
      if (id === request) {
        busy = false;
        updateActions();
      }
    }
  }

  opener.onclick = () => toggle(panel.hidden === true);
  close.onclick = () => toggle(false);
  recheck.onclick = () => void run('recheck');
  watch.onclick = () => void run('watch');
  updateActions();

  return (observation: ClientState['observation']) => {
    const nextContext =
      observation.connected && observation.capabilities?.includes(CONNECTION_ANALYSIS_CAPABILITY)
        ? JSON.stringify([observation.generation, observation.permissions?.observation_scope])
        : '';
    if (nextContext === context) return;
    context = nextContext;
    request++;
    busy = false;
    results.replaceChildren();
    results.hidden = true;
    status.textContent = context
      ? 'Recheck Unidentified now or start a watch before launching an app.'
      : 'Connection analysis is unavailable from the Activity daemon.';
    updateActions();
  };
}

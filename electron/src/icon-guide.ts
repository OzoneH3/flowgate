import { blockerGlyph, STATUS_SLOTS } from './activity-policy';
import { statusIconMarkup } from './fast-path';
import type { Row } from './model';
import type { NetworkZone } from './network-zones';
import type { ChipTone } from './rule-chip';
import { limitGlyph } from './upload-shaping-view';

type Icon = Node | string;

export function createIconGuide(
  rowIcon: (kind: Row['kind'] | NetworkZone | 'service' | 'terminal') => SVGElement,
  statusFamilyGlyph: (key: string) => HTMLElement,
) {
  const dialog = document.createElement('dialog');
  dialog.id = 'iconGuide';
  dialog.setAttribute('aria-labelledby', 'iconGuideTitle');
  const title = document.createElement('h2');
  title.id = 'iconGuideTitle';
  title.textContent = 'Icons and symbols';
  const body = document.createElement('div');
  body.className = 'icon-guide-body';

  function section(name: string, entries: [Icon, string, string][]) {
    const heading = document.createElement('h3');
    heading.textContent = name;
    const list = document.createElement('dl');
    for (const [icon, label, explanation] of entries) {
      const term = document.createElement('dt');
      const sample = document.createElement('span');
      sample.className = 'icon-guide-sample';
      sample.setAttribute('aria-hidden', 'true');
      sample.append(icon);
      term.append(sample, label);
      const definition = document.createElement('dd');
      definition.textContent = explanation;
      list.append(term, definition);
    }
    body.append(heading, list);
  }

  function symbol(text: string, className: string) {
    const span = document.createElement('span');
    span.className = className;
    span.textContent = text;
    return span;
  }
  function connectionStatus(state: 'on' | 'idle' | 'in-use') {
    const span = symbol('', 'connection-status-slot ' + state);
    span.innerHTML = statusIconMarkup(state);
    return span;
  }
  function blocker(tone: ChipTone) {
    return blockerGlyph({ glyph: '', text: '', detail: '', tone });
  }
  function shield(active: boolean) {
    const img = document.createElement('img');
    img.src = active ? 'flowgate.png' : 'flowgate-off.png';
    img.alt = '';
    return img;
  }

  section('Activity rows', [
    [rowIcon('overview'), 'Computer', 'Overview of the sockets visible to FlowGate.'],
    [rowIcon('internet'), 'Internet', 'Internet traffic, either across applications or for the app shown.'],
    [rowIcon('local'), 'Local Network', 'Local network traffic, either across applications or for the app shown.'],
    [rowIcon('application'), 'Application', 'An application or group. FlowGate uses the application’s own icon when available.'],
    [rowIcon('process'), 'Process', 'An individual running instance, identified by its process ID.'],
    [rowIcon('service'), 'Service fallback', 'A generic icon for a service or background program.'],
    [rowIcon('terminal'), 'Terminal fallback', 'A generic icon for a command-line program.'],
    [rowIcon('inactive-group'), 'Not running', 'Applications with saved rules and no observed running instance.'],
    [rowIcon('unidentified'), 'Unidentified', 'The socket owner could not be assigned to a single verified application.'],
    [rowIcon('kernel-lifecycle'), 'Kernel TCP lifecycle', 'Kernel socket records, such as TIME_WAIT, that can outlast the owning process.'],
    ['▷ / ◢', 'Tree arrows', 'Expand or collapse the row’s children.'],
  ]);

  section('Connection observations', [
    [connectionStatus('on'), 'Green dot', 'An established TCP connection or a UDP socket with a connected peer.'],
    [connectionStatus('in-use'), 'Lightning bolt', 'Recent UDP fast-path hits were observed for this application.'],
    [connectionStatus('idle'), 'Outlined diamond', 'A UDP fast-path grant exists, with no recent fast-path hits observed.'],
    [symbol('←', 'connection-direction connection-incoming'), 'Incoming', 'The remote peer initiated the connection.'],
    [symbol('→', 'connection-direction connection-outgoing'), 'Outgoing', 'The local application initiated the connection.'],
    [symbol('·', 'connection-direction connection-listening'), 'Listening', 'A TCP socket waiting for incoming connections.'],
    [symbol('○', 'connection-direction connection-neutral'), 'Unconnected UDP', 'A UDP socket without one connected peer.'],
    [symbol('↔', 'connection-direction connection-neutral'), 'Ambiguous initiation', 'Available evidence does not resolve who initiated the connection.'],
    [symbol('?', 'connection-direction connection-neutral'), 'Unknown initiation', 'FlowGate has no verified initiation direction for this connection.'],
  ]);

  const slotDescriptions = [
    'Controls how this application’s traffic is prioritized when shaping is available.',
    'Download rate limit.',
    'Upload rate limit.',
    'Firewall rules for connections initiated by the remote peer.',
    'Firewall rules for connections initiated by the local application.',
  ];
  section('Rule Status strip, left to right', STATUS_SLOTS.map(({ key, label }, index) => {
    const slot = symbol('', 'status-slot');
    slot.append(key === 'priority' ? limitGlyph('priority') : statusFamilyGlyph(key));
    return [slot, label, slotDescriptions[index]];
  }));
  const configuredLimit = symbol('', 'status-slot upload-limit upload-configured');
  configuredLimit.append(limitGlyph('upload'));
  section('Rule indicators', [
    [blocker('allow'), 'Green check · Allow', 'The configured rule permits matching attempts.'],
    [blocker('block'), 'Red cross · Deny', 'The configured rule blocks matching attempts.'],
    [blocker('ask'), 'Yellow question mark · Ask', 'Matching new attempts prompt for a decision.'],
    [blocker('mixed'), 'Orange ± · Mixed', 'Rules in this summary have different actions. Check the matching scope.'],
    [blocker('off'), 'Dashed circle · Inactive', 'The rule is disabled, expired, or bound to an ended process.'],
    [blocker('unavailable'), 'Gray question mark · Unavailable', 'FlowGate cannot show a verified rule status for this row.'],
    ['·', 'Small gray dot', 'The slot has no displayed rule indicator. Hover to identify the control or see why it is unavailable.'],
    ['+2', 'Scoped rule count', 'The number of additional rules with a narrower scope.'],
    [configuredLimit, 'Blue limit or priority icon', 'A shaping setting is configured. Its coverage is shown in the control’s details.'],
  ]);

  section('Measurements and controls', [
    ['*', 'Asterisk', 'Partial coverage. The value includes only traffic FlowGate could observe.'],
    ['—', 'Dash', 'No measurement is available. A measured zero is shown as 0.'],
    [symbol('━', 'graph-download'), 'Green chart series', 'Download rate.'],
    [symbol('━', 'graph-upload'), 'Red chart series', 'Upload rate.'],
    ['❚❚ / ▶', 'Pause / resume', 'Pause chart updates or resume following live traffic.'],
    ['↻', 'Refresh / return to live', 'In Activity, refresh the snapshot. In the chart, return to live.'],
    ['‹ / ›', 'Previous / next', 'Inspect the neighboring chart sample.'],
    ['⊞ / ⊟', 'Expand all / collapse all', 'Open or close all Activity tree groups.'],
    ['▾ / ✕', 'Pane menu / close', 'Open the pane menu or close the pane. Closed panes can be reopened from Window.'],
    [shield(true), 'Blue FlowGate shield', 'Firewall protection is confirmed active.'],
    [shield(false), 'Red FlowGate shield', 'Firewall protection is off or its active state is unconfirmed.'],
  ]);

  const footer = document.createElement('footer');
  const close = document.createElement('button');
  close.textContent = 'Close';
  close.autofocus = true;
  close.onclick = () => dialog.close();
  footer.append(close);
  dialog.append(title, body, footer);
  document.body.append(dialog);
  return dialog;
}

import type { Application, PermissionTarget, Provenance, RequestEvent } from './protocol';
import { launchTitle, promptIdentity, verifiedLaunch } from './provenance';

// The first view of a pending request: who,
// to where, and nothing else. Pure; every technical field lives in Details.

type Ev = Pick<RequestEvent, 'flow' | 'attribution' | 'local_peer'>;

// Same-host services a game commonly reaches. Display only: the decision
// target is always the backend's exact pair or permission_target.
const LOCAL_SERVICES: Record<string, string> = {
  cupsd: 'Local printing service',
  'avahi-daemon': 'Local network discovery',
  'systemd-resolved': 'Local DNS resolver',
  dnsmasq: 'Local DNS service',
  pipewire: 'Local audio service',
  pulseaudio: 'Local audio service',
  'steam': 'Steam client',
  steamwebhelper: 'Steam client',
};

function baseName(app?: { display_name?: string; name?: string; executable?: string }, exe = '') {
  return (
    app?.display_name ||
    (app?.name || '').replace(/ \(deleted\)$/, '') ||
    (app?.executable || exe).split('/').pop() ||
    ''
  );
}

/** "Local printing service (cupsd)", or the verified peer's name; '' when not local. */
export function localServiceName(e: Ev): string {
  const peer = e.local_peer;
  if (!peer) return '';
  const name = peer.state === 'verified' && peer.owner ? baseName(peer.owner.application, peer.owner.executable) : '';
  if (!name) return e.flow.direction === 'incoming' ? 'Unknown local client' : 'Local service';
  if (e.flow.direction === 'incoming') return name;
  const known = LOCAL_SERVICES[name.toLowerCase()];
  return known ? `${known} (${name})` : `Local service (${name})`;
}

export interface PromptSummary {
  /** Game when the backend verified the launch; else the application. */
  title: string;
  /** The process that actually owns the socket, when it differs from the title. */
  owner: string;
  /** Unverified association (e.g. an Electron runtime whose app is unverified). */
  note: string;
  /** The title is the application's own identity (icon/desktop name may apply). */
  ownIdentity: boolean;
  /** The program that started it (e.g. Heroic for nile), display only. */
  launchedBy: string;
  /** "Local printing service (cupsd)" or the remote endpoint. */
  destination: string;
  /** "127.0.0.1:631" (omitted when it equals destination). */
  endpoint: string;
  protocol: string;
  contextApplication?: Application;
}

export function promptSummary(e: Ev, fallbackName: string): PromptSummary {
  const identity = promptIdentity(e as RequestEvent);
  const own = baseName(e.attribution.application, e.attribution.owners[0]?.executable) || fallbackName;
  const service = localServiceName(e);
  // Incoming: the endpoint that connects to us is the remote side.
  const endpoint = e.flow.remote;
  const app = e.attribution.application;
  const provenance = e.attribution.provenance;
  const invocation = provenance?.invocation;
  // If the socket owner is an interpreter acting as a verified launcher, prefer
  // the verified executable it launched for the prompt's display context. The
  // interpreter remains the permission identity; this is deliberately generic
  // for any verified launcher, not a game-specific rule.
  if (invocation && provenance?.role === 'launcher' && verifiedLaunch(provenance)) {
    const interpreter = app?.display_name || app?.name || own;
    return {
      title: launchTitle(provenance),
      owner: interpreter,
      note: `Verified launch context only. Permission applies to the ${interpreter} interpreter.`,
      ownIdentity: false,
      launchedBy: '',
      destination: service || endpoint,
      endpoint: service ? endpoint : '',
      protocol: e.flow.protocol.toUpperCase(),
    };
  }
  if (invocation) {
    const interpreter = app?.display_name || app?.name || own;
    const title = invocation.application?.display_name || invocation.application?.name || invocation.name;
    return { title, owner: interpreter, note: `Permission applies to the ${interpreter} interpreter. The invoked program is display context only.`, ownIdentity: false, launchedBy: '', destination: service || endpoint, endpoint: service ? endpoint : '', protocol: e.flow.protocol.toUpperCase(), contextApplication: invocation.application };
  }
  if (app?.kind === 'wine' && app.key && app.revision && (e.attribution.provenance?.role==='game' || e.attribution.owners.some(p=>p.application.key!==app.key))) return {title:app.name || app.executable.split('/').pop() || own, owner:'',note:'',ownIdentity:true,launchedBy:launchedByName(e),destination:service||endpoint,endpoint:service?endpoint:'',protocol:e.flow.protocol.toUpperCase()};
  // A launcher socket is permission for the launcher, never its future game.
  if (app?.key && app.revision && e.attribution.provenance?.role === 'launcher')
    return {title: own, owner: '', note: 'Launcher connection; permission applies to this executable', ownIdentity: true, launchedBy: launchedByName(e), destination: service || endpoint, endpoint: service ? endpoint : '', protocol: e.flow.protocol.toUpperCase()};
  // A verified Electron app: the bundle is the application, the runtime owns the socket.
  if (!identity.title && app?.kind === 'electron')
    return {
      title: own,
      owner: (app.runtime || app.hosted?.runtime || 'electron').split('/').pop()!,
      note: '',
      ownIdentity: true,
      launchedBy: launchedByName(e),
      destination: service || endpoint,
      endpoint: service ? endpoint : '',
      protocol: e.flow.protocol.toUpperCase(),
    };
  return {
    title: identity.title ? gameName(e.attribution.provenance) || identity.title : own,
    owner: identity.title && own !== identity.title ? own : '',
    note: app?.hosted?.state === 'unverified' ? 'application unverified' : '',
    ownIdentity: !identity.title,
    // A verified game launch already names the context; otherwise the parent program.
    launchedBy: identity.title ? '' : launchedByName(e),
    destination: service || endpoint,
    endpoint: service ? endpoint : '',
    protocol: e.flow.protocol.toUpperCase(),
  };
}

/** "Timberborn" (manifest/title) rather than "Timberborn · Timberborn.exe". */
function gameName(p?: Provenance) {
  const v = verifiedLaunch(p);
  const game = v?.launch?.game;
  if (!game) return '';
  return game.title || game.name.replace(/\.exe$/i, '') || launchTitle(v!);
}

/** One line for the first view: destination, endpoint, protocol. */
export function destinationLine(s: PromptSummary, direction: string): string {
  const parts = [s.destination, s.endpoint, s.protocol].filter(Boolean);
  return (direction === 'incoming' ? 'From ' : 'To ') + parts.join(' · ');
}

/**
 * Concise label of what Remember saves, shown before the click. Never names the
 * game as the scope: a Wine helper rule covers every program in that prefix.
 */
export function rememberLabel(t?: PermissionTarget): string {
  if (!t || t.kind === 'unavailable') return 'Unavailable: no verified application identity';
  if (t.kind === 'runtime-unverified') return 'Unavailable: application unverified (the runtime runs many applications)';
  const name = t.label.replace(/ \(.*\)$/, '').replace(/ in prefix .*$/, '');
  const prefix = t.prefix ? shortPrefix(t.prefix) : '';
  switch (t.kind) {
    case 'helper':
      return prefix
        ? `Rule for ${name} in prefix ${prefix} · every game using this prefix`
        : `Rule for ${name} · every program running it`;
    case 'interpreter':
      return `Rule for ${name} · every script it runs`;
    default:
      return prefix ? `Rule for ${name} in prefix ${prefix}` : `Rule for ${name}`;
  }
}

function shortPrefix(p: string) {
  const home = p.replace(/^\/home\/[^/]+/, '~').replace(/\/$/, '');
  const parts = home.split('/');
  return home.length > 40 && parts.length > 3 ? '…/' + parts.slice(-2).join('/') : home;
}

/**
 * One backend preview as Details fields: the rule sentence without its verb
 * (Allow and Deny previews are never both shown) and the overlap list.
 */
export function splitPreview(text: string): { preview: string; overlaps: string[] } {
  const overlaps: string[] = [];
  const preview = text
    .replace(/ ?Overlap: [^.]*\([^)]*\)\./g, (m) => {
      overlaps.push(m.trim().replace(/^Overlap: /, '').replace(/\.$/, ''));
      return '';
    })
    .replace(/ ?And (\d+) more overlapping rules\./, (_m, n) => {
      overlaps.push(`and ${n} more`);
      return '';
    })
    .replace(/^(Allow|Deny|Block) /, '')
    .trim();
  return { preview, overlaps };
}

// ---- Permission window layout ------------------------------------

/** "Outgoing connection - TCP(6)" (IANA protocol number as NetLimiter shows it). */
export function connectionHeader(flow: Pick<RequestEvent['flow'], 'direction' | 'protocol'>): string {
  const dir = flow.direction === 'incoming' ? 'Incoming' : flow.direction === 'outgoing' ? 'Outgoing' : 'Unknown';
  const proto = flow.protocol.toLowerCase();
  const number: Record<string, number> = { tcp: 6, udp: 17, icmp: 1, icmpv6: 58, sctp: 132 };
  return `${dir} connection - ${proto.toUpperCase()}${number[proto] ? `(${number[proto]})` : ''}`;
}

/**
 * "[2001:db8::1%eth0]:443" -> { address: "2001:db8::1%eth0", port: "443" }.
 * The backend's own address text is kept verbatim (IPv6 compression, zone).
 */
export function splitEndpoint(endpoint: string): { address: string; port: string } {
  const v6 = /^\[([^\]]+)\]:(\d+)$/.exec(endpoint);
  if (v6) return { address: v6[1], port: v6[2] };
  const v4 = /^([^:\[\]]+):(\d+)$/.exec(endpoint);
  if (v4) return { address: v4[1], port: v4[2] };
  return { address: endpoint, port: '' };
}

export interface ProgramSide {
  kind: 'program';
  /** Game or application name (bold, with icon). */
  name: string;
  /** Socket-owning helper when it differs (e.g. rundll32.exe for a Proton game). */
  owner: string;
  /** Unverified association, shown beside the name. */
  note?: string;
}
export interface PeerSide {
  kind: 'peer';
  /** Known local service, verified local program, or the remote address. */
  text: string;
}
/** From/To: the program is From for outgoing and To for incoming. */
export function fromTo(e: Ev, s: PromptSummary): { from: ProgramSide | PeerSide; to: ProgramSide | PeerSide } {
  const program: ProgramSide = { kind: 'program', name: s.title, owner: s.owner, ...(s.note ? { note: s.note } : {}) };
  const service = localServiceName(e);
  const peer: PeerSide = { kind: 'peer', text: service || splitEndpoint(e.flow.remote).address };
  return e.flow.direction === 'incoming' ? { from: peer, to: program } : { from: program, to: peer };
}

/** The four field rows under the From/To box, from backend values only. */
export function connectionFields(e: Ev) {
  const owners = e.attribution.owners;
  const app = e.attribution.application;
  const executable = app?.display_executable || app?.executable || owners[0]?.executable || '';
  // An Electron app's identity is its bundle: name the bundle with its folder
  // ("heroic-games-launcher/app.asar"), never the shared runtime.
  const application = app?.kind === 'electron' ? executable.split('/').slice(-2).join('/') : executable.split('/').pop();
  return {
    application: application || 'Unavailable',
    executable,
    process: owners.length ? 'Process ' + owners.map((o) => o.pid).join(', ') : 'Unavailable',
    local: splitEndpoint(e.flow.local),
    remote: splitEndpoint(e.flow.remote),
  };
}

/** Name of the program that started the socket owner (provenance parent). */
export function launchedByName(e: Pick<RequestEvent, 'attribution'>): string {
  const parent = e.attribution.provenance?.parent;
  if (!parent) return '';
  return parent.application?.display_name || parent.application?.name || parent.name;
}

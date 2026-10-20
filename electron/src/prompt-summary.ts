import type { PermissionTarget, Provenance, RequestEvent } from './protocol';
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
  /** "Local printing service (cupsd)" or the remote endpoint. */
  destination: string;
  /** "127.0.0.1:631" (omitted when it equals destination). */
  endpoint: string;
  protocol: string;
}

export function promptSummary(e: Ev, fallbackName: string): PromptSummary {
  const identity = promptIdentity(e as RequestEvent);
  const own = baseName(e.attribution.application, e.attribution.owners[0]?.executable) || fallbackName;
  const service = localServiceName(e);
  // Incoming: the endpoint that connects to us is the remote side.
  const endpoint = e.flow.remote;
  return {
    title: identity.title ? gameName(e.attribution.provenance) || identity.title : own,
    owner: identity.title && own !== identity.title ? own : '',
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

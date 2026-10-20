import type { Application, Provenance, RequestEvent } from './protocol';

// local-pair-v1: same-host connections. The backend identifies the other
// endpoint of a local connection from the EXACT reversed tuple (never by port,
// time or name) and links the two requests of one connection (client outgoing
// + server incoming) through local_peer.correlated_event_id. This module only
// presents that evidence: each request's permission target stays its own
// (an incoming rule for the server is never an outgoing rule for the client).

export const LOCAL_PAIR_CAPABILITY = 'local-pair-v1';

export interface LocalPeerOwner {
  pid: number;
  start_ticks: string;
  uid: number;
  executable: string;
  application: Pick<Application, 'key' | 'name' | 'executable' | 'revision' | 'display_name'> & { kind?: string };
  provenance?: Provenance;
}
export interface LocalPeerSocket {
  kind: 'client' | 'listener' | 'bound';
  protocol: string;
  local: string;
  remote: string;
  state: string;
  cookie: string;
  inode: number;
}
export interface LocalPeer {
  state: 'verified' | 'unknown';
  role: 'client' | 'server';
  reason: string;
  evidence?: string;
  owner?: LocalPeerOwner;
  socket?: LocalPeerSocket;
  correlated_event_id?: string;
}
export interface OwnSocket {
  protocol: string;
  local: string;
  remote: string;
  state: number;
  cookie: string;
  inode: number;
}

const obj = (v: unknown): Record<string, unknown> =>
  v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
const str = (v: unknown, max = 1024) => (typeof v === 'string' ? v.slice(0, max) : '');
const int = (v: unknown) => (Number.isSafeInteger(v) && (v as number) >= 0 ? (v as number) : 0);

/** Bounded parser; anything malformed is dropped (no peer shown), never trusted. */
export function parseLocalPeer(raw: unknown, provenance: (v: unknown) => Provenance | undefined): LocalPeer | undefined {
  if (raw == null) return;
  const p = obj(raw);
  if (!['verified', 'unknown'].includes(str(p.state)) || !['client', 'server'].includes(str(p.role))) return;
  const o = p.owner == null ? undefined : obj(p.owner);
  const s = p.socket == null ? undefined : obj(p.socket);
  const a = o ? obj(o.application) : {};
  const peer: LocalPeer = {
    state: str(p.state) as LocalPeer['state'],
    role: str(p.role) as LocalPeer['role'],
    reason: str(p.reason),
    evidence: str(p.evidence, 2048) || undefined,
    owner:
      o && int(o.pid) > 0
        ? {
            pid: int(o.pid),
            start_ticks: str(o.start_ticks, 32),
            uid: int(o.uid),
            executable: str(o.executable),
            application: {
              key: str(a.key, 256),
              name: str(a.name, 256),
              executable: str(a.executable),
              revision: str(a.revision, 256),
              display_name: str(a.display_name, 256) || undefined,
              kind: str(a.kind, 32) || undefined,
            },
            provenance: provenance(o.provenance),
          }
        : undefined,
    socket:
      s && ['client', 'listener', 'bound'].includes(str(s.kind))
        ? {
            kind: str(s.kind) as LocalPeerSocket['kind'],
            protocol: str(s.protocol, 8),
            local: str(s.local, 64),
            remote: str(s.remote, 64),
            state: str(s.state, 64),
            cookie: str(s.cookie, 32),
            inode: int(s.inode),
          }
        : undefined,
    correlated_event_id: /^[0-9a-f]{1,64}$/.test(str(p.correlated_event_id)) ? str(p.correlated_event_id) : undefined,
  };
  // A verified peer without its owner and socket evidence is not verified.
  if (peer.state === 'verified' && (!peer.owner || !peer.socket)) peer.state = 'unknown';
  return peer;
}

export function parseOwnSockets(raw: unknown): OwnSocket[] | undefined {
  if (!Array.isArray(raw)) return;
  return raw.slice(0, 16).map(obj).map((s) => ({
    protocol: str(s.protocol, 8),
    local: str(s.local, 64),
    remote: str(s.remote, 64),
    state: int(s.state),
    cookie: str(s.cookie, 32),
    inode: int(s.inode),
  }));
}

export interface PairAdmission {
  action: 'allow' | 'block';
  until: string;
  local: string;
  remote: string;
  outcome: 'pair' | 'rule';
  configured_action?: 'allow' | 'block';
  configured_rule?: string;
  sentence: string;
}
export interface PairResult {
  events: RequestEvent[];
  incoming_admission?: PairAdmission;
  sentence: string;
}
export function parsePairResult(raw: unknown, event: (v: unknown) => RequestEvent): PairResult | undefined {
  if (raw == null) return;
  const p = obj(raw);
  if (!Array.isArray(p.events) || p.events.length < 1 || p.events.length > 2) throw Error('Invalid pair decision');
  const a = p.incoming_admission == null ? undefined : obj(p.incoming_admission);
  const action = (v: unknown) => (v === 'allow' || v === 'block' ? v : undefined);
  return {
    events: p.events.map(event),
    sentence: str(p.sentence),
    incoming_admission:
      a && action(a.action) && ['pair', 'rule'].includes(str(a.outcome))
        ? {
            action: action(a.action)!,
            until: str(a.until, 64),
            local: str(a.local, 64),
            remote: str(a.remote, 64),
            outcome: str(a.outcome) as 'pair' | 'rule',
            configured_action: action(a.configured_action),
            configured_rule: str(a.configured_rule, 256) || undefined,
            sentence: str(a.sentence),
          }
        : undefined,
  };
}

export interface PairChoice {
  generation: string;
  ids: string[];
  action: 'allow' | 'block';
  scope: 'once';
}
export function validatePairChoice(v: unknown): PairChoice {
  const c = obj(v);
  if (
    Object.keys(c).sort().join(',') !== 'action,generation,ids,scope' ||
    !str(c.generation) ||
    str(c.generation).length > 256 ||
    !Array.isArray(c.ids) ||
    c.ids.length < 1 ||
    c.ids.length > 2 ||
    c.ids.some((id) => typeof id !== 'string' || !/^[0-9a-f]{1,64}$/.test(id)) ||
    new Set(c.ids).size !== c.ids.length ||
    !['allow', 'block'].includes(str(c.action)) ||
    c.scope !== 'once'
  )
    throw Error('Invalid pair decision');
  return { generation: str(c.generation), ids: [...(c.ids as string[])], action: c.action as PairChoice['action'], scope: 'once' };
}

// ---- presentation -------------------------------------------------------

type Ev = Pick<RequestEvent, 'id' | 'state' | 'flow' | 'attribution' | 'local_peer'> & { remainingMs?: number };

function nameOf(app?: { display_name?: string; name?: string; executable?: string }, exe = '') {
  return (
    app?.display_name ||
    (app?.name || '').replace(/ \(deleted\)$/, '') ||
    (app?.executable || exe).split('/').pop() ||
    ''
  );
}
/** The verified game for a provenance (same rule as the prompt heading). */
function gameOf(p?: Provenance) {
  const g = p?.evidence === 'verified' && p.launch?.game?.status === 'verified-file' ? p.launch.game : undefined;
  return g ? (g.title && g.title !== g.name ? `${g.title} · ${g.name}` : g.name) : '';
}
function ownName(e: Ev) {
  return nameOf(e.attribution.application, e.attribution.owners[0]?.executable) || 'Unidentified application';
}
function ownDisplay(e: Ev) {
  const game = gameOf(e.attribution.provenance);
  const own = ownName(e);
  return game ? `${game} (via ${own})` : own;
}
function peerName(p?: LocalPeer) {
  return p?.state === 'verified' && p.owner ? nameOf(p.owner.application, p.owner.executable) || 'Unknown' : '';
}
function peerDisplay(p?: LocalPeer) {
  const name = peerName(p);
  const game = p?.state === 'verified' ? gameOf(p.owner?.provenance) : '';
  return game ? `${game} (via ${name})` : name;
}

export interface PairSide {
  direction: 'outgoing' | 'incoming';
  label: string;
  status: string;
  phase: 'pending' | 'allowed' | 'blocked' | 'ended' | 'not-requested' | 'not-intercepted';
  eventId?: string;
}
export interface LocalPairView {
  title: string;
  line: string;
  verified: boolean;
  unknown?: string;
  sides: PairSide[];
  target: string;
  pairIds?: string[];
  pairNote?: string;
  details: [string, string][];
}

export const PAIR_NOT_REQUESTED = 'Not requested yet (held until the outgoing side is answered)';

function sidePhase(e: Ev): PairSide['phase'] {
  if (e.state === 'awaiting-decision' && (e.remainingMs ?? 1) > 0) return 'pending';
  if (e.state === 'allowed') return 'allowed';
  if (e.state === 'blocked') return 'blocked';
  return 'ended';
}
const phaseText: Record<PairSide['phase'], string> = {
  pending: 'Waiting for a decision',
  allowed: 'Allowed',
  blocked: 'Denied',
  ended: 'Ended (not delivered)',
  'not-requested': PAIR_NOT_REQUESTED,
  'not-intercepted': 'Not asked: no outgoing request was observed for this connection',
};

/** The other request of the same connection, only when BOTH reference each other. */
export function counterpart(e: Ev, events: Ev[]): Ev | undefined {
  const id = e.local_peer?.correlated_event_id;
  if (!id) return;
  const c = events.find((x) => x.id === id);
  return c?.local_peer?.correlated_event_id === e.id ? c : undefined;
}

function peerRow(p: LocalPeer): string {
  const s = p.socket,
    o = p.owner;
  return [
    o ? `${nameOf(o.application, o.executable)} · PID ${o.pid} · start ${o.start_ticks} · UID ${o.uid}` : 'Owner not identified',
    o ? o.application.executable || o.executable : '',
    s ? `${s.kind} socket ${s.local} → ${s.remote} · ${s.state}` : '',
    s ? `cookie ${s.cookie} · inode ${s.inode}` : '',
    gameOf(o?.provenance) ? `Launch: ${gameOf(o?.provenance)} (verified provenance)` : '',
    p.state === 'verified' ? p.evidence || p.reason : p.reason,
  ]
    .filter(Boolean)
    .join('\n');
}

/**
 * Presentation of a same-host request: who connects to whom, both required
 * permissions with their current state, and the explicit target of THIS
 * request's own decision. undefined when the request is not a local one.
 */
export function localPairView(e: Ev, events: Ev[], capabilities: string[] = []): LocalPairView | undefined {
  const peer = e.local_peer;
  if (!peer) return;
  const incoming = e.flow.direction === 'incoming';
  const proto = e.flow.protocol.toUpperCase();
  const other = counterpart(e, events);
  const verified = peer.state === 'verified';
  const client = incoming ? peerDisplay(peer) || 'Unknown local client' : ownDisplay(e);
  const server = incoming ? ownName(e) : peerName(peer) || 'unknown local server';
  const clientShort = incoming ? peerName(peer) || 'unknown local client' : ownName(e);
  const out = incoming ? other : e,
    inc = incoming ? e : other;
  const sides: PairSide[] = [];
  const serverEndpoint = incoming ? e.flow.local : e.flow.remote,
    clientEndpoint = incoming ? e.flow.remote : e.flow.local;
  // Outgoing (client) side.
  const outPhase: PairSide['phase'] = out ? sidePhase(out) : 'not-intercepted';
  sides.push({
    direction: 'outgoing',
    label: `Outgoing: ${clientShort} → ${serverEndpoint}`,
    status: phaseText[outPhase],
    phase: outPhase,
    eventId: out?.id,
  });
  // Incoming (server) side.
  const inPhase: PairSide['phase'] = inc ? sidePhase(inc) : 'not-requested';
  sides.push({
    direction: 'incoming',
    label: `Incoming: ${server} ← ${clientShort} (${clientEndpoint})`,
    status: phaseText[inPhase],
    phase: inPhase,
    eventId: inc?.id,
  });
  const target = incoming
    ? `This request's permission: incoming to ${server} only. It is not an outgoing permission for ${clientShort}.`
    : `This request's permission: outgoing for ${clientShort} only. It is not an incoming permission for ${server}.`;
  const view: LocalPairView = {
    title: `${client} → ${server}`,
    line: `${incoming ? 'Incoming to' : 'Outgoing to'} ${server} · ${proto} · local`,
    verified,
    unknown: verified ? undefined : peer.reason || (incoming ? 'Local client unknown' : 'Local server unknown'),
    sides,
    target,
    details: [],
  };
  // One Allow/Deny answers both hooks of this exact connection (Once), offered
  // only for a backend-confirmed pair; the note is a Details field, never the first view.
  if (capabilities.includes(LOCAL_PAIR_CAPABILITY)) {
    if (other && out && inc && [out, inc].some((x) => sidePhase(x) === 'pending')) {
      view.pairIds = [out.id, inc.id];
      view.pairNote = 'Allow/Deny (Once) answers the waiting side of this one connection; a side already decided keeps its verdict.';
    } else if (!incoming && !other && verified && peer.role === 'server' && sidePhase(e) === 'pending') {
      view.pairIds = [e.id];
      view.pairNote = `Allow/Deny (Once) also answers the incoming side at ${server} for this same connection only; an existing rule for that side still decides it and is reported.`;
    }
  }
  const sockets = e.attribution.sockets ?? [];
  view.details.push([
    'This socket',
    `${ownName(e)} · ${e.flow.local} ${incoming ? '←' : '→'} ${e.flow.remote}` +
      (sockets.length ? '\n' + sockets.map((s) => `cookie ${s.cookie} · inode ${s.inode}`).join('\n') : ''),
  ]);
  view.details.push([incoming ? 'Local client' : 'Local server', peerRow(peer)]);
  if (other?.local_peer) view.details.push([incoming ? 'Paired request' : 'Paired request', `${other.flow.direction} request ${other.id} (exact reversed tuple; same connection)`]);
  return view;
}

/** Short text for a pair decision result; both verdicts, never only one. */
export function pairResultText(r: PairResult): string {
  const verdict = (s: string) => (s === 'allowed' ? 'Allowed' : s === 'blocked' ? 'Denied' : s);
  const parts = r.events.map((e) => `${e.flow.direction === 'outgoing' ? 'Outgoing' : 'Incoming'}: ${verdict(e.state)}`);
  const a = r.incoming_admission;
  if (a)
    parts.push(
      a.outcome === 'rule'
        ? `Incoming: ${a.configured_action === 'block' ? 'Denied' : 'Allowed'} by rule ${a.configured_rule} (not by this decision)`
        : `Incoming: ${a.action === 'allow' ? 'Allowed' : 'Denied'} once when it arrives`,
    );
  return parts.join(' · ');
}

/** Details rows of a local connection: both sides, their states, the evidence. */
export function pairDetailRows(v: LocalPairView): [string, string][] {
  return [
    ['Connection', v.title + (v.unknown ? '\n' + v.unknown : '')],
    ...v.sides.map((s): [string, string] => [s.direction === 'outgoing' ? 'Outgoing side' : 'Incoming side', `${s.label}\n${s.status}`]),
    ['This request', v.target],
    ...(v.pairNote ? [['Once', v.pairNote] as [string, string]] : []),
    ...v.details,
  ];
}

/** Changes that must rebuild the pair section (states of both sides). */
export function pairSignature(e: Ev, events: Ev[]): string {
  const o = counterpart(e, events);
  return JSON.stringify([e.local_peer, o?.id, o?.state, o?.local_peer?.correlated_event_id]);
}

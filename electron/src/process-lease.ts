import { accountLabel } from './accounts';
// decision-for-a-while-v1 (NetLimiter 5.3.28 "For a while"): the backend decides
// the current request like Once and keeps an in-memory process-instance lease
// (same direction, exactly this verified process instance, all addresses and
// ports). The UI defaults to one hour when duration selection is supported. It is
// never a rule. The UI only displays leases the backend lists.
export const FOR_A_WHILE_CAPABILITY = 'decision-for-a-while-v1';
// Legacy wire default and popup inspection hold; do not change for old backends.
export const FOR_A_WHILE_SECONDS = 15;
export const DEFAULT_FOR_A_WHILE_SECONDS = 3600;
// Initial explanation; the renderer fills in the selected duration.
export const FOR_A_WHILE_NOTE = 'This process instance · all remote addresses and ports · this direction · not saved as a rule.';
export const FOR_A_WHILE_TOOLTIP =
  'Allow or deny this connection and new TCP/UDP connections from this process to any address and port for the selected duration. Ends if the process exits. Not saved as a rule.';
export const forAWhileSupported = (capabilities?: string[]) =>
  !!capabilities?.includes(FOR_A_WHILE_CAPABILITY);

// decision-for-a-while-durations-v1 (FlowGate extension; NetLimiter's popup has
// no duration selector): the backend's exact allowed set. The backend's
// returned `until` is the authority; local arithmetic is only a preview.
export const FOR_A_WHILE_DURATIONS_CAPABILITY = 'decision-for-a-while-durations-v1';
export const FOR_A_WHILE_DURATION_CHOICES = [15, 60, 300, 600, 1800, 3600] as const;
export function durationLabel(seconds: number) {
  if (seconds >= 3600 && seconds % 3600 === 0) return seconds === 3600 ? '1 h' : `${seconds / 3600} h`;
  if (seconds >= 60 && seconds % 60 === 0) return `${seconds / 60} min`;
  return `${seconds} s`;
}
// Durations offered for this backend: its advertised list restricted to the
// known set; without the capability only the fixed 15 s exists.
export function forAWhileDurations(control: { capabilities?: string[]; forAWhileDurations?: number[] }) {
  if (!control.capabilities?.includes(FOR_A_WHILE_DURATIONS_CAPABILITY)) return [FOR_A_WHILE_SECONDS];
  const offered = (control.forAWhileDurations ?? []).filter((d) =>
    (FOR_A_WHILE_DURATION_CHOICES as readonly number[]).includes(d),
  );
  return offered.length ? offered : [FOR_A_WHILE_SECONDS];
}
// Preserve an explicit choice; otherwise default to one hour when supported.
export function defaultForAWhile(saved: unknown, allowed: number[]) {
  return typeof saved === 'number' && allowed.includes(saved) ? saved : allowed.includes(DEFAULT_FOR_A_WHILE_SECONDS) ? DEFAULT_FOR_A_WHILE_SECONDS : allowed.includes(FOR_A_WHILE_SECONDS) ? FOR_A_WHILE_SECONDS : allowed[0];
}
export const validForAWhileSeconds = (v: unknown) =>
  typeof v === 'number' && (FOR_A_WHILE_DURATION_CHOICES as readonly number[]).includes(v);
// Shown before the click: the expiry the selection would produce (preview only).
export function expiryPreview(seconds: number, now: number) {
  const until = new Date(now + seconds * 1000),
    two = (n: number) => String(n).padStart(2, '0');
  return `until ${two(until.getHours())}:${two(until.getMinutes())}${seconds < 60 ? ':' + two(until.getSeconds()) : ''}`;
}
export function forAWhileNote(seconds: number) {
  return `For ${durationLabel(seconds)} · this process instance · all remote addresses and ports · this direction · ends early if it exits · not saved as a rule.`;
}

// NetLimiter 5.3.28 (observed): "Allow | Deny | ☐ Remember | ☐ For a while";
// checking either option unchecks the other (and For a while collapses the
// Remember panel). Kept in this one constant so it can be changed; if it is
// ever false, Remember takes precedence when deciding.
export const DECISION_OPTIONS_EXCLUSIVE = true;
export interface DecisionOptions {
  forAWhile: boolean;
  remember: boolean;
}
export function toggleDecisionOption(
  current: DecisionOptions,
  option: keyof DecisionOptions,
  checked: boolean,
  exclusive = DECISION_OPTIONS_EXCLUSIVE,
): DecisionOptions {
  const next = { ...current, [option]: checked };
  if (exclusive && checked) next[option === 'forAWhile' ? 'remember' : 'forAWhile'] = false;
  return next;
}

export interface ProcessLease {
  id: string;
  action: 'allow' | 'block';
  direction: string;
  application: string;
  executable: string;
  uid: number;
  pid: number;
  start: string;
  until: string;
  remaining_ms: number;
  // Authoritative lease duration (seconds) from the backend.
  seconds: number;
  event_id: string;
}
const obj = (v: unknown): Record<string, unknown> =>
  v && typeof v === 'object' ? (v as Record<string, unknown>) : {};
const text = (v: unknown, max = 4096) =>
  typeof v === 'string' && v.length <= max ? v : typeof v === 'number' && Number.isFinite(v) ? String(v) : '';
function applicationName(v: unknown) {
  if (typeof v === 'string') return v.slice(0, 1024);
  const a = obj(v);
  return text(a.display_name, 1024) || text(a.name, 1024).replace(/ \(deleted\)$/, '');
}
// Invalid entries are dropped individually: a malformed lease never hides the others.
export function parseProcessLeases(raw: unknown): ProcessLease[] | undefined {
  if (!Array.isArray(raw)) return undefined;
  const leases: ProcessLease[] = [];
  for (const item of raw.slice(0, 256)) {
    const l = obj(item);
    const id = text(l.id, 256),
      until = text(l.until, 64);
    if (
      !id ||
      !['allow', 'block'].includes(String(l.action)) ||
      !Number.isFinite(Date.parse(until)) ||
      !Number.isSafeInteger(l.pid) ||
      Number(l.pid) <= 0
    )
      continue;
    leases.push({
      id,
      action: l.action as 'allow' | 'block',
      direction: text(l.direction, 32),
      application: text(l.application_name, 1024) || applicationName(l.application),
      executable: text(l.executable),
      uid: Number.isSafeInteger(l.uid) ? Number(l.uid) : -1,
      pid: Number(l.pid),
      start: text(l.start, 64),
      until,
      remaining_ms: Number.isFinite(l.remaining_ms) ? Math.max(0, Number(l.remaining_ms)) : 0,
      seconds: Number.isSafeInteger(l.seconds) && Number(l.seconds) > 0 ? Number(l.seconds) : FOR_A_WHILE_SECONDS,
      event_id: text(l.event_id, 256),
    });
  }
  return leases;
}
// The decided event's own lease reference ("lease": {id, until}).
export function parseLeaseRef(raw: unknown): { id: string; until: string } | undefined {
  const l = obj(raw),
    id = text(l.id, 256),
    until = text(l.until, 64);
  return id && Number.isFinite(Date.parse(until)) ? { id, until } : undefined;
}
// Backend `until` against the backend clock; never extended locally.
export const leaseRemainingMs = (lease: { until: string }, now: number) =>
  Math.max(0, Date.parse(lease.until) - now);
export const activeLeases = (leases: ProcessLease[] | undefined, now: number) =>
  (leases ?? []).filter((l) => leaseRemainingMs(l, now) > 0);
const shortDirection = (d: string) => (d === 'incoming' ? 'In' : d === 'outgoing' ? 'Out' : d || '?');
export function remainingText(ms: number) {
  const s = Math.ceil(ms / 1000);
  if (s < 120) return `${s} s left`;
  if (s < 7200) return `${Math.ceil(s / 60)} min left`;
  return `${Math.ceil(s / 3600)} h left`;
}
// Countdown from the backend's `until` (never extended locally).
export function leaseLine(lease: ProcessLease, now: number) {
  return `For a while: ${lease.action === 'allow' ? 'Allow' : 'Deny'} · process ${lease.pid} · ${shortDirection(lease.direction)} · ${remainingText(leaseRemainingMs(lease, now))}`;
}
export function leaseDetails(lease: ProcessLease): [string, string][] {
  const until = new Date(lease.until);
  return [
    ['Application', lease.application || 'Unknown'],
    ['Executable', lease.executable || 'Unknown'],
    ['Process', `PID ${lease.pid}${lease.start ? ' · start ' + lease.start : ''}`],
    ['UID', accountLabel(lease.uid).replace(/^UID /, '')],
    ['Direction', lease.direction === 'incoming' ? 'Incoming' : lease.direction === 'outgoing' ? 'Outgoing' : lease.direction || 'Unknown'],
    ['Action', lease.action === 'allow' ? 'Allow' : 'Deny'],
    ['Duration', durationLabel(lease.seconds)],
    ['Expires', `${until.toLocaleTimeString()} (${lease.until}) · earlier if the process exits`],
    ['Scope', 'This process instance only, same direction, all remote addresses and ports, TCP and UDP. Not saved as a rule.'],
  ];
}
// Leases relevant to one request card: its own decision, or the same process instance.
export function leasesForRequest(
  leases: ProcessLease[] | undefined,
  e: { id: string; attribution: { owners: { pid: number; start_ticks?: unknown }[] } } | undefined,
  now: number,
) {
  if (!e) return [];
  const owner = e.attribution.owners.length === 1 ? e.attribution.owners[0] : undefined;
  return activeLeases(leases, now).filter(
    (l) =>
      l.event_id === e.id ||
      (!!owner && l.pid === owner.pid && (!l.start || !owner.start_ticks || l.start === String(owner.start_ticks))),
  );
}
// The permission window stays on a request decided "For a while" while its
// lease is active (and nothing else is waiting), so the lease stays inspectable.
export function leaseHolds(
  control: {
    processLeases?: ProcessLease[];
    serverNow?: number;
    events: { id: string; lease?: { id: string; until: string } }[];
  },
  eventID: string,
  now = control.serverNow ?? Date.now(),
) {
  const listed = control.processLeases;
  // Long leases (up to 1 h) keep the card only for the first 15 s; the lease
  // stays listed under Temporary decisions for its whole duration.
  const mine = listed?.find((l) => l.event_id === eventID && leaseRemainingMs(l, now) > 0);
  if (mine) return Date.parse(mine.until) - mine.seconds * 1000 + FOR_A_WHILE_SECONDS * 1000 > now;
  const own = control.events.find((e) => e.id === eventID)?.lease;
  // Before the first list after the decision, the decided event's lease reference.
  return !!own && leaseRemainingMs(own, now) > 0;
}

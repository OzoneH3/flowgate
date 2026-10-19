// decision-for-a-while-v1 (NetLimiter 5.3.28 "For a while"): the backend decides
// the current request like Once and keeps an in-memory process-instance lease
// (same direction, exactly this verified process instance, fixed 15 s). It is
// never a rule. The UI only displays leases the backend lists.
export const FOR_A_WHILE_CAPABILITY = 'decision-for-a-while-v1';
export const FOR_A_WHILE_SECONDS = 15;
// One-line explanation shown while For a while is checked (it has no duration control).
export const FOR_A_WHILE_NOTE = 'For 15 seconds · this process instance · this direction · not saved as a rule.';
export const FOR_A_WHILE_TOOLTIP =
  'Allow or deny this connection and new connections from this process for 15 seconds. Not saved as a rule.';
export const forAWhileSupported = (capabilities?: string[]) =>
  !!capabilities?.includes(FOR_A_WHILE_CAPABILITY);

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
export function leaseLine(lease: ProcessLease, now: number) {
  return `For a while: ${lease.action === 'allow' ? 'Allow' : 'Deny'} · process ${lease.pid} · ${shortDirection(lease.direction)} · ${Math.ceil(leaseRemainingMs(lease, now) / 1000)} s left`;
}
export function leaseDetails(lease: ProcessLease): [string, string][] {
  const until = new Date(lease.until);
  return [
    ['Application', lease.application || 'Unknown'],
    ['Executable', lease.executable || 'Unknown'],
    ['Process', `PID ${lease.pid}${lease.start ? ' · start ' + lease.start : ''}`],
    ['UID', lease.uid >= 0 ? String(lease.uid) : 'Unknown'],
    ['Direction', lease.direction === 'incoming' ? 'Incoming' : lease.direction === 'outgoing' ? 'Outgoing' : lease.direction || 'Unknown'],
    ['Action', lease.action === 'allow' ? 'Allow' : 'Deny'],
    ['Expires', `${until.toLocaleTimeString()} (${lease.until})`],
    ['Scope', 'This process instance only, same direction. Not saved as a rule.'],
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
  if (listed?.some((l) => l.event_id === eventID && leaseRemainingMs(l, now) > 0)) return true;
  const own = control.events.find((e) => e.id === eventID)?.lease;
  // Before the first list after the decision, the decided event's lease reference.
  return !!own && leaseRemainingMs(own, now) > 0;
}

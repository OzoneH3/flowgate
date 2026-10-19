import {
  canDecide,
  validateDecision,
  type ClientState,
  type RequestEvent,
  type Rule,
  type ViewEvent,
} from './protocol';
import { reviewFailureOf } from './decision-remember';
import type { RequestRef } from './notifications';
export interface RequestGroup {
  key: string;
  // Oldest awaiting request without a local attempt (else the oldest): the one
  // card shown and the only event a decision targets. Never fanned out.
  representative: ViewEvent;
  events: ViewEvent[];
  count: number;
}
// Backend `request_group` joins equivalent repeats; without it each event is its own group.
export const groupKey = (e: { id: string; request_group?: string }) =>
  e.request_group ? 'g:' + e.request_group : 'e:' + e.id;
export const awaiting = (e: ViewEvent) => e.state === 'awaiting-decision' && e.remainingMs > 0 && !reviewFailureOf(e);
const age = (e: ViewEvent) => {
  const t = Date.parse(e.first_seen);
  return Number.isFinite(t) ? t : Date.parse(e.deadline);
};
// Only requests still awaiting a decision: settled (re-evaluated after policy
// change), finalized, decided and expired requests leave the list immediately.
export function requestGroups(events: ViewEvent[]): RequestGroup[] {
  const groups = new Map<string, ViewEvent[]>();
  for (const e of events) {
    if (!awaiting(e)) continue;
    const key = groupKey(e),
      list = groups.get(key);
    if (list) list.push(e);
    else groups.set(key, [e]);
  }
  return [...groups]
    .map(([key, list]) => {
      const sorted = list
        .map((e, i) => [e, i] as const)
        .sort(([a, i], [b, j]) => age(a) - age(b) || i - j)
        .map(([e]) => e);
      return {
        key,
        representative: sorted.find((e) => !e.attempt) ?? sorted[0],
        events: sorted,
        count: sorted.length,
      };
    })
    .sort((a, b) => age(a.events[0]) - age(b.events[0]));
}
// stored-ask-v1: which rule caused the prompt. Rules have no names; the id is the name.
export function askSource(e: RequestEvent, rules?: Rule[]) {
  if (!e.ask_rule) return 'No matching rule (default Ask)';
  const r = rules?.find((r) => r.id === e.ask_rule!.id);
  if (!r) return `Asked by rule ${e.ask_rule.id}`;
  const f = r.filter,
    target = f.process
      ? 'process'
      : f.all_programs
        ? 'zone'
        : f.protocol === '*' &&
            (!f.remote_address || f.remote_address === '*') &&
            !f.remote &&
            !f.local_port &&
            !f.remote_port
          ? 'application'
          : 'scoped',
    direction =
      f.direction === 'incoming' ? 'In' : f.direction === 'outgoing' ? 'Out' : f.direction || 'any';
  return `Asked by rule ${r.id} (Ask, ${target}, ${direction})`;
}
export function groupOf(state: ClientState, id: string) {
  const e = state.control.events.find((e) => e.id === id);
  return e ? groupKey(e) : undefined;
}
// One foreground card at a time (NetLimiter): the representative of the oldest
// group. A dismissed group never auto-opens again in that daemon generation.
export class AutomaticPrompts {
  private dismissed = new Map<string, true>();
  private key = (generation: string, group: string) => generation + '\0' + group;
  dismiss(ref: RequestRef) {
    if (!ref.group) return;
    const key = this.key(ref.generation, ref.group);
    this.dismissed.delete(key);
    this.dismissed.set(key, true);
    while (this.dismissed.size > 512) this.dismissed.delete(this.dismissed.keys().next().value!);
  }
  next(state: ClientState, occupied: boolean): RequestRef | undefined {
    // After an unknown/rejected outcome nothing new is presented until an
    // authoritative list issued after it was read (queue reconciliation).
    if (occupied || !canDecide(state.control) || state.control.reconciling) return;
    const g = requestGroups(state.control.events).find(
      (g) =>
        !g.representative.attempt && !this.dismissed.has(this.key(state.control.generation, g.key)),
    );
    return g && { generation: state.control.generation, id: g.representative.id, group: g.key };
  }
  // The open card after a state update: the same ref while its request still
  // awaits; else the group's next representative (advance); else undefined (close).
  follow(state: ClientState, ref: RequestRef): RequestRef | undefined {
    if (state.control.generation !== ref.generation) return;
    const e = state.control.events.find((e) => e.id === ref.id);
    if (e && (reviewFailureOf(e) || awaiting(e) || e.attempt?.phase === 'unknown' || e.attempt?.phase === 'submitting'))
      return ref;
    // An ended request whose retained record still offers Remember / For a while keeps its
    // card until the user moves on (Next request / Close) or the backend stops listing it.
    // A waiting request always wins (paced): the ended one stays reachable from Pending requests.
    if (
      e &&
      e.request_rule?.available &&
      !state.control.events.some((x) => x.id !== e.id && awaiting(x))
    )
      return ref;
    if (!canDecide(state.control)) return;
    // Never advance to another request before reconciliation completed.
    if (state.control.reconciling) return e ? ref : undefined;
    const group = ref.group ?? (e ? groupKey(e) : undefined),
      g = requestGroups(state.control.events).find((g) => g.key === group);
    return g && !g.representative.attempt
      ? { generation: ref.generation, id: g.representative.id, group: g.key }
      : undefined;
  }
}
// The input-release + pacing guard shared by every automatic presentation or
// advance: never under the click/keypress that answered the previous request.
export function inputSettled(g: {
  now: number;
  transitionUntil: number;
  keys: number;
  rendererKeys: number;
  pointerDown: boolean;
}) {
  return !(g.now < g.transitionUntil || g.keys > 0 || g.rendererKeys > 0 || g.pointerDown);
}
export function edgePosition(
  area: { x: number; y: number; width: number; height: number },
  width: number,
  height: number,
) {
  return {
    x: area.x + Math.max(0, area.width - width),
    y: area.y + Math.max(0, area.height - height),
    width: Math.min(width, area.width),
    height: Math.min(height, area.height),
  };
}

export function boundDecision(value: unknown, ref?: RequestRef) {
  const decision = validateDecision(value);
  if (ref && (decision.id !== ref.id || decision.generation !== ref.generation))
    throw Error('Decision does not belong to this permission window');
  return decision;
}

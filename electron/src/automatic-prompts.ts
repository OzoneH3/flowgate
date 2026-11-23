import {
  canDecide,
  canManageRules,
  validateDecision,
  type ClientState,
  type Decision,
  type RequestEvent,
  type Rule,
  type ViewEvent,
} from './protocol';
import { REQUEST_RULE_CAPABILITY, requestRuleAvailable } from './request-rule';
import { REMEMBER_DURATIONS, reviewFailureOf } from './decision-remember';
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
export interface QueuedRememberSelection {
  field: 'address' | 'port' | 'endpoint';
  duration: number;
}
export function queuedRememberSelection(choice: Decision): QueuedRememberSelection | undefined {
  const fields = choice.remember;
  if (!fields || fields.process || fields.protocol || (!fields.address && !fields.port)) return;
  const field = fields.address && fields.port ? 'endpoint' : fields.address ? 'address' : 'port';
  if (choice.scope === 'persistent') return { field, duration: 0 };
  if (choice.scope !== 'application' || !choice.duration_seconds) return;
  const preset = REMEMBER_DURATIONS.find(({ seconds }) => seconds === choice.duration_seconds);
  if (preset) return { field, duration: preset.seconds };
}
// Capture already-waiting peers before submitting a scoped choice. Carry the
// settings alone so the next card gets its own endpoint and review.
export function queuedRemember(state: ClientState, choice: Decision) {
  const selection = queuedRememberSelection(choice);
  if (state.control.generation !== choice.generation || !selection) return;
  const events = state.control.events;
  const source = events.find((e) => e.id === choice.id);
  if (
    !source?.ask_rule || source.flow.direction !== 'outgoing' || source.flow.protocol !== 'tcp' ||
    !source.attribution.visibility_complete || source.attribution.owners.length !== 1
  ) return;
  const [owner] = source.attribution.owners;
  const ask = source.ask_rule;
  const filter = source.remembered_filter;
  if (!owner.start_ticks || !filter?.application || !filter.revision || !filter.remote_address) return;
  const matches = (e: ViewEvent) => {
    if (
      e.id === source.id || !awaiting(e) || e.attempt || !e.scope_previews[choice.scope] ||
      e.ask_rule?.id !== ask.id || e.ask_rule.version !== ask.version ||
      e.flow.direction !== source.flow.direction || e.flow.protocol !== source.flow.protocol ||
      e.flow.netns !== source.flow.netns ||
      !e.attribution.visibility_complete || e.attribution.owners.length !== 1
    ) return false;
    const [peer] = e.attribution.owners;
    const target = e.remembered_filter;
    if (!target?.remote_address) return false;
    const addressChanged = target.remote_address !== filter.remote_address;
    const portsKnown = !!filter.remote_port && !!target.remote_port;
    const portChanged = portsKnown && target.remote_port !== filter.remote_port;
    const nextEndpoint = selection.field === 'address' ? addressChanged :
      selection.field === 'port' ? portChanged : portsKnown && (addressChanged || portChanged);
    return peer.pid === owner.pid && peer.start_ticks === owner.start_ticks && peer.uid === owner.uid &&
      target.application === filter.application && target.revision === filter.revision &&
      target.uid === filter.uid && nextEndpoint &&
      e.attribution.permission_target?.prefix === source.attribution.permission_target?.prefix &&
      e.attribution.runtime_table?.prefix === source.attribution.runtime_table?.prefix;
  };
  const ids = new Set(events.filter(matches).map((e) => e.id));
  if (!ids.size) return;
  return (generation: string, event: ViewEvent) =>
    generation === choice.generation && ids.has(event.id) && matches(event) ? selection : undefined;
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
  next(state: ClientState, occupied: boolean, minimumRemainingMs = 0): RequestRef | undefined {
    // After an unknown/rejected outcome nothing new is presented until an
    // authoritative list issued after it was read (queue reconciliation).
    if (occupied || !canDecide(state.control) || state.control.reconciling || state.control.events.some(e=>e.attempt?.phase==='submitting')) return;
    const g = requestGroups(state.control.events).find(
      (g) =>
        !g.representative.attempt && g.representative.remainingMs > minimumRemainingMs &&
        !this.dismissed.has(this.key(state.control.generation, g.key)),
    );
    return g && { generation: state.control.generation, id: g.representative.id, group: g.key };
  }
  // While the window is already open, use the next actionable card directly
  // if the old one settled. A replaced daemon still gets a separate reveal.
  continueVisible(state: ClientState, ref: RequestRef, reviewingRemember: boolean, minimumRemainingMs: number) {
    const c = state.control;
    if (c.generation !== ref.generation) return;
    const current = c.events.find((e) => e.id === ref.id);
    // Keep an already presented card through expiry when it still has an
    // application-rule target. The clock can reach zero before the next
    // daemon list publishes the terminal state and enables the reviewed action.
    if (canManageRules(c) && current && (current.state === 'awaiting-decision' || current.state === 'expired') &&
        (requestRuleAvailable(current, c.capabilities) ||
          (current.state === 'awaiting-decision' && current.remainingMs <= 0 &&
            current.request_rule?.available && c.capabilities?.includes(REQUEST_RULE_CAPABILITY))))
      return ref;
    const next = this.follow(state, ref, reviewingRemember);
    if (next?.id === ref.id) return next;
    if (next && state.control.events.some((e) => e.id === next.id && e.remainingMs > minimumRemainingMs))
      return next;
    return this.next(state, false, minimumRemainingMs);
  }
  // The open card after a state update: the same ref while its request still
  // awaits; else the group's next representative (advance); else undefined (close).
  follow(state: ClientState, ref: RequestRef, reviewingRemember = false): RequestRef | undefined {
    if (state.control.generation !== ref.generation) return;
    const e = state.control.events.find((e) => e.id === ref.id);
    if (e && (e.attempt?.phase === 'unknown' || e.attempt?.phase === 'submitting')) return ref;
    if (e && awaiting(e)) return ref;
    // Explicit Remember review survives a short-lived socket. Only future-rule
    // actions remain possible; the ended flow is never released.
    if (reviewingRemember && e && requestRuleAvailable(e, state.control.capabilities)) return ref;
    // Ended/settled cards remain inspectable in Pending requests, but never
    // occupy the automatic popup with disabled decision controls.
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
// Initial permission window size; content can expand the height.
export const PROMPT_WIDTH = 745,
  PROMPT_HEIGHT = 590,
  PROMPT_MIN_HEIGHT = 240;
export function compactPromptBounds(
  area: Parameters<typeof edgePosition>[0],
  unanchoredWayland: boolean,
) {
  // A Wayland work area can describe the whole output before the compositor
  // places the window under its desktop chrome. Leave clearance on short
  // outputs so the fixed footer fits even with a late placement adjustment.
  const height = unanchoredWayland
    ? Math.min(PROMPT_HEIGHT, Math.max(PROMPT_MIN_HEIGHT, area.height - 64))
    : PROMPT_HEIGHT;
  return edgePosition(area, PROMPT_WIDTH, height);
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

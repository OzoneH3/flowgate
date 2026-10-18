import { canDecide, validateDecision, type ClientState } from './protocol';
import type { RequestRef } from './notifications';
// One foreground request, pinned until closed. A dismissed request never auto-opens again.
export class AutomaticPrompts {
  private shown = new Map<string, true>();
  mark(ref: RequestRef) {
    const key = ref.generation + '\0' + ref.id;
    this.shown.delete(key);
    this.shown.set(key, true);
    while (this.shown.size > 512) this.shown.delete(this.shown.keys().next().value!);
  }
  next(state: ClientState, occupied: boolean): RequestRef | undefined {
    if (occupied || !canDecide(state.control)) return;
    const e = state.control.events.find(
      (e) =>
        e.state === 'awaiting-decision' &&
        e.remainingMs > 0 &&
        !e.attempt &&
        !this.shown.has(state.control.generation + '\0' + e.id),
    );
    if (!e) return;
    const ref = { generation: state.control.generation, id: e.id };
    this.mark(ref);
    return ref;
  }
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

import type { ClientState, ViewEvent } from './protocol';
export interface RequestRef {
  generation: string;
  id: string;
}
export interface Notice {
  on(event: 'click' | 'close' | 'failed', fn: (...args: unknown[]) => void): unknown;
  show(): void;
  close(): void;
}
export interface NoticeContent {
  title: string;
  body: string;
}
const key = (r: RequestRef) => r.generation + '\0' + r.id;
// Desktop notification daemons may interpret body markup: remove markup delimiters
// and control characters rather than passing backend text as formatting.
export const plain = (s: string, max = 110) =>
  s
    .replace(/[<>\x00-\x1f\x7f]/g, ' ')
    .replace(/\s+/g, ' ')
    .slice(0, max);
export function pending(state: ClientState) {
  return state.control.connected
    ? state.control.events.filter((e) => e.state === 'awaiting-decision' && e.remainingMs > 0)
    : [];
}
export class RequestNotifications {
  private seen = new Map<string, true>();
  private queued = new Map<string, RequestRef>();
  private live = new Map<Notice, RequestRef | undefined>();
  private next = 0;
  status = 'Notifications follow desktop delivery and Do Not Disturb settings.';
  constructor(
    private supported: () => boolean,
    private create: (content: NoticeContent) => Notice,
    private review: (ref?: RequestRef) => void,
    private now = () => Date.now(),
  ) {}
  update(state: ClientState, active: boolean) {
    const events = state.control.readOnly ? [] : pending(state).filter((e) => !e.attempt),
      current = new Map(
        events.map((e) => [key({ generation: state.control.generation, id: e.id }), e]),
      );
    for (const [n, ref] of this.live)
      if (!state.control.connected || active || !events.length || (ref && !current.has(key(ref)))) {
        this.live.delete(n);
        n.close();
      }
    for (const k of this.queued.keys()) if (!current.has(k) || active) this.queued.delete(k);
    for (const e of events) {
      const ref = { generation: state.control.generation, id: e.id },
        k = key(ref),
        fresh = !this.seen.has(k);
      this.seen.delete(k);
      this.seen.set(k, true);
      if (fresh && !active) this.queued.set(k, ref);
    }
    while (this.seen.size > 512) this.seen.delete(this.seen.keys().next().value!);
    while (this.queued.size > 256) this.queued.delete(this.queued.keys().next().value!);
    if (!this.supported()) {
      this.queued.clear();
      this.status = 'Desktop notifications unavailable. Use the tray pending list.';
      return;
    }
    if (active || !this.queued.size || this.now() < this.next) return;
    const refs = [...this.queued.values()];
    this.queued.clear();
    this.next = this.now() + 3000;
    const ref = refs.length === 1 ? refs[0] : undefined,
      e = ref ? current.get(key(ref)) : undefined;
    const content = e
      ? this.content(e)
      : {
          title: `FlowGate · ${events.length} pending requests`,
          body: 'Several connections need review. Open the current pending list. No decision has been sent.',
        };
    try {
      while (this.live.size >= 3) {
        const old = this.live.keys().next().value!;
        this.live.delete(old);
        old.close();
      }
      const n = this.create(content);
      this.live.set(n, ref);
      n.on('click', () => {
        this.live.delete(n);
        this.review(ref);
      });
      n.on('close', () => this.live.delete(n));
      n.on('failed', () => {
        this.live.delete(n);
        this.status = 'Desktop notification delivery failed. Requests remain in the pending list.';
      });
      this.status =
        'Notifications requested when inactive; desktop settings control delivery. Pending list remains authoritative.';
      n.show();
    } catch {
      this.status = 'Desktop notification delivery failed. Requests remain in the pending list.';
    }
  }
  private content(e: ViewEvent): NoticeContent {
    return {
      title:
        'FlowGate · ' +
        plain(
          e.attribution.application?.name ||
            e.attribution.application?.executable ||
            'Unidentified application',
          70,
        ),
      body: `${plain(e.flow.direction, 16)} ${plain(e.flow.protocol, 8).toUpperCase()} · ${plain(e.flow.remote, 100)}\nReview this request in FlowGate.`,
    };
  }
  close() {
    for (const n of this.live.keys()) n.close();
    this.live.clear();
    this.queued.clear();
    this.seen.clear();
  }
  // Bounded diagnostics for unit tests; not exposed to the renderer.
  counts() {
    return { seen: this.seen.size, queued: this.queued.size, live: this.live.size };
  }
}

import { canDecide } from './protocol';
import type { ClientState, ViewEvent } from './protocol';
import { requestGroups, type RequestGroup } from './automatic-prompts';
export interface RequestRef {
  generation: string;
  id: string;
  // Request group key (automatic-prompts groupKey); the id is its representative.
  group?: string;
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
const key = (generation: string, group: string) => generation + '\0' + group;
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
  private deliveryStatus = 'Notifications follow desktop delivery and Do Not Disturb settings.';
  constructor(
    private supported: () => boolean,
    private create: (content: NoticeContent) => Notice,
    private review: (ref?: RequestRef) => void,
    private now = () => Date.now(),
    private enabled = true,
  ) {}
  status(trayAvailable: boolean) {
    if (!this.enabled)
      return `System notifications off; permission requests use the popup${trayAvailable ? ' and tray' : ''}.`;
    if (!this.supported())
      return trayAvailable
        ? 'Desktop notifications unavailable. Use the tray pending list.'
        : 'Desktop notifications unavailable. Permission requests use the popup.';
    return this.deliveryStatus;
  }
  // One notice per request group: 51 identical attempts are one request.
  update(state: ClientState, active: boolean) {
    if (!this.enabled) {
      this.close();
      return;
    }
    const generation = state.control.generation,
      groups = !canDecide(state.control)
        ? []
        : requestGroups(pending(state)).filter((g) => !g.representative.attempt),
      current = new Map(groups.map((g) => [key(generation, g.key), g]));
    for (const [n, ref] of this.live)
      if (
        !state.control.connected ||
        active ||
        !groups.length ||
        (ref && !current.has(key(ref.generation, ref.group!)))
      ) {
        this.live.delete(n);
        n.close();
      }
    for (const k of this.queued.keys()) if (!current.has(k) || active) this.queued.delete(k);
    for (const g of groups) {
      const k = key(generation, g.key),
        fresh = !this.seen.has(k);
      this.seen.delete(k);
      this.seen.set(k, true);
      if (fresh && !active)
        this.queued.set(k, { generation, id: g.representative.id, group: g.key });
    }
    while (this.seen.size > 512) this.seen.delete(this.seen.keys().next().value!);
    while (this.queued.size > 256) this.queued.delete(this.queued.keys().next().value!);
    if (!this.supported()) {
      this.queued.clear();
      return;
    }
    if (active || !this.queued.size || this.now() < this.next) return;
    const refs = [...this.queued.values()];
    this.queued.clear();
    this.next = this.now() + 3000;
    const queued = refs.length === 1 ? current.get(key(generation, refs[0].group!)) : undefined,
      ref = queued && { generation, id: queued.representative.id, group: queued.key },
      attempts = groups.reduce((n, g) => n + g.count, 0);
    const content = queued
      ? this.content(queued)
      : {
          title: `FlowGate · ${groups.length} pending requests`,
          body: `${attempts} connection attempts need review. Open the current pending list. No decision has been sent.`,
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
        this.deliveryStatus = 'Desktop notification delivery failed. Requests remain in the pending list.';
      });
      this.deliveryStatus =
        'Notifications requested when inactive; desktop settings control delivery. Pending list remains authoritative.';
      n.show();
    } catch {
      this.deliveryStatus = 'Desktop notification delivery failed. Requests remain in the pending list.';
    }
  }
  private content(g: RequestGroup): NoticeContent {
    const e: ViewEvent = g.representative;
    return {
      title:
        'FlowGate · ' +
        plain(
          e.attribution.application?.name ||
            e.attribution.application?.executable ||
            'Unidentified application',
          70,
        ),
      body: `${plain(e.flow.direction, 16)} ${plain(e.flow.protocol, 8).toUpperCase()} · ${plain(e.flow.remote, 100)}${g.count > 1 ? ` · ${g.count} similar requests` : ''}\nReview this request in FlowGate.`,
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

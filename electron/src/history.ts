import { performance } from 'node:perf_hooks';
import { hierarchy, allRows } from './model';
import type { ClientState, SocketRow } from './protocol';
export type Source = 'tcp' | 'udp';
export interface GraphPoint {
  at: number;
  source: Source;
  up?: number;
  down?: number;
  partial: boolean;
  note: string;
  breakBefore: boolean;
}
export interface GraphView {
  revision: number;
  now: number;
  started: number;
  connected: boolean;
  label: string;
  points: GraphPoint[];
  limited: boolean;
  message: string;
}
interface Entry {
  label: string;
  seen: number;
  active: boolean;
  points: GraphPoint[];
  limited: boolean;
}
interface Previous {
  since: string;
  definition: string;
  up?: number;
  down?: number;
}
export const HISTORY_LIMITS = {
  duration: 300000,
  closedDuration: 60000,
  closed: 256,
  entities: 8192,
  points: 120000,
  perEntity: 1202,
};
// Observation-only. No counters are differentiated here; backend rate semantics remain authoritative.
export class TrafficHistory {
  private entries = new Map<string, Entry>();
  private previous = new Map<string, Previous>();
  private stamp = '';
  private generation = '';
  private sequence = 0;
  private udpGeneration = '';
  private udpState = '';
  private last = 0;
  private sampleAt = 0;
  private collectedAt = 0;
  private connected = false;
  private revision = 0;
  private started: number;
  constructor(
    private clock = () => performance.now(),
    private limits = HISTORY_LIMITS,
  ) {
    this.started = clock();
  }
  observe(observation: ClientState['observation']) {
    const now = this.clock();
    if (!observation.connected || !observation.activity) {
      if (this.connected) {
        this.connected = false;
        this.stamp = '';
        this.previous.clear();
        this.revision++;
        for (const e of this.entries.values())
          if (e.active) {
            for (const source of new Set(e.points.map((p) => p.source)))
              e.points.push({
                at: now,
                source,
                partial: false,
                note: 'Observer disconnected',
                breakBefore: true,
              });
            e.active = false;
          }
      }
      this.prune(now);
      return;
    }
    const a = observation.activity;
    const stamp = `${observation.generation}:${a.sequence}:${a.collected}`;
    if (
      stamp === this.stamp ||
      (this.connected && observation.generation === this.generation && a.sequence <= this.sequence)
    )
      return;
    if (this.generation && observation.generation !== this.generation) {
      this.entries.clear();
      this.previous.clear();
      this.started = now;
    }
    const resume = !this.connected || observation.generation !== this.generation;
    // Anchor backend collection timestamps onto the frontend monotonic timeline.
    // Wall-clock jumps re-anchor and break the trace, never turn into a traffic rate.
    const collected = /^\d{4}-/.test(a.collected) ? Date.parse(a.collected) : NaN;
    const candidate = this.sampleAt + collected - this.collectedAt;
    const clockJump =
      !resume &&
      Number.isFinite(collected) &&
      this.collectedAt > 0 &&
      (collected <= this.collectedAt || Math.abs(candidate - now) > 2000);
    this.sampleAt =
      !resume && !clockJump && Number.isFinite(candidate) && this.collectedAt > 0
        ? Math.min(now, candidate)
        : now;
    this.collectedAt = Number.isFinite(collected) ? collected : 0;
    const gap =
      !resume && (clockJump || a.sequence !== this.sequence + 1 || now - this.last > 60000);
    this.stamp = stamp;
    this.generation = observation.generation;
    this.sequence = a.sequence;
    this.connected = true;
    this.last = now;
    this.revision++;
    const udpChanged =
      this.udpGeneration !== (a.udp?.generation || '') || this.udpState !== (a.udp?.state || '');
    this.udpGeneration = a.udp?.generation || '';
    this.udpState = a.udp?.state || '';
    const next = new Map<string, Previous>(),
      measured = new Map<string, GraphPoint>();
    for (const s of a.rows.slice(0, 2048)) {
      if (measured.has(s.id)) continue;
      const t = s.traffic,
        old = this.previous.get(s.id),
        source: Source = s.socket.protocol === 'udp' ? 'udp' : 'tcp';
      const reset =
        !!old &&
        (old.since !== t.since ||
          old.definition !== t.definition ||
          (t.uploaded !== undefined && old.up !== undefined && t.uploaded < old.up) ||
          (t.downloaded !== undefined && old.down !== undefined && t.downloaded < old.down));
      const supported =
        t.definition === 'tcp-transport-payload' || t.definition === 'udp-api-reported';
      const collectorGap = source === 'udp' && udpChanged;
      const collectorUnavailable = source === 'udp' && !!a.udp && a.udp.state !== 'active';
      const blocked =
        resume || reset || collectorGap || collectorUnavailable || !t.available || !supported;
      const rate = (v: number | undefined) =>
        !blocked && v !== undefined && Number.isFinite(v) && v >= 0 ? v : undefined;
      const up = rate(t.upload_bps),
        down = rate(t.download_bps);
      measured.set(s.id, {
        at: this.sampleAt,
        source,
        up,
        down,
        partial: t.partial,
        breakBefore: resume || reset || collectorGap || collectorUnavailable || gap || !old,
        note: resume
          ? 'New observer baseline / reconnect'
          : collectorGap
            ? 'UDP collector generation/state changed; new baseline'
            : collectorUnavailable
              ? 'UDP collector unavailable; preceding samples are historical'
              : reset
                ? 'Counter reset or source/baseline change'
                : !t.available
                  ? t.reason || 'Measurement unavailable'
                  : up === undefined || down === undefined
                    ? t.state === 'warming-up'
                      ? 'Warm-up / no fresh backend rate'
                      : 'Missing rate'
                    : gap
                      ? 'Missing observation interval'
                      : t.partial
                        ? 'Partial measurement coverage'
                        : !a.complete
                          ? 'Measured; census visibility partial'
                          : 'Measured',
      });
      next.set(s.id, {
        since: t.since,
        definition: t.definition,
        up: t.uploaded,
        down: t.downloaded,
      });
    }
    this.previous = next;
    const active = new Set<string>();
    // Unfiltered hierarchy freezes historical membership; later ownership discovery cannot reassign old points.
    for (const row of allRows(hierarchy(a))) {
      if (active.size >= this.limits.entities) break;
      active.add(row.id);
      let entry = this.entries.get(row.id);
      if (!entry) {
        entry = { label: row.label, seen: now, active: true, points: [], limited: false };
        this.entries.set(row.id, entry);
      }
      entry.label = row.label;
      entry.seen = now;
      entry.active = true;
      const unique = [...new Map(row.rows.map((s) => [s.id, s])).values()];
      for (const source of ['tcp', 'udp'] as Source[]) {
        const points = unique
          .map((s) => measured.get(s.id))
          .filter((p): p is GraphPoint => !!p && p.source === source);
        if (!points.length) {
          const prior = [...entry.points].reverse().find((p) => p.source === source);
          if (prior && (prior.up !== undefined || prior.down !== undefined))
            entry.points.push({
              at: now,
              source,
              partial: false,
              note: 'No current sockets in this source',
              breakBefore: true,
            });
          continue;
        }
        const knownUp = points.filter((p) => p.up !== undefined),
          knownDown = points.filter((p) => p.down !== undefined);
        const partial =
          points.some((p) => p.partial) ||
          knownUp.length < points.length ||
          knownDown.length < points.length;
        const notes = [...new Set(points.filter((p) => p.note !== 'Measured').map((p) => p.note))];
        entry.points.push({
          at: this.sampleAt,
          source,
          up: knownUp.length ? knownUp.reduce((n, p) => n + p.up!, 0) : undefined,
          down: knownDown.length ? knownDown.reduce((n, p) => n + p.down!, 0) : undefined,
          partial,
          breakBefore: points.some((p) => p.breakBefore),
          note: notes.join(' · ').slice(0, 512) || 'Measured',
        });
      }
    }
    for (const [id, e] of this.entries)
      if (!active.has(id) && e.active) {
        e.active = false;
        for (const source of new Set(e.points.map((p) => p.source)))
          e.points.push({
            at: now,
            source,
            partial: false,
            note: 'Socket/group absent',
            breakBefore: true,
          });
      }
    this.prune(now);
  }
  private prune(now: number) {
    const closed = [...this.entries]
      .filter(([, e]) => !e.active)
      .sort((a, b) => b[1].seen - a[1].seen);
    for (let i = 0; i < closed.length; i++)
      if (i >= this.limits.closed || now - closed[i][1].seen > this.limits.closedDuration)
        this.entries.delete(closed[i][0]);
    while (this.entries.size > this.limits.entities)
      this.entries.delete(this.entries.keys().next().value!);
    const cap = Math.min(
      this.limits.perEntity,
      Math.max(1, Math.floor(this.limits.points / Math.max(1, this.entries.size))),
    );
    for (const e of this.entries.values()) {
      const keep = e.points.filter((p) => now - p.at <= this.limits.duration);
      if (keep.length > cap) e.limited = true;
      e.points = keep.slice(-cap);
    }
  }
  view(value: unknown): GraphView {
    const q = value as { id: string; seconds: number };
    if (
      !q ||
      typeof q !== 'object' ||
      Object.keys(q).sort().join(',') !== 'id,seconds' ||
      typeof q.id !== 'string' ||
      q.id.length > 4096 ||
      ![60, 300].includes(q.seconds)
    )
      throw Error('Invalid graph selection');
    const now = this.clock(),
      e = this.entries.get(q.id);
    return {
      revision: this.revision,
      now,
      started: this.started,
      connected: this.connected,
      label: e?.label || '',
      points: e?.points.filter((p) => now - p.at <= q.seconds * 1000) || [],
      limited: e?.limited || false,
      message: !q.id
        ? 'Select a socket, process, application or Unidentified group'
        : !e
          ? 'No retained observations for this selection'
          : !this.connected
            ? 'Observer disconnected — history retained'
            : !e.active
              ? 'Selection no longer observed — closed history retained briefly'
              : 'All observed sockets; table filters do not change graph membership',
    };
  }
  stats() {
    return {
      entries: this.entries.size,
      points: [...this.entries.values()].reduce((n, e) => n + e.points.length, 0),
      revision: this.revision,
    };
  }
}

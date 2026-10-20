import { verifiedLaunch } from './provenance';
import type { ClientState, Process } from './protocol';
export interface LaunchContext {
  title: string;
  executable: string;
  revision: string;
  captured: string;
}
export interface CallerRecord {
  name: string;
  executable: string;
  pid: number;
  start: string;
  captured: string;
  request: string;
  ownerPid: number;
}
const identity = (key: string, revision: string, uid: number) =>
  JSON.stringify([key, revision, uid]);
// Recorded process/connection ancestry, not rule provenance. Bounded to this GUI session and
// daemon generation. No current /proc lookup, script inference or permission use.
export class ApplicationCallers {
  private generation = '';
  private records = new Map<string, CallerRecord[]>();
  private launches = new Map<string, LaunchContext[]>();
  private rememberLaunch(owner: Process) {
    const p = verifiedLaunch(owner.provenance),
      game = p?.launch?.game,
      app = owner.application;
    if (
      !app?.key ||
      !app.revision ||
      !game?.revision ||
      !game.executable ||
      !p?.captured_at ||
      !Number.isFinite(Date.parse(p.captured_at))
    )
      return;
    const key = identity(app.key, app.revision, owner.uid),
      prior = this.launches.get(key) || [];
    const item: LaunchContext = {
      title: game.title || game.name.replace(/\.exe$/i, ''),
      executable: game.executable,
      revision: game.revision,
      captured: p.captured_at,
    };
    const old = prior.find((x) => x.executable === item.executable && x.revision === item.revision);
    if (old && Date.parse(old.captured) >= Date.parse(item.captured)) return;
    this.launches.delete(key);
    this.launches.set(
      key,
      [item, ...prior.filter((x) => x !== old)]
        .sort((a, b) => Date.parse(b.captured) - Date.parse(a.captured))
        .slice(0, 4),
    );
    while (this.launches.size > 128) this.launches.delete(this.launches.keys().next().value!);
  }
  observe(state: ClientState) {
    const control = state.control;
    if (!control.generation) return;
    if (this.generation !== control.generation) {
      this.records.clear();
      this.launches.clear();
      this.generation = control.generation;
    }
    if (state.observation.generation === control.generation)
      for (const process of Object.values(state.observation.activity?.processes || {}))
        this.rememberLaunch(process);
    for (const event of control.events) {
      for (const owner of event.attribution.owners) {
        this.rememberLaunch(owner);
        const app = owner.application,
          provenance = owner.provenance,
          parent = provenance?.parent;
        if (
          !app?.key ||
          !app.revision ||
          !parent?.executable ||
          !parent.start_ticks ||
          !provenance?.captured_at ||
          !Number.isFinite(Date.parse(provenance.captured_at))
        )
          continue;
        if (
          !provenance.ancestry.some(
            (a) =>
              a.pid === parent.pid &&
              a.start_ticks === parent.start_ticks &&
              a.executable === parent.executable,
          )
        )
          continue;
        const key = identity(app.key, app.revision, owner.uid),
          prior = this.records.get(key) || [];
        const item: CallerRecord = {
          name:
            parent.application?.display_name ||
            parent.application?.name ||
            parent.name ||
            parent.executable.split('/').pop() ||
            'Caller',
          executable: parent.executable,
          pid: parent.pid,
          start: parent.start_ticks,
          captured: provenance.captured_at,
          request: event.id,
          ownerPid: owner.pid,
        };
        const same = prior.find(
          (x) => x.pid === item.pid && x.start === item.start && x.executable === item.executable,
        );
        if (same && Date.parse(same.captured) >= Date.parse(item.captured)) continue;
        const next = [item, ...prior.filter((x) => x !== same)]
          .sort((a, b) => Date.parse(b.captured) - Date.parse(a.captured))
          .slice(0, 4);
        this.records.delete(key);
        this.records.set(key, next);
        while (this.records.size > 128) this.records.delete(this.records.keys().next().value!);
      }
    }
  }
  forLaunches(key: string, revision: string, uid: number): readonly LaunchContext[] {
    return this.launches.get(identity(key, revision, uid)) || [];
  }
  forApplication(key: string, revision: string, uid: number): readonly CallerRecord[] {
    return this.records.get(identity(key, revision, uid)) || [];
  }
}

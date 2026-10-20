import type { Activity, SocketRow, Process, Traffic, Application, Rule } from './protocol';
import { launchProcessLabel, launchTitle, verifiedLaunch } from './provenance';
export type Metric = 'download_bps' | 'upload_bps' | 'downloaded' | 'uploaded';
export interface Row {
  id: string;
  parent?: string;
  // 'launch': display-only group of processes from one verified game launch
  // (backend provenance). Never a firewall target; rules stay per process/application.
  kind: 'overview' | 'network' | 'application' | 'launch' | 'process' | 'socket' | 'unidentified';
  label: string;
  pid?: number;
  rows: SocketRow[];
  children: Row[];
  process?: Process;
  displayApplication?: Application;
  socket?: SocketRow;
  // Not running: an application identity that only stored rules name (NetLimiter
  // lists such applications too). No process, sockets or traffic.
  inactive?: InactiveApplication;
}
export interface InactiveApplication {
  key: string;
  revision: string;
  uid: number;
  executable: string;
  rules: number;
  // Another revision of the same application is running or has newer rules (updated file).
  earlierVersion: boolean;
  // Short location shown when another entry has the same name (different program).
  where?: string;
}
// Observation status only: a listening/bound socket is not a connected peer.
export function hasObservedConnection(row: Row): boolean {
  return row.rows.some((r) =>
    r.socket.protocol === 'tcp'
      ? r.socket.state === 1
      : r.socket.protocol === 'udp' && /:[1-9]\d*$/.test(r.socket.remote),
  );
}
export interface Sum {
  value?: number;
  partial: boolean;
  mixed: boolean;
  known: number;
  count: number;
}
export type MeasurementSource = 'tcp' | 'udp';
export const sourceRows = (rows: SocketRow[], source?: MeasurementSource) => [
  ...new Map(
    rows.filter((r) => !source || r.socket.protocol === source).map((r) => [r.id, r]),
  ).values(),
];
export const NETWORK_UNAVAILABLE =
  'Classification unavailable: the daemon supplies no configured network-zone attribution. These totals are unknown, not zero; this is not a firewall target.';
export function networkOverviews(): Row[] {
  return ['Internet', 'Local Network'].map((label, index) => ({
    id: index ? 'network:local' : 'network:internet',
    parent: 'overview',
    kind: 'network' as const,
    label,
    rows: [],
    children: [],
  }));
}
export function overview(activity: Activity, children: Row[] = []): Row {
  return {
    id: 'overview',
    kind: 'overview',
    label: 'All applications',
    rows: sourceRows(activity.rows),
    children,
  };
}
export function sum(rows: SocketRow[], metric: Metric, source?: MeasurementSource): Sum {
  rows = sourceRows(rows, source);
  const definitions = new Set<string>();
  let value = 0,
    known = 0,
    partial = false;
  for (const r of rows) {
    const t = r.traffic;
    if (
      t.available &&
      (!source ||
        t.definition === (source === 'tcp' ? 'tcp-transport-payload' : 'udp-api-reported'))
    ) {
      definitions.add(t.definition || t.source || 'unknown');
      if (t[metric] !== undefined) {
        value += t[metric]!;
        known++;
      }
      partial ||= t.partial;
    }
  }
  return {
    value: known && definitions.size <= 1 ? value : undefined,
    partial: partial || known < rows.length,
    mixed: definitions.size > 1,
    known,
    count: rows.length,
  };
}
export function amount(v: number | undefined, rate = false) {
  if (v === undefined) return '—';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let u = 0;
  while (v >= 1024 && u < 4) {
    v /= 1024;
    u++;
  }
  return `${v.toFixed(u ? 1 : 0)} ${units[u]}${rate ? '/s' : ''}`;
}
export function metricLabel(s: Sum, rate = false) {
  return s.mixed
    ? 'Mixed sources'
    : amount(s.value, rate) + (s.value !== undefined && s.partial ? ' *' : '');
}
export function hierarchy(activity: Activity, query = '', filter = 'all'): Row[] {
  const roots: Row[] = [];
  const apps = new Map<string, Row>(),
    procs = new Map<string, Row>();
  let unknown: Row | undefined;
  const seen = new Set<string>();
  for (const s of activity.rows) {
    if (seen.has(s.id)) continue;
    seen.add(s.id);
    const owners = s.owners.map((id) => activity.processes[id]).filter(Boolean);
    const hay = [
      s.socket.local,
      s.socket.remote,
      s.socket.protocol,
      s.state,
      s.display_application?.name || '',
      s.display_application?.executable || '',
      ...owners.flatMap((p) => [
        p.executable,
        p.application.name,
        String(p.pid),
        String(p.thread_group_pid || ''),
        verifiedLaunch(p.provenance) ? launchTitle(p.provenance!) : '',
      ]),
    ]
      .join(' ')
      .toLowerCase();
    if (!hay.includes(query.toLowerCase())) continue;
    const listening =
      s.socket.protocol === 'tcp' ? s.socket.state === 10 : s.socket.remote.endsWith(':0');
    const active =
      s.socket.protocol === 'udp' ? !listening : [1, 2, 3, 12].includes(s.socket.state);
    if ((filter === 'active' && !active) || (filter === 'listening' && !listening)) continue;
    let parent: Row;
    if (s.display_application?.key && s.owners.length > 1 && owners.length === s.owners.length) {
      // Trust only the explicit backend display association; never infer a policy identity.
      const display = s.display_application,
        key = `${display.key}|${display.revision}|uid:${owners[0].uid}`;
      let a = apps.get(key);
      if (!a) {
        a = {
          id: 'app:' + key,
          kind: 'application',
          label:
            display.display_name || display.name.replace(/ \(deleted\)$/, '') || display.executable,
          children: [],
          rows: [],
          displayApplication: display,
        };
        apps.set(key, a);
        roots.push(a);
      }
      a.rows.push(s);
      parent = a;
    } else if (
      s.owners.length === 1 &&
      owners.length === 1 &&
      verifiedLaunch(owners[0].provenance)
    ) {
      // Verified launch: the helper/launcher/game process sits beneath its game node.
      const p = owners[0],
        prov = verifiedLaunch(p.provenance)!,
        key = `launch:${p.uid}:${prov.group}`;
      let g = apps.get(key);
      if (!g) {
        g = { id: key, kind: 'launch', label: launchTitle(prov), children: [], rows: [] };
        apps.set(key, g);
        roots.push(g);
      }
      const pk = 'process:' + key + ':' + p.id;
      let pr = procs.get(pk);
      if (!pr) {
        pr = {
          id: pk,
          parent: g.id,
          kind: 'process',
          label: launchProcessLabel(p),
          pid: p.pid,
          children: [],
          rows: [],
          process: p,
        };
        procs.set(pk, pr);
        g.children.push(pr);
      }
      g.rows.push(s);
      pr.rows.push(s);
      parent = pr;
    } else if (s.owners.length === 1 && owners.length === 1) {
      const p = owners[0],
        key = p.application.key
          ? `${p.application.key}|${p.application.revision}|uid:${p.uid}`
          : `unresolved:${p.id}`;
      let a = apps.get(key);
      if (!a) {
        a = {
          id: 'app:' + key,
          kind: 'application',
          label:
            p.application.display_name ||
            p.application.name.replace(/ \(deleted\)$/, '') ||
            p.executable ||
            'Unknown application',
          children: [],
          rows: [],
          process: p,
        };
        apps.set(key, a);
        roots.push(a);
      }
      const pk = 'process:' + key + ':' + p.id;
      let pr = procs.get(pk);
      if (!pr) {
        pr = {
          id: pk,
          parent: a.id,
          kind: 'process',
          label: p.thread_group_pid
            ? `Worker TID ${p.pid} (process ${p.thread_group_pid})`
            : 'Process ' + p.pid,
          pid: p.pid,
          children: [],
          rows: [],
          process: p,
        };
        procs.set(pk, pr);
        a.children.push(pr);
      }
      a.rows.push(s);
      pr.rows.push(s);
      parent = pr;
    } else {
      if (!unknown) {
        unknown = {
          id: 'unidentified',
          kind: 'unidentified',
          label: 'Unidentified',
          children: [],
          rows: [],
        };
        roots.push(unknown);
      }
      unknown.rows.push(s);
      parent = unknown;
    }
    parent.children.push({
      id: s.id,
      parent: parent.id,
      kind: 'socket',
      label: (s.display_application && s.owners.length > 1 ? 'Shared · ' : '') + s.socket.remote,
      children: [],
      rows: [s],
      socket: s,
      pid: owners.length === 1 ? owners[0].pid : undefined,
    });
  }
  return nestLaunchedApplications(roots);
}
/** The application row key of a process ("<key>|<revision>|uid:<uid>"). */
const appRowKey = (a: Pick<Application, 'key' | 'revision'>, uid: number) => `app:${a.key}|${a.revision}|uid:${uid}`;
/**
 * The verified application that launched every process of this application row,
 * or undefined. Only a backend-verified launch parent counts: provenance.parent
 * with a verified Electron application identity (e.g. Heroic for nile). Any
 * process without it, or two different parents, leaves the row separate.
 */
export function launchingApplication(row: Row): string | undefined {
  if (row.kind !== 'application' || !row.process?.application.key) return;
  const processes = row.children.filter((c) => c.kind === 'process').map((c) => c.process!);
  if (!processes.length) return;
  let parent: string | undefined;
  for (const p of processes) {
    const app = p.provenance?.parent?.application;
    if (!app?.key || !app.revision || app.kind !== 'electron' || app.hosted?.state !== 'verified') return;
    const key = appRowKey(app, p.uid);
    if (parent && parent !== key) return;
    parent = key;
  }
  return parent && parent !== row.id ? parent : undefined;
}
/**
 * Display only: an application launched by another verified application sits
 * beneath it (Heroic › nile, legendary, gogdl). Both stay separate applications
 * with their own sockets, totals and rule status; nothing is inherited.
 */
export function nestLaunchedApplications(roots: Row[]): Row[] {
  const byId = new Map(roots.filter((r) => r.kind === 'application').map((r) => [r.id, r]));
  const moved = new Set<Row>();
  for (const r of roots) {
    const parentId = launchingApplication(r);
    const parent = parentId ? byId.get(parentId) : undefined;
    // Only beneath a parent that is itself a top-level row (one level, no chains).
    if (!parent || parent === r || launchingApplication(parent)) continue;
    r.parent = parent.id;
    parent.children.push(r);
    moved.add(r);
  }
  return moved.size ? roots.filter((r) => !moved.has(r)) : roots;
}
export function flatten(
  roots: Row[],
  expanded: Set<string>,
  key: string,
  descending: boolean,
  source?: MeasurementSource,
): { row: Row; depth: number }[] {
  const result: { row: Row; depth: number }[] = [];
  const value = (r: Row): number | string =>
    key === 'name'
      ? r.label
      : key === 'pid'
        ? (r.pid ?? -1)
        : key === 'count'
          ? r.rows.length
          : key === 'protocol'
            ? (r.socket?.socket.protocol ?? '')
            : key === 'local'
              ? (r.socket?.socket.local ?? '')
              : key === 'remote'
                ? (r.socket?.socket.remote ?? '')
                : key === 'state'
                  ? (r.socket?.state ?? '')
                  : (sum(r.rows, key as Metric, source).value ?? -1);
  const walk = (rows: Row[], depth: number) => {
    for (const row of [...rows].sort((a, b) => {
      if (a.kind === 'network' || b.kind === 'network') {
        if (a.kind !== b.kind) return a.kind === 'network' ? -1 : 1;
        return a.id === b.id ? 0 : a.id === 'network:internet' ? -1 : 1;
      }
      // Not-running applications with rules stay at the bottom in every sort order.
      if (!!a.inactive !== !!b.inactive) return a.inactive ? 1 : -1;
      if (a.inactive && b.inactive) return a.label.localeCompare(b.label) || a.id.localeCompare(b.id);
      const av = value(a),
        bv = value(b);
      if (['upload_bps', 'download_bps'].includes(key) && (av === -1 || bv === -1) && av !== bv)
        return av === -1 ? 1 : -1;
      return (
        (typeof av === 'number' && typeof bv === 'number'
          ? av - bv
          : String(av).localeCompare(String(bv))) * (descending ? -1 : 1) ||
        a.id.localeCompare(b.id)
      );
    })) {
      result.push({ row, depth });
      if (expanded.has(row.id)) walk(row.children, depth + 1);
    }
  };
  walk(roots, 0);
  return result;
}
export function allRows(roots: Row[]): Row[] {
  return roots.flatMap((r) => [r, ...allRows(r.children)]);
}
export function endpoint(value: string): [string, string] {
  const match = value.match(/^\[(.*)\]:(\d+)$/) || value.match(/^(.*):(\d+)$/);
  return match ? [match[1], match[2]] : [value, '—'];
}
export function trafficDetails(t: Traffic) {
  return [
    t.available ? 'Measurement available' : 'Measurement unavailable',
    t.definition,
    t.source,
    t.reason,
    t.since ? 'Observed since ' + t.since : '',
  ]
    .filter(Boolean)
    .join('\n');
}

export function ownershipExplanation(category?: string) {
  const descriptions: Record<string, string> = {
    'visible-holder': 'A current userspace descriptor holder was observed.',
    shared:
      'Multiple descriptor holders were observed. The socket is counted once; a display association grants no firewall permission.',
    'no-userspace-inode':
      'No userspace inode (inode zero). These can be kernel-managed rows such as TIME_WAIT; no current userspace owner is inferred.',
    'holder-changed':
      'A holder was observed but its generation or descriptor changed during inspection.',
    'holder-inaccessible': 'A matching descriptor was observed, but executable access was denied.',
    'holder-metadata-unavailable':
      'A holder was observed, but its executable identity could not be validated.',
    'holders-truncated':
      'The holder list reached its inspection limit; no complete common application association is available.',
    unknown:
      'No current descriptor association was established. A different socket creation UID or inaccessible directories elsewhere do not prove this socket was permission denied.',
  };
  return (
    descriptions[category || ''] ||
    'No categorized ownership evidence supplied; see the backend ownership and evidence fields.'
  );
}

/** Display name of an executable path; an Electron bundle is named by its folder. */
export function executableName(path: string) {
  const parts = path.replace(/ \(deleted\)$/, '').split('/').filter(Boolean);
  const base = parts.pop() || path || 'Unknown application';
  return /\.asar$/.test(base) && parts.length ? parts.pop()! : base;
}
/**
 * Applications that have stored rules but are not running: one row per
 * application key/revision/UID with no live row, listed after all running
 * applications. Rules with only a process binding, all-programs or zone-wide
 * scope name no application and are not listed here.
 */
export function inactiveApplications(rules: Rule[] | undefined, live: Row[], query = '', filter = 'all'): Row[] {
  if (!rules?.length || filter !== 'all') return [];
  const running = new Set(allRows(live).filter((r) => r.kind === 'application').map((r) => r.id));
  const liveExecutables = new Set(
    allRows(live)
      .filter((r) => r.kind === 'application' && r.process)
      .map((r) => `${r.process!.application.executable}|${r.process!.uid}`),
  );
  const out = new Map<string, Row>();
  for (const rule of rules) {
    const f = rule.filter;
    if (!f.application || !f.revision || f.all_programs || f.uid === undefined || f.uid === null) continue;
    const id = `app:${f.application}|${f.revision}|uid:${f.uid}`;
    if (running.has(id)) continue;
    let row = out.get(id);
    if (!row) {
      const executable = rule.executable || '';
      const label = executableName(executable);
      if (query && !`${label} ${executable}`.toLowerCase().includes(query.toLowerCase())) continue;
      row = {
        id,
        kind: 'application',
        label,
        rows: [],
        children: [],
        inactive: { key: f.application, revision: f.revision, uid: f.uid, executable, rules: 0, earlierVersion: liveExecutables.has(`${executable}|${f.uid}`) },
      };
      out.set(id, row);
    }
    row.inactive!.rules++;
  }
  // Several revisions of one application (same key and UID): only the newest rules
  // describe the current file; older ones are marked as an earlier version.
  const newest = new Map<string, string>();
  for (const rule of rules) {
    const f = rule.filter;
    if (!f.application || !f.revision) continue;
    const k = `${f.application}|${f.uid}`;
    if ((newest.get(k) || '') < (rule.created || '')) newest.set(k, rule.created || '');
  }
  for (const row of out.values()) {
    const i = row.inactive!,
      latest = rules
        .filter((r) => r.filter.application === i.key && r.filter.revision === i.revision && r.filter.uid === i.uid)
        .reduce((m, r) => ((r.created || '') > m ? r.created || '' : m), '');
    const others = [...out.values()].some((o) => o !== row && o.inactive!.key === i.key && o.inactive!.uid === i.uid);
    if (others && latest < (newest.get(`${i.key}|${i.uid}`) || '')) i.earlierVersion = true;
  }
  // Same name, different programs: show where each one lives.
  const labels = new Map<string, number>();
  for (const r of [...allRows(live).filter((r) => r.kind === 'application'), ...out.values()])
    labels.set(r.label, (labels.get(r.label) || 0) + 1);
  for (const row of out.values()) if ((labels.get(row.label) || 0) > 1) row.inactive!.where = shortLocation(row.inactive!.executable);
  return [...out.values()].sort((a, b) => a.label.localeCompare(b.label) || a.id.localeCompare(b.id));
}
/** "~/.codex/…/0.160.0-x86_64-unknown-linux-musl/bin" for an executable path. */
export function shortLocation(path: string) {
  const dir = path.replace(/^\/home\/[^/]+/, '~').split('/').slice(0, -1);
  const text = dir.join('/');
  return text.length <= 48 ? text : [dir[0], '…', ...dir.slice(-2)].join('/');
}
/** Running applications followed by not-running applications with rules. */
export function activityTree(activity: Activity, rules: Rule[] | undefined, query = '', filter = 'all'): Row[] {
  const live = hierarchy(activity, query, filter);
  return [...live, ...inactiveApplications(rules, live, query, filter)];
}

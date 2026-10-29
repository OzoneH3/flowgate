import { accountLabel, accountRowLabel } from './accounts';
import { addApplicationZones, type ApplicationZone } from './application-zones';
import type { NetworkZones } from './network-zones';
import type { Activity, SocketRow, Process, Traffic, Application, Rule, ViewEvent } from './protocol';
import { launchProcessLabel, launchTitle, verifiedLaunch } from './provenance';
export type Metric = 'download_bps' | 'upload_bps' | 'downloaded' | 'uploaded';
export interface Row {
  id: string;
  parent?: string;
  // 'launch': display-only group of processes from one verified game launch
  // (backend provenance). Never a firewall target; rules stay per process/application.
  kind: 'inactive-group' | 'overview' | 'network' | 'application' | 'program' | 'launch' | 'process' | 'socket' | 'unidentified' | 'kernel-lifecycle';
  label: string;
  program?: { executable: string; inactive: boolean };
  presentationLabel?: string;
  identityNote?: string;
  pid?: number;
  rows: SocketRow[];
  children: Row[];
  runtimeApplication?: SocketRow["runtime_application"];
  process?: Process;
  displayApplication?: Application;
  socket?: SocketRow;
  applicationZone?: ApplicationZone;
  requestEvent?: ViewEvent;
  policyRows?: SocketRow[];
  // Not running: an application identity that only stored rules name (NetLimiter
  // lists such applications too). No process, sockets or traffic.
  inactive?: InactiveApplication;
  // Saved-rule entries of other revisions of the same verified program (key+UID),
  // folded into this row's details instead of separate version rows. Their rules
  // keep their own exact scope; folding transfers no permission.
  foldedVersions?: InactiveApplication[];
  // Revisions of the same program whose running processes are listed under this row.
  revisions?: string[];
}
export interface InactiveApplication {
  key: string;
  revision: string;
  uid: number;
  executable: string;
  rules: number;
  invocations?: string[];
  // Another revision of the same application is running or has newer rules (updated file).
  earlierVersion: boolean;
  // Daemon-reported: these rules follow updates of this verified program, so the row
  // stands for the program/user, not one file revision (revision is the newest seen).
  followsUpdates?: boolean;
  created?: string;
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
export const KERNEL_LIFECYCLE_EXPLANATION =
  'TCP TIME_WAIT records retained by the kernel after closure. No current userspace owner is identified; no previous application is inferred. These rows are not permission targets.';

// Presentation only. Inode zero alone also occurs in active handshake records.
// Require explicit, consistent evidence; older/incomplete metadata stays unresolved.
export function isKernelTimeWait(row: SocketRow): boolean {
  return row.socket.protocol === 'tcp' && row.socket.state === 6 &&
    row.socket.inode === 0 && row.owners.length === 0 &&
    row.ownership_category === 'no-userspace-inode' &&
    !row.runtime_application && !row.display_application;
}

/** Counts the displayed socket leaves, independent of grouping and expansion. */
export function activityRowCounts(roots: Row[]) {
  const all = allRows(roots);
  const sockets = sourceRows(all.flatMap(r => r.kind === 'socket' && r.socket ? [r.socket] : []));
  const unresolved = sourceRows(all.filter(r => r.kind === 'unidentified').flatMap(r => r.rows));
  return { displayed: sockets.length, lifecycle: sockets.filter(isKernelTimeWait).length, unresolved: unresolved.length };
}
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
export function overview(activity: Activity, children: Row[] = [], label = 'All applications'): Row {
  return {
    id: 'overview',
    kind: 'overview',
    label,
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
  let unknown: Row | undefined, lifecycle: Row | undefined;
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
    if (isKernelTimeWait(s)) {
      if (!lifecycle) {
        lifecycle = { id: 'kernel-lifecycle', kind: 'kernel-lifecycle', label: 'Kernel TCP lifecycle', children: [], rows: [] };
        roots.push(lifecycle);
      }
      lifecycle.rows.push(s);
      parent = lifecycle;
    } else if (s.runtime_application) {
      const runtime=s.runtime_application, display=runtime.application;
      const key=`${display.key}|${display.revision}|uid:${runtime.uid}`;
      let a=apps.get(key);
      if(!a){ a={id:'app:'+key,kind:'application',label:display.name,children:[],rows:[]}; apps.set(key,a);roots.push(a); }
      a.runtimeApplication=runtime; a.label=display.name||display.executable.split('/').pop()||'Windows application';
      a.rows.push(s);parent=a;
    } else if (s.display_application?.key && s.owners.length > 1 && owners.length === s.owners.length) {
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
      verifiedLaunch(owners[0].provenance) &&
      !(owners[0].application.key && owners[0].application.revision)
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
            (p.application.kind==='wine' ? p.application.name : p.application.display_name) ||
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
          label: p.provenance?.role === 'launcher' && verifiedLaunch(p.provenance)
            ? launchProcessLabel(p)
            : p.thread_group_pid
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
      runtimeApplication:s.runtime_application,
      pid: owners.length === 1 ? owners[0].pid : undefined,
    });
  }
  if (lifecycle) lifecycle.label = `Kernel TCP lifecycle (${lifecycle.rows.length})`;
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
      const categoryOrder = (r: Row) => r.kind === 'overview' ? 0 : r.kind === 'unidentified' ? 1 : r.kind === 'kernel-lifecycle' ? 2 : r.kind === 'inactive-group' ? 3 : undefined;
      const ac = categoryOrder(a), bc = categoryOrder(b);
      if (ac !== undefined && bc !== undefined && ac !== bc) return ac - bc;
      if (a.kind === 'network' || b.kind === 'network') {
        if (a.kind !== b.kind) return a.kind === 'network' ? -1 : 1;
        return a.id === b.id ? 0 : a.id === 'network:internet' ? -1 : 1;
      }
      if (a.kind === 'inactive-group' || b.kind === 'inactive-group') return a.kind === b.kind ? 0 : a.kind === 'inactive-group' ? 1 : -1;
      if (!!a.applicationZone !== !!b.applicationZone) return a.applicationZone ? -1 : 1;
      if (a.applicationZone && b.applicationZone) return (a.applicationZone.zone === b.applicationZone.zone ? a.id.localeCompare(b.id) : a.applicationZone.zone === 'local' ? -1 : 1);
      // Not-running applications with rules stay at the bottom in every sort order.
      if (!!(a.inactive || a.program?.inactive) !== !!(b.inactive || b.program?.inactive)) return (a.inactive || a.program?.inactive) ? 1 : -1;
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
/** Rules listed under an inactive row: its exact revision, or every rule following updates. */
export function inactiveRuleMatches(i: InactiveApplication, rule: Rule): boolean {
  const f = rule.filter;
  return f.application === i.key && f.uid === i.uid && !f.all_programs &&
    (i.followsUpdates ? rule.follows_updates === true : f.revision === i.revision && rule.follows_updates !== true);
}
/**
 * Applications that have stored rules but are not running: one row per
 * application key/revision/UID with no live row (key/UID for rules the daemon
 * reports as following updates of the same verified program), listed after all running
 * applications. Rules with only a process binding, all-programs or zone-wide
 * scope name no application and are not listed here.
 */
export function inactiveApplications(rules: Rule[] | undefined, live: Row[], query = '', filter = 'all'): Row[] {
  if (!rules?.length || filter !== 'all') return [];
  const running = new Set(allRows(live).flatMap((r) => {
    const ids = r.kind === 'application' ? [r.id] : [];
    const p = r.process;
    if (p?.application.key && p.application.revision)
      ids.push(`app:${p.application.key}|${p.application.revision}|uid:${p.uid}`, `program:${p.application.key}|uid:${p.uid}`);
    return ids;
  }));
  const liveExecutables = new Set(
    allRows(live)
      .filter((r) => r.kind === 'application' && r.process)
      .map((r) => `${r.process!.application.executable}|${r.process!.uid}`),
  );
  const out = new Map<string, Row>();
  for (const rule of rules) {
    const f = rule.filter;
    if (!f.application || !f.revision || f.all_programs || f.uid === undefined || f.uid === null) continue;
    const follows = rule.follows_updates === true;
    // A following rule already applies to any running revision of the same program.
    if (follows && running.has(`program:${f.application}|uid:${f.uid}`)) continue;
    const id = follows ? `app:${f.application}|uid:${f.uid}` : `app:${f.application}|${f.revision}|uid:${f.uid}`;
    if (running.has(id)) continue;
    let row = out.get(id);
    if (row && follows && (rule.created || '') > (row.inactive!.created || '')) {
      row.inactive!.revision = f.revision;
      row.inactive!.created = rule.created;
    }
    if (!row) {
      const executable = rule.executable || '';
      const scope: InactiveApplication = { key: f.application, revision: f.revision, uid: f.uid, executable, rules: 0, earlierVersion: false, ...(follows ? { followsUpdates: true } : {}) };
      const matching = rules.filter(r => inactiveRuleMatches(scope, r));
      const contexts = [...new Set(matching.filter(r => r.invocation?.mode === 'file').map(r => r.invocation!.path!))];
      const oneContext = contexts.length === 1 && matching.every(r => r.invocation?.path === contexts[0]);
      const label = oneContext ? `${matching[0].invocation!.name} via ${executableName(executable)}` : executableName(executable);
      if (query && !`${label} ${executable} ${contexts.join(" ")}`.toLowerCase().includes(query.toLowerCase())) continue;
      row = {
        id,
        kind: 'application',
        label,
        presentationLabel: oneContext ? label : undefined,
        identityNote: contexts.length ? "Shared interpreter rule" : undefined,
        rows: [],
        children: [],
        inactive: { ...scope, invocations: contexts, earlierVersion: !follows && liveExecutables.has(`${executable}|${f.uid}`), created: rule.created },
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
    const i = row.inactive!;
    if (i.followsUpdates) continue; // stands for the program, never an earlier version of it
    const latest = rules
        .filter((r) => inactiveRuleMatches(i, r))
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
export function activityTree(activity: Activity, rules: Rule[] | undefined, query = '', filter = 'all', _contextFor?: undefined, zones?: NetworkZones, events: ViewEvent[] = []): Row[] {
  const live = hierarchy(activity, query, filter);
  const rows=[...live, ...inactiveApplications(rules, live, query, filter)];
  addRequestApplications(rows, events, query, filter);
  const grouped = addApplicationZones(groupProgramAccounts(groupApplicationVersions(rows)),rules||[],zones);
  const inactive = grouped.filter(r => (r.inactive || r.program?.inactive) &&
    !allRows([r]).some(child => child.requestEvent?.state === 'awaiting-decision'));
  if (!inactive.length) return grouped;
  const id = 'inactive-applications';
  for (const row of inactive) row.parent = id;
  return [...grouped.filter(r => !inactive.includes(r)),
    {id, kind: 'inactive-group', label: `Not running (${inactive.length})`, rows: [], children: inactive}];
}

// A held or recently ended request can outlive the socket census. Preserve its
// exact recorded identity without inventing a live process or traffic totals.
export function addRequestApplications(rows: Row[], events: ViewEvent[], query = '', filter = 'all') {
  if (filter !== 'all') return;
  const byId = new Map(allRows(rows).map(r => [r.id, r]));
  for (const e of [...events].sort((a,b) => Date.parse(b.first_seen)-Date.parse(a.first_seen))) {
    const a=e.attribution.application, owners=e.attribution.owners;
    if (!a?.key || !a.revision || !owners.length || owners.some(p => p.uid !== owners[0].uid)) continue;
    if (!`${a.name} ${a.executable}`.toLowerCase().includes(query.toLowerCase())) continue;
    const id=`app:${a.key}|${a.revision}|uid:${owners[0].uid}`;
    let row=byId.get(id);
    if (!row) {
      // A process nested in a launch already represents this exact identity.
      row=allRows(rows).find(r => r.process?.application.key===a.key && r.process.application.revision===a.revision && r.process.uid===owners[0].uid);
    }
    if (!row) {
      row={id,kind:'application',label:a.display_name||a.name,rows:[],children:[],displayApplication:a};
      rows.push(row);byId.set(id,row);
    }
    if (!row.requestEvent || (e.state==='awaiting-decision' && e.remainingMs>0 && row.requestEvent.state!=='awaiting-decision')) row.requestEvent=e;
  }
}


// Presentation only: group versions by the backend application key and UID,
// never by display name. Each child retains its exact rule/decision identity.
export function groupApplicationVersions(rows: Row[]): Row[] {
  const keyOf = (r: Row) => {
    const a = r.process?.application || r.runtimeApplication?.application || r.displayApplication || r.requestEvent?.attribution.application;
    const key = r.inactive?.key || a?.key;
    const uid = r.inactive?.uid ?? r.process?.uid ?? r.requestEvent?.attribution.owners[0]?.uid;
    return key && uid !== undefined ? `${key}|uid:${uid}` : undefined;
  };
  const representatives = new Map<string, Row>();
  for (const r of allRows(rows)) {
    const key = keyOf(r);
    if (!key || r.inactive || (r.kind !== 'application' && r.kind !== 'process')) continue;
    if (!representatives.has(key)) representatives.set(key,r);
  }
  // Representative among not-running rows: rules following updates, then the newest revision.
  const rank = (r: Row) => (r.inactive?.followsUpdates ? 0 : r.inactive?.earlierVersion ? 2 : 1);
  const ordered = [...rows].sort((a,b) => rank(a)-rank(b));
  const removed = new Set<Row>();
  const revisionOf = (r: Row) => r.inactive?.revision || r.process?.application.revision || r.runtimeApplication?.application.revision || r.displayApplication?.revision;
  for (const r of ordered) {
    if (r.kind !== 'application') continue;
    const key = keyOf(r);
    if (!key) continue;
    const parent = representatives.get(key);
    if (!parent) { representatives.set(key,r); continue; }
    if (parent === r) continue;
    if (r.inactive) {
      // Saved rules of the same program/user: details of one program row, not a version row.
      parent.foldedVersions = [...(parent.foldedVersions || []), r.inactive, ...(r.foldedVersions || [])];
      removed.add(r);
      continue;
    }
    if (r.process || r.rows.length) {
      // Running processes of another revision: listed under the program; each process
      // row keeps its exact identity, rule status and actions.
      const own = revisionOf(parent), other = revisionOf(r);
      parent.revisions = [...new Set([...(parent.revisions || (own ? [own] : [])), ...(r.revisions || (other ? [other] : []))])];
      for (const child of r.children) {
        child.parent = parent.id;
        if (child.process && other && other !== own) child.identityNote = [child.identityNote, `Revision ${other.slice(0, 12)}`].filter(Boolean).join(' · ');
        parent.children.push(child);
      }
      parent.rows.push(...r.rows);
      if (r.requestEvent && (!parent.requestEvent || (r.requestEvent.state === 'awaiting-decision' && parent.requestEvent.state !== 'awaiting-decision')))
        parent.requestEvent = r.requestEvent;
      removed.add(r);
      continue;
    }
    // A request without an observed process stays visible on its own row.
    r.parent = parent.id;
    r.presentationLabel = 'Recent request from another version';
    r.identityNote = `Revision ${revisionOf(r) || 'unknown'}`;
    parent.children.push(r);
    removed.add(r);
  }
  const result = rows.filter(r => !removed.has(r));
  const names = new Map<string, Row[]>();
  for (const r of result) if (r.kind === 'application') names.set(r.label,[...(names.get(r.label)||[]),r]);
  for (const same of names.values()) if (same.length > 1) {
    for (const r of same) {
      const a = r.process?.application || r.displayApplication || r.requestEvent?.attribution.application;
      const path = r.inactive?.executable || a?.executable || '';
      const uid = r.inactive?.uid ?? r.process?.uid ?? r.requestEvent?.attribution.owners[0]?.uid;
      r.identityNote = [r.identityNote, path, r.process?.provenance?.launch?.prefix ? `Prefix ${r.process.provenance.launch.prefix}` : '', accountLabel(uid), `Identity ${(r.inactive?.key || a?.key || 'unknown').slice(0,12)}`].filter(Boolean).join(' · ');
    }
  }
  return result;
}

// One visual program across accounts. This wrapper deliberately has no application
// key, process, request or rule target: all actions remain on the original children.
export function groupProgramAccounts(rows: Row[]): Row[] {
  const groups = new Map<string, Row[]>();
  for (const row of rows) {
    if (row.kind !== 'application') continue;
    const app = row.process?.application || row.runtimeApplication?.application || row.displayApplication || row.requestEvent?.attribution.application;
    const path = row.inactive?.executable || app?.executable;
    if (!path || !path.startsWith('/')) continue;
    groups.set(path, [...(groups.get(path) || []), row]);
  }
  const replacements = new Map<Row, Row>();
  const removed = new Set<Row>();
  for (const [path, children] of groups) {
    if (children.length < 2) continue;
    const id = `program:${path}`;
    const group: Row = { id, kind: 'program', label: executableName(path),
      program: { executable: path, inactive: children.every(r => !!r.inactive) },
      identityNote: 'Separate permissions by account and identity',
      rows: sourceRows(allRows(children).flatMap(r => r.rows)), children };
    for (const child of children) {
      const app = child.process?.application || child.runtimeApplication?.application || child.displayApplication || child.requestEvent?.attribution.application;
      const uid = child.inactive?.uid ?? child.process?.uid ?? child.runtimeApplication?.uid ?? child.requestEvent?.attribution.owners[0]?.uid;
      const prefix = child.process?.provenance?.launch?.prefix;
      const identity = child.inactive?.key || app?.key;
      child.parent = id;
      child.presentationLabel = `${accountRowLabel(uid)}${prefix ? ` · ${prefix}` : ''}`;
      child.identityNote = `${child.label} · ${child.inactive ? 'Saved rules' : 'Observed'}${identity ? ` · Identity ${identity.slice(0,12)}` : ''}`;
      removed.add(child);
    }
    replacements.set(children[0], group);
  }
  return rows.flatMap(row => replacements.has(row) ? [replacements.get(row)!] : removed.has(row) ? [] : [row]);
}

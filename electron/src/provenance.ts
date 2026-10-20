import type { Application, PermissionTarget, Process, Provenance, RequestEvent } from './protocol';

// Launch provenance presentation. Display grouping only: a launch group is
// never a firewall target; every decision still binds the socket owner's own
// identity exactly as the backend's permission_target states.

/** A provenance usable for grouping/naming: verified chain and a verified game file. */
export function verifiedLaunch(p?: Provenance) {
  return p?.evidence === 'verified' && p.group && p.launch?.game?.status === 'verified-file'
    ? p
    : undefined;
}

// Display metadata identity only: registered from the backend's verified launch,
// never submitted as a decision/application-policy target.
export function gameIconApplication(p?: Provenance): Application | undefined {
  const verified = verifiedLaunch(p), game = verified?.launch?.game;
  if (!verified || !game?.revision || !game.executable) return;
  return { key: `launch-artwork:${verified.group}`, revision: game.revision,
    executable: game.executable, name: game.name };
}

/** "DEATH STRANDING 2: ON THE BEACH · DS2.exe", or just the executable name. */
export function launchTitle(p: Provenance): string {
  const game = p.launch?.game;
  if (!game) return p.launch?.launcher_name || 'Launch';
  return game.title && game.title !== game.name ? `${game.title} · ${game.name}` : game.name;
}

function ownerName(process: Pick<Process, 'application' | 'executable'>) {
  return (
    process.application?.display_name ||
    (process.application?.name || '').replace(/ \(deleted\)$/, '') ||
    (process.executable || '').split('/').pop() ||
    'Unknown'
  );
}

/** Process row label beneath a launch node. */
export function launchProcessLabel(process: Process): string {
  const p = process.provenance,
    name = ownerName(process);
  const launcher = p?.launch?.launcher_name.split(' ').slice(1).join(' ');
  switch (p?.role) {
    case 'game':
      return `${name} (game) · PID ${process.pid}`;
    case 'launcher':
      return `${name} · ${launcher || p.launch?.kind || ''} launcher · PID ${process.pid}`;
    case 'runtime':
      return `${name} (runtime) · PID ${process.pid}`;
    default:
      return `${name} (helper) · PID ${process.pid}`;
  }
}

function principal(e: RequestEvent): Process | undefined {
  const owners = e.attribution.owners;
  const app = e.attribution.application;
  if (owners.length === 1) return owners[0];
  return owners.find((o) => app?.key && o.application?.key === app.key);
}

/** Application line for the prompt card: the game when the backend verified the launch. */
export function promptIdentity(e: RequestEvent): { title?: string; via?: string } {
  const p = verifiedLaunch(e.attribution.provenance);
  const owner = principal(e);
  if (!p || !owner) return {};
  const name = ownerName(owner);
  if (p.role === 'game') return { title: launchTitle(p) };
  if (p.role === 'launcher') {
    const script = p.launch?.launcher_name.split(' ').slice(1).join(' ');
    return {
      title: launchTitle(p),
      via: `via ${name}${script ? ' · ' + script + ' launcher' : ''}`,
    };
  }
  return { title: launchTitle(p), via: `via ${name}` };
}

/** Explicit scope lines shown before Allow/Deny/Remember. Backend text only. */
export function targetLines(t?: PermissionTarget): { label: string; text: string }[] {
  if (!t) return [];
  return [
    { label: 'Once', text: t.once },
    { label: 'For a while', text: t.for_a_while },
    {
      label: 'Remember',
      text: t.shared_with_note ? `${t.label} — ${t.shared_with_note}` : t.label,
    },
  ];
}

function shortPath(p: string) {
  return p.replace(/^\/home\/[^/]+/, '~');
}

/** Details rows: owner, launch, prefix, ancestry, evidence. */
export function provenanceDetails(e: RequestEvent): [string, string][] {
  const rows: [string, string][] = [];
  const owner = principal(e);
  const p = e.attribution.provenance;
  if (owner)
    rows.push([
      'Socket owner',
      `${ownerName(owner)} owns this socket\nPID ${owner.pid} · start ${owner.start_ticks} · UID ${owner.uid}\n${owner.application?.executable || owner.executable || 'executable unavailable'}`,
    ]);
  if (!p) return rows;
  if (p.invocation) rows.push(['Invoked program',
    `${p.invocation.name} · ${p.invocation.mode}` +
    (p.invocation.path ? `\nProcess namespace path: ${p.invocation.path}` : '') +
    (p.invocation.host_path ? `\nVerified host file: ${p.invocation.host_path}\nFile revision: ${p.invocation.revision || 'unavailable'}` : '') +
    (p.invocation.application ? `\nDisplay metadata identity: ${p.invocation.application.key}` : '') +
    '\nDisplay context only; permission target remains the interpreter.'
  ]);
  if (p.parent?.invocation) rows.push(['Parent invocation',
    `${p.parent.invocation.name} · ${p.parent.invocation.mode}` +
    (p.parent.invocation.path ? `\n${p.parent.invocation.path}` : '') +
    '\nDisplay context only; permission target remains the socket owner.'
  ]);
  if (p.parent)
    rows.push([
      'Launched by',
      `${p.parent.application?.display_name || p.parent.name} · PID ${p.parent.pid} · start ${p.parent.start_ticks}` +
        `\n${p.parent.executable}` +
        (p.parent.depth > 1 ? `\n${p.parent.depth - 1} intermediate process(es) (shells, session)` : '') +
        (p.parent.application ? '\nVerified Electron app ' + p.parent.application.executable : '') +
        (p.parent.note ? '\n' + p.parent.note : '') +
        '\nDisplay only: rules apply to the socket owner itself',
    ]);
  const l = p.launch;
  if (l) {
    rows.push([
      'Launch',
      [
        `${l.kind} · launcher ${l.launcher_name} PID ${l.launcher_pid} (start ${l.launcher_start_ticks})`,
        l.runtime ? 'Runtime ' + l.runtime : '',
        l.steam_app_id ? 'Steam app ' + l.steam_app_id : '',
        l.game_id ? 'Game ID ' + l.game_id : '',
        l.markers.length ? 'Markers: ' + l.markers.join(', ') : '',
      ]
        .filter(Boolean)
        .join('\n'),
    ]);
    if (l.game)
      rows.push([
        'Game',
        `${launchTitle(p)}\n${l.game.executable}\n${l.game.status === 'verified-file' ? 'File verified · revision ' + (l.game.revision || 'unavailable') : 'Not verified (file not found)'} · from ${l.game.source}`,
      ]);
    if (l.prefix)
      rows.push([
        'Prefix',
        `${shortPath(l.prefix)}${l.prefix_id ? ' · inode ' + l.prefix_id : ''}${l.prefix_source ? '\nfrom ' + l.prefix_source : ''}`,
      ]);
  }
  rows.push([
    'Provenance',
    `${p.evidence === 'verified' ? 'Verified' : p.evidence === 'none' ? 'No launcher' : 'Unavailable'}${p.role ? ' · ' + p.role : ''} · ${p.reason}`,
  ]);
  if (p.ancestry.length)
    rows.push([
      'Ancestry',
      p.ancestry
        .map((a) => `PID ${a.pid} · ${a.name}${a.marker ? ' [' + a.marker + ']' : ''}`)
        .join('\n') + `\n(stop: ${p.stop})`,
    ]);
  return rows;
}

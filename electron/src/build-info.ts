// Identity of the running GUI, from its own prepared release bundle:
// <bundle>/matched-manifest.json (source revision, built_at, file hashes) next to
// <bundle>/electron. The GUI files listed there are re-hashed before the release
// is shown; the daemon's build is a separate identity used only for comparison.
export interface GuiBuild {
  state: 'verified' | 'unverified' | 'unavailable';
  source?: string;
  builtAt?: string;
  reason: string;
}
export interface DaemonBuild {
  source: string;
  modified: boolean;
}

export const HEX40 = /^[0-9a-f]{40}$/;

/** Fail-soft: the daemon reports `source` (some builds `revision`). */
export function parseDaemonBuild(raw: unknown): DaemonBuild | undefined {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return undefined;
  const b = raw as Record<string, unknown>;
  const source = [b.source, b.revision].find((v): v is string => typeof v === 'string' && HEX40.test(v));
  return source ? { source, modified: b.modified === true } : undefined;
}

export function formatBuildTime(iso: string, timeZone?: string, locale?: string) {
  return new Intl.DateTimeFormat(locale, {
    year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', timeZoneName: 'short', ...(timeZone ? { timeZone } : {}),
  }).format(new Date(iso));
}

/** Header text (GUI release + build date/time) and tooltip; daemon only compared. */
export function headerVersion(gui: GuiBuild | undefined, daemon: DaemonBuild | undefined, timeZone?: string, locale?: string) {
  const lines: string[] = [];
  let text: string, mismatch = false;
  if (!gui) {
    text = 'version …';
    lines.push('GUI build: checking');
  } else if (gui.state === 'verified') {
    text = gui.source!.slice(0, 7) + ' · ' + (gui.builtAt ? 'built ' + formatBuildTime(gui.builtAt, timeZone, locale) : 'build time unavailable');
    lines.push('GUI release: ' + gui.source + ' (' + gui.reason + ')', 'Built: ' + (gui.builtAt ?? 'not recorded by this release'));
  } else {
    text = gui.state === 'unverified' ? 'unverified build' : 'version unavailable';
    lines.push('GUI build: ' + gui.reason);
  }
  if (daemon) {
    lines.push('Daemon build: ' + daemon.source + (daemon.modified ? ' (modified)' : ''));
    if (gui?.state === 'verified' && daemon.source !== gui.source) {
      mismatch = true;
      text += ' · daemon ' + daemon.source.slice(0, 7);
    }
    if (daemon.modified) text += ' · daemon modified';
  } else lines.push('Daemon build: unavailable');
  return { text, title: lines.join('\n'), mismatch };
}

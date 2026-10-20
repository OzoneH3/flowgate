import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { createHash } from 'node:crypto';
import type { Application, ClientState } from './protocol';
export const iconKey = (a: Application) => JSON.stringify([a.key, a.revision, a.executable]);
const MAX_FILE = 256 * 1024;
async function read(file: string) {
  const s = await fs.stat(file);
  if (!s.isFile() || s.size > MAX_FILE) throw Error('Icon metadata too large');
  return fs.readFile(file);
}
export function desktopEntry(text: string): Record<string, string> {
  const fields: Record<string, string> = Object.create(null);
  let active = false;
  for (const line of text.split(/\r?\n/)) {
    if (line.startsWith('[')) {
      active = line === '[Desktop Entry]';
      continue;
    }
    if (!active || line.startsWith('#')) continue;
    const i = line.indexOf('=');
    if (i > 0) fields[line.slice(0, i)] = line.slice(i + 1);
  }
  return fields;
}
// Parse only the executable token. Never execute Exec, TryExec, actions, or a shell.
export function execToken(exec: string): string | undefined {
  const match = exec.match(/^(?:"([^"\\]+)"|([^\s"'\\]+))(?:\s|$)/);
  const token = match?.[1] || match?.[2];
  if (
    !token ||
    /[%$`]/.test(token) ||
    ['env', 'sh', 'bash', 'flatpak', 'snap', 'wine', 'wine64'].includes(path.basename(token))
  )
    return;
  return token;
}
export function safeIcon(data: Buffer, ext: string): boolean {
  if (data.length > MAX_FILE) return false;
  if (ext === '.png')
    return (
      data.length >= 24 &&
      data.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10])) &&
      [data.readUInt32BE(16), data.readUInt32BE(20)].every((n) => n > 0 && n <= 1024)
    );
  if (ext !== '.svg') return false;
  const s = data.toString('utf8');
  return (
    /<svg[\s>]/i.test(s) &&
    !/<!DOCTYPE|<!ENTITY|<\?xml-stylesheet|<(?:script|foreignObject|image|iframe|object|embed|audio|video)\b|\son[a-z]+\s*=|@import|(?:href\s*=\s*["']\s*(?!#))|url\(\s*["']?(?!#)[^)]/i.test(
      s,
    )
  );
}
export class ApplicationIcons {
  private allowed = new Map<string, Application>();
  private cache = new Map<string, Promise<string | null>>();
  private images = new Map<string, { data: Buffer; type: string }>();
  private ready: Promise<void>;
  private imageBytes = 0;
  private entries = new Map<string, Set<string>>();
  private names = new Map<string, Set<string>>();
  // Desktop entries (display only) for Electron apps on a shared runtime.
  private desktops: { executable: string; name?: string; wmclass?: string }[] = [];
  private scripts = new Map<string, Promise<string>>();
  private themes: string[] = [];
  private iconRoots: string[];
  private themeDirs = new Map<string, string[]>();
  constructor(
    private home = os.homedir(),
    private dataDirs = [
      process.env.XDG_DATA_HOME || path.join(home, '.local/share'),
      ...(process.env.XDG_DATA_DIRS || '/usr/local/share:/usr/share').split(':'),
    ],
    private searchPath = (process.env.PATH || '/usr/bin:/bin').split(':'),
  ) {
    this.iconRoots = [
      path.join(home, '.icons'),
      ...dataDirs.map((d) => path.join(d, 'icons')),
    ].filter(path.isAbsolute);
    this.ready = this.index();
  }
  observe(state: ClientState) {
    this.allowed.clear();
    const add = (a?: Application) => {
      if (a?.key && a.executable && this.allowed.size < 4096) this.allowed.set(iconKey(a), a);
    };
    for (const p of Object.values(state.observation.activity?.processes || {})) add(p.application);
    for (const r of state.observation.activity?.rows || []) add(r.display_application);
    for (const e of state.control.events) {
      add(e.attribution.application);
      // The launching program (display only), e.g. Heroic for its nile helper.
      add(e.attribution.provenance?.parent?.application);
    }
    for (const p of Object.values(state.observation.activity?.processes || {})) add(p.provenance?.parent?.application);
  }
  private async executable(token: string) {
    for (const p of path.isAbsolute(token)
      ? [token]
      : this.searchPath.filter(path.isAbsolute).map((d) => path.join(d, token))) {
      try {
        const s = await fs.stat(p);
        if (s.isFile() && s.mode & 0o111) return await fs.realpath(p);
      } catch {}
    }
    return '';
  }
  private async index() {
    const seen = new Set<string>();
    for (const dir of this.dataDirs.filter(path.isAbsolute)) {
      let files: string[] = [];
      try {
        files = await fs.readdir(path.join(dir, 'applications'));
      } catch {}
      for (const file of files.filter((f) => f.endsWith('.desktop')).slice(0, 2048)) {
        if (seen.has(file)) continue;
        seen.add(file);
        try {
          const entry = desktopEntry((await read(path.join(dir, 'applications', file))).toString());
          if (entry.Type !== 'Application' || entry.Hidden === 'true' || !entry.Icon) continue;
          const token = execToken(entry.Exec || '');
          if (!token) continue;
          const executable = await this.executable(token);
          if (!executable) continue;
          const icons = this.entries.get(executable) || new Set<string>();
          icons.add(entry.Icon);
          this.entries.set(executable, icons);
          if (entry.Name && entry.Name.length < 256) {
            const names = this.names.get(executable) || new Set<string>();
            names.add(entry.Name);
            this.names.set(executable, names);
          }
          if (this.desktops.length < 2048)
            this.desktops.push({ executable, name: entry.Name?.slice(0, 255), wmclass: entry.StartupWMClass?.slice(0, 255) });
        } catch {}
      }
    }
    let theme = 'breeze';
    try {
      const config = (
        await read(
          path.join(process.env.XDG_CONFIG_HOME || path.join(this.home, '.config'), 'kdeglobals'),
        )
      ).toString();
      theme = config.match(/\[Icons\][^[]*?\bTheme=([^\r\n]+)/)?.[1] || theme;
    } catch {}
    const visit = async (name: string) => {
      if (!/^[\w.-]+$/.test(name) || this.themes.includes(name) || this.themes.length >= 16) return;
      this.themes.push(name);
      for (const root of this.iconRoots)
        try {
          const text = (await read(path.join(root, name, 'index.theme'))).toString();
          const dirs = text.match(/^Directories=(.*)$/m)?.[1].split(',') || [];
          this.themeDirs.set(
            path.join(root, name),
            dirs
              .filter((d) => !d.includes('..') && !path.isAbsolute(d))
              .sort((a, b) => score(a) - score(b)),
          );
          for (const parent of (text.match(/^Inherits=(.*)$/m)?.[1] || '').split(','))
            await visit(parent.trim());
        } catch {}
    };
    await visit(theme);
    await visit('hicolor');
  }
  // Steam game: the verified executable's realpath must lie under a library's steamapps/common/<installdir>,
  // and exactly one app manifest in that library must declare that installdir. The app ID comes only from
  // that manifest (never from a name); the icon is Steam's own steam_icon_<appid> in the icon theme.
  private steamLibraries?: Promise<string[]>;
  private steamManifests = new Map<string, Promise<Map<string, { appid: string; name?: string }>>>();
  private libraries() {
    this.steamLibraries ??= (async () => {
      const roots = new Set<string>();
      for (const base of [path.join(this.home, '.local/share/Steam'), path.join(this.home, '.steam/steam')])
        try {
          const text = (await read(path.join(base, 'steamapps/libraryfolders.vdf'))).toString();
          for (const m of text.matchAll(/"path"\s+"([^"\r\n]{1,1024})"/g)) {
            const p = m[1].replace(/\\\\/g, '\\');
            if (path.isAbsolute(p) && !p.split('/').includes('..')) roots.add(p);
          }
        } catch {}
      return [...roots].slice(0, 64);
    })();
    return this.steamLibraries;
  }
  private manifests(library: string) {
    if (!this.steamManifests.has(library))
      this.steamManifests.set(
        library,
        (async () => {
          const byDir = new Map<string, { appid: string; name?: string }>(),
            ambiguous = new Set<string>();
          let files: string[] = [];
          try {
            files = await fs.readdir(path.join(library, 'steamapps'));
          } catch {}
          for (const file of files.filter((f) => /^appmanifest_\d{1,12}\.acf$/.test(f)).slice(0, 4096))
            try {
              const text = (await read(path.join(library, 'steamapps', file))).toString();
              const appid = text.match(/"appid"\s+"(\d{1,12})"/)?.[1];
              const dir = text.match(/"installdir"\s+"([^"\r\n/]{1,255})"/)?.[1];
              if (!appid || !dir || appid !== file.slice(12, -4)) continue;
              if (byDir.has(dir)) ambiguous.add(dir);
              const name = text.match(/"name"\s+"([^"\r\n]{1,255})"/)?.[1];
              byDir.set(dir, { appid, name });
            } catch {}
          for (const dir of ambiguous) byDir.delete(dir);
          return byDir;
        })(),
      );
    return this.steamManifests.get(library)!;
  }
  private async steamGame(executable: string) {
    if (!executable) return undefined;
    for (const library of await this.libraries())
      try {
        const common = await fs.realpath(path.join(library, 'steamapps/common'));
        if (!executable.startsWith(common + '/')) continue;
        const installdir = executable.slice(common.length + 1).split('/')[0];
        const app = (await this.manifests(library)).get(installdir);
        if (app) return app;
      } catch {}
    return undefined;
  }
  private async resolve(executable: string) {
    const actual = await this.executable(executable);
    let candidates = this.entries.get(actual);
    if (candidates?.size !== 1) {
      const game = await this.steamGame(actual);
      if (!game) return null;
      candidates = new Set(['steam_icon_' + game.appid]);
    }
    const name = [...candidates][0];
    const files: string[] = [];
    if (path.isAbsolute(name)) files.push(name);
    else if (/^[\w.+-]+$/.test(name)) {
      for (const theme of this.themes) {
        // Icon theme spec: a theme's Directories apply in every base directory, including user roots
        // (e.g. ~/.local/share/icons/hicolor holding Steam's steam_icon_<appid>) that ship no index.theme.
        const dirs =
          this.iconRoots.map((r) => this.themeDirs.get(path.join(r, theme))).find((d) => d?.length) || [];
        for (const root of this.iconRoots)
          for (const dir of dirs)
            for (const ext of ['.png', '.svg'])
              files.push(path.join(root, theme, dir, name.endsWith(ext) ? name : name + ext));
      }
      for (const root of this.dataDirs)
        files.push(
          path.join(root, 'pixmaps', name + '.png'),
          path.join(root, 'pixmaps', name + '.svg'),
        );
    }
    for (const file of files)
      try {
        const data = await read(file),
          ext = path.extname(file).toLowerCase();
        if (!safeIcon(data, ext)) continue;
        const id = createHash('sha256').update(data).digest('hex') + ext;
        if (!this.images.has(id)) {
          if (this.images.size >= 256 || this.imageBytes + data.length > 16 * 1024 * 1024)
            return null;
          this.imageBytes += data.length;
        }
        this.images.set(id, { data, type: ext === '.png' ? 'image/png' : 'image/svg+xml' });
        return 'flowgate://app/icons/' + id;
      } catch {}
    return null;
  }
  // A verified Electron app (executable = its bundle) gets the desktop entry
  // whose launcher script names exactly that bundle (e.g. /usr/bin/heroic runs
  // electron43 /usr/lib/heroic-games-launcher/app.asar); otherwise a unique
  // StartupWMClass equal to the package name. Display only, never identity.
  private async electronDesktop(a: Application) {
    const bundle = a.hosted?.state === 'verified' ? a.hosted.bundle || a.executable : '';
    if (a.kind !== 'electron' || !bundle) return undefined;
    const script = (exe: string) => {
      if (!this.scripts.has(exe))
        this.scripts.set(
          exe,
          fs
            .stat(exe)
            .then((st) => (st.size <= 65536 ? read(exe).then((b) => b.toString('latin1')) : ''))
            .catch(() => ''),
        );
      return this.scripts.get(exe)!;
    };
    const byScript: typeof this.desktops = [];
    for (const d of this.desktops) if ((await script(d.executable)).includes(bundle)) byScript.push(d);
    const unique = (list: typeof this.desktops) =>
      new Set(list.map((d) => d.executable)).size === 1 ? list[0] : undefined;
    const pkg = a.hosted?.package_name?.toLowerCase();
    return (
      unique(byScript) ??
      (pkg ? unique(this.desktops.filter((d) => d.wmclass?.toLowerCase() === pkg)) : undefined)
    );
  }
  async request(value: unknown) {
    if (
      !Array.isArray(value) ||
      value.length > 128 ||
      value.some((v) => typeof v !== 'string' || v.length > 8192)
    )
      throw Error('Invalid icon identities');
    await this.ready;
    const result: Record<string, string | null> = Object.create(null);
    for (const key of value as string[]) {
      const a = this.allowed.get(key);
      if (!a) {
        result[key] = null;
        continue;
      }
      if (!this.cache.has(key)) {
        if (this.cache.size >= 2048) this.cache.delete(this.cache.keys().next().value!);
        this.cache.set(
          key,
          a.kind === 'electron'
            ? this.electronDesktop(a).then((d) => (d ? this.resolve(d.executable) : null))
            : this.resolve(a.display_executable || a.executable.replace(/ \(deleted\)$/, '')),
        );
      }
      result[key] = await this.cache.get(key)!;
    }
    return result;
  }
  async metadata(value: unknown) {
    const icons = await this.request(value);
    const result: Record<
      string,
      { icon: string | null; name?: string; source: 'desktop-metadata' | 'steam-manifest' | 'unavailable' }
    > = Object.create(null);
    for (const [key, icon] of Object.entries(icons)) {
      const app = this.allowed.get(key);
      if (app?.kind === 'electron') {
        const entry = await this.electronDesktop(app);
        result[key] = { icon, name: entry?.name, source: entry || icon ? 'desktop-metadata' : 'unavailable' };
        continue;
      }
      const executable =
        app &&
        (await this.executable(
          app.display_executable || app.executable.replace(/ \(deleted\)$/, ''),
        ));
      const names = executable ? this.names.get(executable) : undefined;
      const desktop = this.entries.get(executable || '')?.size === 1 || names?.size === 1;
      const game = desktop ? undefined : await this.steamGame(executable || '');
      result[key] = {
        icon,
        name: names?.size === 1 ? [...names][0] : game?.name,
        source: desktop ? 'desktop-metadata' : game ? 'steam-manifest' : icon ? 'desktop-metadata' : 'unavailable',
      };
    }
    return result;
  }
  asset(name: string) {
    return this.images.get(name);
  }
}
function score(dir: string) {
  const n = Number(dir.match(/(?:^|\/)(\d+)(?:x\d+)?(?:\/|$)/)?.[1]);
  return n ? Math.abs(n - 16) : dir.includes('scalable') ? 20 : 100;
}

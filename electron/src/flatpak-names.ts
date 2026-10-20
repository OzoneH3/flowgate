import fs from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';
import type { Application } from './protocol';

// Display-only interpretation of a deliberately small wrapper subset. Never run
// shell code. Only literal initial assignments and a final quoted exec target
// are accepted; commands, substitutions and unknown variables are not expanded.
export function wrapperTarget(text: string, dataHome: string): string | undefined {
  if (text.length > 65536) return;
  const vars = new Map<string, string>([['XDG_DATA_HOME', dataHome]]);
  const lines = text.split(/\r?\n/).map(s => s.trim()).filter(s => s && !s.startsWith('#'));
  const expand = (value: string) => {
    let valid = true;
    const out = value.replace(/\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))/g, (_, a, b) => {
      const v = vars.get(a || b); if (v === undefined) valid = false; return v || '';
    });
    return valid && !/[\$`\\\n\r]/.test(out) ? out : undefined;
  };
  let i = 0;
  for (; i < lines.length; i++) {
    const m = lines[i].match(/^([A-Za-z_][A-Za-z0-9_]*)="([^"`]*)"$/);
    if (!m) break;
    if (vars.has(m[1])) return;
    const v = expand(m[2]); if (v === undefined) return; vars.set(m[1], v);
  }
  const tail = lines.slice(i);
  if (tail.some(line => /\b(eval|source|read)\b|^\./.test(line))) return;
  for (const name of vars.keys())
    if (tail.some(line => new RegExp(`\\b${name}\\s*=`).test(line))) return;
  const executions = tail.filter(line => /^exec\s/.test(line));
  if (executions.length !== 1 || executions[0] !== lines.at(-1)) return;
  const exec = executions[0].match(/^exec "([^"`]+)"(?: "\$@")?$/);
  const target = exec && expand(exec[1]);
  if (!target || !path.isAbsolute(target) || target.split('/').includes('..')) return;
  return target;
}

async function bounded(file: string) {
  const st = await fs.stat(file); if (!st.isFile() || st.size > 65536) throw Error('Metadata too large');
  return fs.readFile(file, 'utf8');
}
async function matches(app: Application, uid: number, file: string) {
  const actual = await fs.realpath(file), st = await fs.stat(actual, { bigint: true });
  const key = createHash('sha256').update(`${uid}|native||${actual}`).digest('hex');
  return st.isFile() && key === app.key && `${st.ino}:${st.size}:${st.mtimeNs}:${st.ctimeNs}` === app.revision;
}

export async function installedFlatpakName(
  app: Application, uid: number, roots: string[], home: string,
  deploymentName: (file: string) => Promise<string | undefined>,
): Promise<string | undefined> {
  if (app.kind && app.kind !== 'native') return;
  const sandbox = app.executable.startsWith('/app/');
  const dataRoot = path.join(home, '.var/app') + '/';
  const privateData = app.executable.startsWith(dataRoot);
  if (!sandbox && !privateData) return;
  const names = new Set<string>();
  for (const root of roots.filter(path.isAbsolute)) {
    let ids: string[]; try { ids = await fs.readdir(root); } catch { continue; }
    for (const id of ids.slice(0, 256)) {
      if (!/^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+){2,}$/.test(id)) continue;
      if (privateData && !app.executable.startsWith(dataRoot + id + '/data/')) continue;
      try {
        const deployment = await fs.realpath(path.join(root, id, 'current/active'));
        const files = path.join(deployment, 'files');
        if (sandbox) {
          const candidate = path.join(files, app.executable.slice('/app/'.length));
          if (!(await fs.realpath(candidate)).startsWith(files + '/')) continue;
          if (await matches(app, uid, candidate)) {
            const name = await deploymentName(candidate); if (name) names.add(name);
          }
        } else {
          // Match a desktop entry's own wrapper and its exact literal exec
          // target. Other executables in the same private data directory fail.
          if (!await matches(app, uid, app.executable)) continue;
          const desktop = await bounded(path.join(files, 'share/applications', id + '.desktop'));
          const section = desktop.split('[Desktop Entry]')[1]?.split(/^\[/m)[0] || '';
          const command = section.match(/^Exec=([A-Za-z0-9_.-]+)(?: %\w)?$/m)?.[1];
          if (!command) continue;
          const wrapper = path.join(files, 'bin', command);
          if (!(await fs.realpath(wrapper)).startsWith(files + '/')) continue;
          const target = wrapperTarget(await bounded(wrapper), path.join(home, '.var/app', id, 'data'));
          if (!target || await fs.realpath(target) !== await fs.realpath(app.executable)) continue;
          const name = await deploymentName(wrapper); if (name) names.add(name);
        }
      } catch { /* Unknown or changed installations keep their executable name. */ }
    }
  }
  return names.size === 1 ? [...names][0] : undefined;
}

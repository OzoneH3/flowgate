import { execFile } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';

export const kwin = (args: string[]) =>
  new Promise<string>((resolve, reject) =>
    execFile('qdbus6', ['org.kde.KWin', ...args], { timeout: 1500, maxBuffer: 4096 }, (err, out) =>
      err ? reject(err) : resolve(out.trim()),
    ),
  );

export function mainActivationScript(pid: number, title: string) {
  if (!Number.isSafeInteger(pid) || pid <= 0) throw Error('Invalid window owner');
  return `const matches = workspace.windowList().filter(w =>
    w.pid === ${pid} && w.normalWindow && w.caption === ${JSON.stringify(title)});
    if (matches.length === 1) {
      const main = matches[0];
      if (main.minimized) main.minimized = false;
      workspace.activeWindow = main;
    }`;
}

// KWin can minimize a Wayland toplevel without updating Electron's state.
// Only an explicit tray Open asks KWin to restore and activate the main window.
export async function activateKDEMain(profile: string, pid: number, title: string) {
  const dir = await fs.mkdtemp(path.join(profile, 'main-activation-'));
  const name = `flowgate-main-${pid}-${path.basename(dir)}`;
  let id: string | undefined;
  try {
    const file = path.join(dir, 'activate.js');
    await fs.writeFile(file, mainActivationScript(pid, title), { mode: 0o600 });
    const loaded = await kwin(['/Scripting', 'org.kde.kwin.Scripting.loadScript', file, name]);
    if (!/^\d+$/.test(loaded)) throw Error('KWin activation unavailable');
    id = loaded;
    await kwin([`/Scripting/Script${id}`, 'org.kde.kwin.Script.run']);
  } finally {
    if (id) await kwin([`/Scripting/Script${id}`, 'org.kde.kwin.Script.stop']).catch(() => {});
    await kwin(['/Scripting', 'org.kde.kwin.Scripting.unloadScript', name]).catch(() => {});
    await fs.rm(dir, { recursive: true, force: true });
  }
}

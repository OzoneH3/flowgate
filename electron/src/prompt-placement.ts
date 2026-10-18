import { execFile } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import type { Rect } from './pane-model';
// Wayland clients cannot choose global coordinates. KDE provides a compositor API.
// One-shot, no installed rules/hooks: own PID + fixed prompt caption, numeric geometry only.
export const PROMPT_TITLE = 'FlowGate — connection permission';
export function promptTitle(windowID: number) {
  if (!Number.isSafeInteger(windowID) || windowID <= 0) throw Error('Invalid permission window');
  return `${PROMPT_TITLE} · ${windowID}`;
}
export function placementScript(pid: number, windowID: number, bounds: Rect) {
  if (
    !Number.isSafeInteger(pid) ||
    pid <= 0 ||
    Object.values(bounds).some((v) => !Number.isFinite(v))
  )
    throw Error('Invalid placement');
  return `for (const w of workspace.windowList()) { if (w.pid === ${pid} && w.caption === ${JSON.stringify(promptTitle(windowID))}) { w.frameGeometry = ${JSON.stringify(bounds)}; workspace.activeWindow = w; print("FLOWGATE_PROMPT_PLACED_${pid}", JSON.stringify(w.frameGeometry)); } }`;
}
const dbus = (args: string[]) =>
  new Promise<string>((resolve, reject) =>
    execFile('qdbus6', ['org.kde.KWin', ...args], { timeout: 1500, maxBuffer: 4096 }, (err, out) =>
      err ? reject(err) : resolve(out.trim()),
    ),
  );
export async function placeKDEPrompt(
  profile: string,
  pid: number,
  windowID: number,
  bounds: Rect,
  isLive: () => boolean,
) {
  if (process.platform !== 'linux') return;
  const dir = await fs.mkdtemp(path.join(profile, 'prompt-placement-'));
  const name = `flowgate-prompt-${pid}-${path.basename(dir)}`;
  const file = path.join(dir, 'place.js');
  try {
    if (!isLive()) return;
    await fs.writeFile(file, placementScript(pid, windowID, bounds), { mode: 0o600 });
    const id = await dbus(['/Scripting', 'org.kde.kwin.Scripting.loadScript', file, name]);
    if (!/^\d+$/.test(id)) throw Error('KWin placement unavailable');
    if (!isLive()) return;
    await dbus([`/Scripting/Script${id}`, 'org.kde.kwin.Script.run']);
    await new Promise((resolve) => setTimeout(resolve, 200));
  } catch (error) {
    console.info('FlowGate: compositor controls prompt placement:', String(error));
  } finally {
    await dbus(['/Scripting', 'org.kde.kwin.Scripting.unloadScript', name]).catch(() => {});
    await fs.rm(dir, { recursive: true, force: true });
  }
}

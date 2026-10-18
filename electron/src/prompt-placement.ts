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
export function placementScript(pid: number, windowID: number, bounds: Rect, outputName?: string) {
  if (
    !Number.isSafeInteger(pid) ||
    pid <= 0 ||
    Object.values(bounds).some((v) => !Number.isFinite(v))
  )
    throw Error('Invalid placement');
  const placement = outputName
    ? `const output=workspace.screens.find(o=>o.name===${JSON.stringify(outputName)}); if(!output)throw new Error('Configured primary output unavailable'); workspace.sendClientToScreen(w,output); const area=workspace.clientArea(KWin.PlacementArea,output,workspace.currentDesktopForScreen(output)); const width=Math.min(${bounds.width},area.width),height=Math.min(${bounds.height},area.height); w.frameGeometry={x:area.x+area.width-width,y:area.y+area.height-height,width:width,height:height};`
    : `w.frameGeometry = ${JSON.stringify(bounds)};`;
  return `for (const w of workspace.windowList()) { if (w.pid === ${pid} && w.caption === ${JSON.stringify(promptTitle(windowID))}) { ${placement} workspace.activeWindow = w; print("FLOWGATE_PROMPT_PLACED_${pid}", ${JSON.stringify(outputName || 'native-primary')}, JSON.stringify(w.frameGeometry)); } }`;
}
export function primaryOutputName(raw: unknown) {
  const outputs = (raw as { outputs?: unknown[] })?.outputs;
  if (!Array.isArray(outputs) || outputs.length > 64) return;
  const candidates = outputs
    .filter(
      (o): o is { name: string; priority: number; connected: boolean } =>
        !!o &&
        typeof o === 'object' &&
        typeof (o as any).name === 'string' &&
        (o as any).name.length <= 128 &&
        (o as any).connected === true &&
        Number.isSafeInteger((o as any).priority) &&
        (o as any).priority > 0,
    )
    .sort((a, b) => a.priority - b.priority);
  return candidates[0]?.name;
}
async function configuredPrimaryOutput(): Promise<string | undefined> {
  return new Promise((resolve) =>
    execFile(
      'kscreen-doctor',
      ['-j'],
      {
        timeout: 1500,
        maxBuffer: 1024 * 1024,
        env: {
          ...process.env,
          QT_QPA_PLATFORM: 'wayland',
          WAYLAND_DISPLAY: process.env.WAYLAND_DISPLAY || 'wayland-0',
          XDG_RUNTIME_DIR: process.env.XDG_RUNTIME_DIR || `/run/user/${process.getuid?.()}`,
        },
      },
      (err, out) => {
        try {
          resolve(err ? undefined : primaryOutputName(JSON.parse(out)));
        } catch {
          resolve(undefined);
        }
      },
    ),
  );
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
    const outputName = await configuredPrimaryOutput();
    if (!isLive()) return;
    await fs.writeFile(file, placementScript(pid, windowID, bounds, outputName), { mode: 0o600 });
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

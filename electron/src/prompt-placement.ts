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
  return `for (const w of workspace.windowList()) { if (w.pid === ${pid} && w.caption === ${JSON.stringify(promptTitle(windowID))}) { ${placement} print("FLOWGATE_PROMPT_PLACED_${pid}", ${JSON.stringify(outputName || 'native-primary')}, JSON.stringify(w.frameGeometry)); } }`;
}
// Bounded startup handshake. KWin/Wayland configure is asynchronous and a desktop
// restore script can overwrite the first request. Bind one native window, settle
// its initial output/geometry, then verify the compact frame; never run on polls.
export function placementQML(
  pid: number,
  windowID: number,
  bounds: Rect,
  outputName?: string,
  reveal = true,
) {
  placementScript(pid, windowID, bounds, outputName); // validate fixed numeric input
  return `import QtQuick
import org.kde.kwin
QtObject {
  id: root
  property var workspace: Workspace
  property var target: null
  function added(w) { if(w.pid===${pid} && w.caption===${JSON.stringify(promptTitle(windowID))}) { target=w; w.keepAbove=true; w.opacity=0; console.log("FLOWGATE_PROMPT_HELD",${pid},${windowID},w.output.name,w.opacity); } }
  Component.onCompleted: { workspace.windowAdded.connect(root.added); for(const w of workspace.stackingOrder) added(w); }
  Component.onDestruction: { workspace.windowAdded.disconnect(root.added); if(target) target.opacity=${reveal ? 1 : 0}; }
  property var state: ({ticks:0, nativeID:null, previous:"", stable:0, applied:0, waited:0, confirmed:0})
  property Timer clock: Timer { interval:50; repeat:true; running:true; onTriggered:root.tick() }
  function tick() {
    const s=state;
    if (++s.ticks>40) { console.log("FLOWGATE_PROMPT_UNCONFIRMED",${pid},${windowID}); if(target) target.opacity=${reveal ? 1 : 0}; clock.stop(); return; }
    const matches=workspace.stackingOrder.filter(w=>w.pid===${pid} && w.caption===${JSON.stringify(promptTitle(windowID))});
    if(matches.length!==1) return;
    const w=matches[0], nativeID=String(w.internalId);
    if(s.nativeID!==null && s.nativeID!==nativeID) { clock.stop(); return; }
    s.nativeID=nativeID;
    const output=workspace.screens.find(o=>o.name===${JSON.stringify(outputName || '')}) || workspace.screens[0];
    if(!output) return;
    const area=workspace.clientArea(KWin.PlacementArea,output,workspace.currentDesktopForScreen(output));
    const width=Math.min(${bounds.width},area.width), height=Math.min(${bounds.height},area.height);
    const desired={x:area.x+area.width-width,y:area.y+area.height-height,width:width,height:height};
    const g=w.frameGeometry, stamp=JSON.stringify(g);
    if(!s.applied) {
      if(w.output!==output) { workspace.sendClientToScreen(w,output); s.stable=0; return; }
      s.stable=stamp===s.previous?s.stable+1:0; s.previous=stamp;
      if(s.stable<3) return;
      w.setMaximize(false,false);
      w.frameGeometry=desired; s.applied=1; return;
    }
    const correct=w.output===output && ["x","y","width","height"].every(k=>Math.abs(g[k]-desired[k])<=1);
    s.confirmed=correct?s.confirmed+1:0;
    if(s.confirmed>=3) {
      w.keepAbove=true; w.opacity=${reveal ? 1 : 0}; w.minimized=${!reveal};
      console.log("FLOWGATE_PROMPT_CONFIRMED",JSON.stringify({pid:${pid},windowID:${windowID},nativeID:nativeID,output:output.name,area:area,geometry:g,attempts:s.applied}));
      clock.stop(); return;
    }
    // One bounded correction for a late initial restore/configure, never a poll loop.
    if(!correct && ++s.waited===8 && s.applied===1) { w.frameGeometry=desired; s.applied=2; }
  }
}`;
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
        (o as any).enabled !== false &&
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
          if (err) console.info('FlowGate: KDE primary discovery unavailable:', err.message);
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
  onPrepared: (installed: boolean) => void = () => {},
  reveal = true,
) {
  if (process.platform !== 'linux') {
    onPrepared(false);
    return;
  }
  let prepared = false;
  let scriptID: string | undefined;
  const dir = await fs.mkdtemp(path.join(profile, 'prompt-placement-'));
  const name = `flowgate-prompt-${pid}-${path.basename(dir)}`;
  const file = path.join(dir, 'place.qml');
  try {
    if (!isLive()) return;
    const outputName = await configuredPrimaryOutput();
    if (!isLive()) return;
    await fs.writeFile(file, placementQML(pid, windowID, bounds, outputName, reveal), {
      mode: 0o600,
    });
    const id = await dbus([
      '/Scripting',
      'org.kde.kwin.Scripting.loadDeclarativeScript',
      file,
      name,
    ]);
    if (!/^\d+$/.test(id)) throw Error('KWin placement unavailable');
    scriptID = id;
    if (!isLive()) return;
    await dbus([`/Scripting/Script${id}`, 'org.kde.kwin.Script.run']);
    prepared = true;
    onPrepared(true);
    await new Promise((resolve) => setTimeout(resolve, 2300));
  } catch (error) {
    console.info('FlowGate: compositor controls prompt placement:', String(error));
  } finally {
    if (!prepared) onPrepared(false);
    // Declarative scripts must be stopped as well as unloaded; otherwise their
    // DBus object can survive and intercept a later reused script ID.
    if (scriptID)
      await dbus([`/Scripting/Script${scriptID}`, 'org.kde.kwin.Script.stop']).catch(() => {});
    await dbus(['/Scripting', 'org.kde.kwin.Scripting.unloadScript', name]).catch(() => {});
    await fs.rm(dir, { recursive: true, force: true });
  }
}

// Content-driven resize: a one-shot compositor placement, without activation or opacity changes.
export async function resizeKDEPrompt(
  profile: string,
  pid: number,
  windowID: number,
  bounds: Rect,
  visible = true,
) {
  if (process.platform !== 'linux') return;
  const dir = await fs.mkdtemp(path.join(profile, 'prompt-resize-'));
  const name = `flowgate-resize-${pid}-${path.basename(dir)}`;
  let id: string | undefined;
  try {
    const file = path.join(dir, 'resize.js');
    await fs.writeFile(
      file,
      placementScript(pid, windowID, bounds, await configuredPrimaryOutput()).replace(
        ' print(',
        ` w.opacity=${visible ? 1 : 0}; w.minimized=${!visible}; print(`,
      ),
      { mode: 0o600 },
    );
    id = await dbus(['/Scripting', 'org.kde.kwin.Scripting.loadScript', file, name]);
    if (!/^\d+$/.test(id)) throw Error('Invalid resize script');
    await dbus([`/Scripting/Script${id}`, 'org.kde.kwin.Script.run']);
  } catch (error) {
    console.info('FlowGate: compositor resize unavailable:', String(error));
  } finally {
    if (id) await dbus([`/Scripting/Script${id}`, 'org.kde.kwin.Script.stop']).catch(() => {});
    await dbus(['/Scripting', 'org.kde.kwin.Scripting.unloadScript', name]).catch(() => {});
    await fs.rm(dir, { recursive: true, force: true });
  }
}

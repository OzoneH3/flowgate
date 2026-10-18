import { contextBridge, ipcRenderer } from 'electron';
const api = {
  applicationIcons: (keys: unknown) => ipcRenderer.invoke('application:icons', keys),
  graph: (value: unknown) => ipcRenderer.invoke('graph', value),
  paneSnapshot: () => ipcRenderer.invoke('pane:snapshot'),
  paneUpdate: (value: unknown) => ipcRenderer.invoke('pane:update', value),
  paneControl: (kind: unknown, action: unknown) => ipcRenderer.invoke('pane:control', kind, action),
  paneRule: (action: unknown) => ipcRenderer.invoke('pane:rule', action),
  onPaneFrame: (fn: (frame: unknown) => void) => {
    const listener = (_e: unknown, frame: unknown) => fn(frame);
    ipcRenderer.on('pane:frame', listener);
    return () => ipcRenderer.removeListener('pane:frame', listener);
  },
};
contextBridge.exposeInMainWorld('flowgate', Object.freeze(api));

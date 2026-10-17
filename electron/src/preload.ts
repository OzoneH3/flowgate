import { contextBridge, ipcRenderer } from 'electron';
import type { Bridge, ClientState, Decision } from './protocol';
const api: Bridge = {
  snapshot: () => ipcRenderer.invoke('snapshot'),
  subscribe: (fn) => {
    const listener = (_event: unknown, state: ClientState) => fn(state);
    ipcRenderer.on('state', listener);
    return () => ipcRenderer.removeListener('state', listener);
  },
  decide: (d: Decision) => ipcRenderer.invoke('decide', d),
  openPrompt: (id: string) => ipcRenderer.invoke('prompt:open', id),
  dismissPrompt: () => ipcRenderer.invoke('prompt:dismiss'),
};
contextBridge.exposeInMainWorld('flowgate', Object.freeze(api));

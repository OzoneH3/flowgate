import type { ClientState } from './protocol';
// Electron-main transport sequence, not daemon policy authority or a rule revision.
// It orders async invoke replies against pushed frames within this app lifetime.
export function acceptsPublication(previous: ClientState | undefined, next: ClientState) {
  return (
    previous?.publication === undefined ||
    next.publication === undefined ||
    next.publication >= previous.publication
  );
}

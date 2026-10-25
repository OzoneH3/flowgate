import { execFile } from 'node:child_process';

// Plasma asks applications to close before logind emits PrepareForShutdown.
// A read-only session query distinguishes that close from the ordinary tray action.
export function kdeSessionEnding(): Promise<boolean> {
  if (process.platform !== 'linux') return Promise.resolve(false);
  return new Promise((resolve) => {
    execFile('qdbus6', [
      'org.kde.ksmserver', '/KSMServer', 'org.kde.KSMServerInterface.isShuttingDown',
    ], { timeout: 500, maxBuffer: 1024 }, (error, stdout) => {
      resolve(!error && stdout.trim() === 'true');
    });
  });
}

export class SessionExit {
  private checking?: Promise<boolean>;
  private stopping = false;
  constructor(private probe: () => Promise<boolean>, private quit: () => void) {}

  shutdown() {
    if (this.stopping) return;
    this.stopping = true;
    this.quit();
  }

  async close(ordinaryClose: () => void) {
    if (this.stopping) return;
    // Several windows can receive close requests in the same shutdown sequence.
    const check = this.checking ||= this.probe().catch(() => false);
    const ending = await check;
    if (this.checking === check) this.checking = undefined;
    if (this.stopping) return;
    if (ending) this.shutdown();
    else ordinaryClose();
  }
}

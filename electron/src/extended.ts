import fs from 'node:fs';
import path from 'node:path';
import { spawn, execFile } from 'node:child_process';
export class ExtendedMonitoring {
  state = {
    busy: false,
    message: 'Extended monitoring is opt-in; no collector is started by this frontend.',
  };
  private pendingUntil = 0;
  constructor(private root: string) {}
  view(active: boolean) {
    if (active || Date.now() > this.pendingUntil) this.state.busy = false;
    return this.state;
  }
  async action(value: unknown) {
    if (value !== 'enable' && value !== 'stop') throw Error('Invalid extended monitoring action');
    if (this.state.busy)
      throw Error('A collector operation is pending; inspect its authentication terminal');
    if (value === 'enable') {
      if (!fs.existsSync(path.join(this.root, '.workspace/udp-collector')))
        throw Error(
          'Optional UDP helper is not built. Run scripts/build-udp.sh first. TCP monitoring remains available.',
        );
      this.state = {
        busy: true,
        message:
          'Authentication requested in a separate terminal. Collector availability comes from the observer; no firewall activation.',
      };
      this.pendingUntil = Date.now() + 120000;
      const child = spawn(
        'konsole',
        [
          '--separate',
          '--hold',
          '-e',
          'python3',
          path.join(this.root, 'scripts/traffic-control.py'),
        ],
        { detached: true, stdio: 'ignore' },
      );
      child.on('error', (e) => {
        this.state = { busy: false, message: 'Authentication terminal failed: ' + e.message };
      });
      child.unref();
      return;
    }
    this.state = {
      busy: true,
      message: 'Requesting collector Stop; waiting for authenticated acknowledgement.',
    };
    this.pendingUntil = Date.now() + 6000;
    await new Promise<void>((resolve) =>
      execFile(
        path.join(this.root, '.workspace/flowgate'),
        ['udp-stop'],
        { timeout: 5000, maxBuffer: 65536 },
        (error, stdout, stderr) => {
          try {
            if (error) throw Error(stderr || error.message);
            const result = JSON.parse(stdout);
            if (result.version !== 1 || result.state !== 'stopped')
              throw Error('Missing stopped acknowledgement');
            this.state = {
              busy: false,
              message:
                'Collector acknowledged Stop. TCP monitoring and firewall evaluation are unchanged.',
            };
          } catch (e) {
            this.state = { busy: false, message: 'Collector Stop not confirmed: ' + String(e) };
          }
          resolve();
        },
      ),
    );
  }
}

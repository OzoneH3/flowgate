import { DaemonEvaluation } from './daemon-evaluation';
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import type { EvaluationAction, EvaluationState } from './protocol';
import { Backend, call } from './backend';
export class Evaluation {
  state: EvaluationState = {
    phase: 'idle',
    message: 'Default startup is read-only. Enforcement state is unknown until confirmed.',
    generation: '',
    busy: false,
    starting: false,
  };
  private jobs: {
    dir: string;
    action: string;
    sequence: number;
    started: number;
    ready: boolean;
  }[] = [];
  private timer: NodeJS.Timeout;
  private daemon: DaemonEvaluation;
  view(): EvaluationState {
    return this.daemon.supported() ? this.daemon.view() : { ...this.state, mode: 'legacy' };
  }
  constructor(
    private root: string,
    private backend: Backend,
    private endpoint = '/run/flowgate-api/control.sock',
  ) {
    this.daemon = new DaemonEvaluation(backend);
    this.timer = setInterval(() => void this.poll(), 300);
  }
  close() {
    clearInterval(this.timer);
  } // Detached terminal and controller retain their original deadline.
  async action(action: unknown, profile: unknown) {
    if (this.daemon.supported()) return this.daemon.action(action, profile);
    if (
      typeof action !== 'string' ||
      !['start', 'stop', 'status', 'recover', 'cancel'].includes(String(action)) ||
      (profile !== undefined &&
        (typeof profile !== 'string' || !['incoming', 'both'].includes(profile)))
    )
      throw Error('Invalid evaluation action');
    if (action === 'cancel') {
      const job = this.jobs.find((j) => j.action === 'start' && !j.ready);
      if (!job) throw Error('No authentication to cancel');
      fs.writeFileSync(path.join(job.dir, 'cancel'), 'cancel\n', { mode: 0o600 });
      this.state.message = 'Cancellation requested; waiting for cleanup acknowledgement.';
      return;
    }
    if (this.state.busy) throw Error('Authentication or cleanup already in progress');
    const c = this.backend.view().control;
    if (action === 'stop' && !/^[a-f0-9]{32}$/.test(c.generation || this.state.generation))
      throw Error('No verified generation; use Status or Recovery');
    if (
      action === 'start' &&
      ((c.connected && !c.readOnly) || this.jobs.some((j) => j.action === 'start'))
    )
      throw Error('A controller is already active or starting');
    if (action === 'start' && !['incoming', 'both'].includes(String(profile)))
      throw Error('Select a profile');
    const dir = fs.mkdtempSync(path.join(this.root, '.workspace/electron-control-'));
    fs.chmodSync(dir, 0o700);
    fs.writeFileSync(
      path.join(dir, 'request.json'),
      JSON.stringify({ profile: profile || 'incoming' }),
      { mode: 0o600 },
    );
    const token = c.generation || this.state.generation;
    const args = [
      '--separate',
      '-e',
      'python3',
      path.join(this.root, 'scripts/desktop-control.py'),
      '--action',
      String(action),
      '--job',
      dir,
    ];
    if (action !== 'start' && /^[a-f0-9]{32}$/.test(token)) args.push('--token', token);
    const job = { dir, action: String(action), sequence: 0, started: Date.now(), ready: false };
    this.jobs.push(job);
    this.state = {
      phase: 'authentication',
      message: 'Authenticate in the terminal. Activity remains read-only and available.',
      generation: token,
      busy: true,
      starting: action === 'start',
    };
    const child = spawn('konsole', args, { detached: true, stdio: 'ignore' });
    child.on('error', (e) => {
      this.jobs = this.jobs.filter((j) => j !== job);
      this.state = {
        ...this.state,
        phase: 'failed',
        message: 'Terminal launch failed: ' + e.message,
        busy: false,
        starting: false,
      };
    });
    child.unref();
  }
  private polling = false;
  private async poll() {
    if (this.polling) return;
    this.polling = true;
    try {
      for (const j of [...this.jobs]) {
        let r: any;
        try {
          const f = path.join(j.dir, 'result.json');
          if (fs.statSync(f).size > 65536) throw Error('Oversized bridge response');
          r = JSON.parse(fs.readFileSync(f, 'utf8'));
        } catch {
          if (Date.now() - j.started > (j.ready ? 360000 : 90000)) {
            this.jobs = this.jobs.filter((x) => x !== j);
            this.state = {
              ...this.state,
              phase: 'unknown',
              message: 'Bridge timed out; enforcement state unknown. Use status/recovery.',
              busy: false,
              starting: false,
            };
          }
          continue;
        }
        if (
          r.version !== 1 ||
          !Number.isInteger(r.sequence) ||
          r.sequence <= j.sequence ||
          typeof r.phase !== 'string' ||
          typeof r.generation !== 'string' ||
          typeof r.message !== 'string'
        )
          continue;
        j.sequence = r.sequence;
        if (r.phase === 'ready') {
          try {
            const reply = await call(this.endpoint, { operation: 'list' });
            if (
              reply.error ||
              reply.generation !== r.generation ||
              reply.mode !== 'host-enforcement' ||
              reply.enforcement?.state !== 'active'
            )
              throw Error('Authenticated readiness mismatch');
            this.backend.controller = this.endpoint;
            await this.backend.pollControl();
            j.ready = true;
            this.state = {
              phase: 'active',
              message: 'Backend readiness verified. Original deadline remains authoritative.',
              generation: r.generation,
              busy: false,
              starting: false,
            };
          } catch (e) {
            this.state = {
              phase: 'unknown',
              message: 'Readiness not verified: ' + String(e) + '. Use Stop or recovery.',
              generation: r.generation,
              busy: false,
              starting: false,
            };
          }
        } else if (['stopped', 'failed', 'cancelled', 'unknown', 'status'].includes(r.phase)) {
          this.jobs = this.jobs.filter((x) => x !== j);
          if (r.phase === 'status' && /^[a-f0-9]{32}$/.test(r.generation)) {
            try {
              const reply = await call(this.endpoint, { operation: 'list' });
              if (
                reply.generation === r.generation &&
                reply.mode === 'host-enforcement' &&
                !reply.error
              ) {
                this.backend.controller = this.endpoint;
                await this.backend.pollControl();
              }
            } catch {}
          }
          if (r.generation && this.state.generation && r.generation !== this.state.generation)
            continue;
          if (r.phase === 'stopped') this.jobs = this.jobs.filter((x) => x.action !== 'start');
          this.state = {
            phase: r.phase,
            message: r.message,
            generation: r.generation,
            busy: false,
            starting: false,
          };
        } else if (!j.ready)
          this.state = {
            phase: r.phase,
            message: r.message,
            generation: r.generation,
            busy: true,
            starting: j.action === 'start',
          };
      }
    } finally {
      this.polling = false;
    }
  }
}

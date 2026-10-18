import { displayAmount, type DisplayUnit } from './display-units';
import type { GraphView, Source } from './history';
export class TrafficGraph {
  private id = '';
  private unit: DisplayUnit = 'autoByte';
  private hoverAt?: number;
  private seconds = 60;
  private source: Source = 'tcp';
  private sourceChosen = false;
  private view?: GraphView;
  private request = 0;
  private signature = '';
  private canvas: HTMLCanvasElement;
  private selector: HTMLSelectElement;
  constructor(private host: HTMLElement) {
    host.innerHTML =
      '<header class="graph-heading"><h2>Traffic chart</h2><div class="graph-controls"><select id="graphSource" aria-label="Measurement source"><option value="tcp">TCP transport payload</option><option value="udp">UDP API-reported bytes</option></select><select id="graphWindow" aria-label="History window"><option value="60">60 s</option><option value="300">5 min</option><option value="600">10 min</option></select></div></header><div id="graphValues" class="graph-values"></div><canvas id="trafficCanvas" role="img" aria-label="Observed upload and download rates over time"></canvas><p id="graphStatus"></p><div id="graphSample" class="graph-sample" hidden role="status"></div><details class="graph-explanation"><summary>Measurement details</summary><p class="graph-scope">All observed sockets, independent of table filters. History starts here; gaps are not zero. TCP transport and UDP API payload are separate sources. Totals include local socket perspectives.</p></details>';
    this.canvas = host.querySelector('canvas')!;
    this.canvas.tabIndex = 0;
    this.canvas.title =
      'Point to inspect an observed sample; click to keep details. Left/Right keys inspect samples, Escape closes details.';
    let pinned = false;
    const inspect = (x: number) => {
      if (!this.view) return;
      this.hoverAt =
        this.view.now -
        this.seconds *
          1000 *
          (1 - Math.max(0, Math.min(1, (x - 55) / (this.canvas.clientWidth - 110))));
      this.sample();
    };
    this.canvas.onpointermove = (e) => {
      if (!pinned) inspect(e.offsetX);
    };
    this.canvas.onpointerleave = () => {
      if (!pinned) {
        this.host.querySelector<HTMLElement>('#graphSample')!.hidden = true;
        this.hoverAt = undefined;
      }
    };
    this.canvas.onclick = (e) => {
      pinned = !pinned;
      inspect(e.offsetX);
    };
    this.canvas.onkeydown = (e) => {
      if (e.key === 'Escape') {
        pinned = false;
        this.hoverAt = undefined;
        this.host.querySelector<HTMLElement>('#graphSample')!.hidden = true;
      }
      if (e.key === 'ArrowLeft' || e.key === 'ArrowRight') {
        e.preventDefault();
        pinned = true;
        this.hoverAt =
          (this.hoverAt ?? this.view?.now ?? 0) + (e.key === 'ArrowLeft' ? -1000 : 1000);
        this.sample();
      }
    };
    // Reference: a round pause/resume button beside the plot ("Continue refreshing the chart").
    const pause = document.createElement('button');
    pause.id = 'graphPause';
    pause.type = 'button';
    pause.className = 'graph-pause';
    pause.textContent = '❚❚';
    pause.title = 'Pause refreshing the chart';
    pause.setAttribute('aria-pressed', 'false');
    pause.onclick = () => {
      this.paused = !this.paused;
      pause.textContent = this.paused ? '▶' : '❚❚';
      pause.title = this.paused ? 'Continue refreshing the chart' : 'Pause refreshing the chart';
      pause.setAttribute('aria-pressed', String(this.paused));
      if (!this.paused) {
        this.signature = '';
        void this.update(this.lastId || this.id, this.lastStamp);
      } else this.request++;
    };
    this.canvas.after(pause);
    this.selector = host.querySelector('#graphSource')!;
    this.selector.onchange = () => {
      this.source = this.selector.value as Source;
      this.sourceChosen = true;
      this.draw();
    };
    host.querySelector<HTMLSelectElement>('#graphWindow')!.onchange = (e) => {
      this.seconds = Number((e.target as HTMLSelectElement).value);
      this.signature = '';
      void this.update(this.id, 'window');
    };
    new ResizeObserver(() => {
      if (!document.hidden) this.draw();
    }).observe(this.canvas);
  }
  setUnit(unit: DisplayUnit) {
    this.unit = unit;
    this.draw();
  }
  private sample() {
    const box = this.host.querySelector<HTMLElement>('#graphSample')!;
    const points = this.view?.points.filter((p) => p.source === this.source) || [];
    const point = points.reduce<(typeof points)[number] | undefined>(
      (best, p) =>
        !best || Math.abs(p.at - this.hoverAt!) < Math.abs(best.at - this.hoverAt!) ? p : best,
      undefined,
    );
    box.hidden = false;
    const requested =
      this.view?.wallNow !== undefined
        ? this.view.wallNow - (this.view.now - this.hoverAt!)
        : undefined;
    if (!point || Math.abs(point.at - this.hoverAt!) > 2000) {
      box.textContent = `${requested ? new Date(requested).toLocaleTimeString() : 'Selected time'} · No observed sample. Gaps are not zero.`;
      return;
    }
    box.textContent = `${point.wallAt ? new Date(point.wallAt).toLocaleTimeString() : 'Observed sample'} · Download ${displayAmount(point.down, true, this.unit)} · Upload ${displayAmount(point.up, true, this.unit)} · ${point.note}${point.partial ? ' · Partial coverage' : ''}`;
  }
  setSource(source: Source) {
    this.sourceChosen = true;
    this.source = source;
    this.selector.value = source;
    this.draw();
  }
  paused = false;
  private lastStamp = '';
  private lastId = '';
  async update(id: string, stamp: string) {
    this.lastStamp = stamp;
    this.lastId = id;
    if (this.paused) {
      // Keep the newest requested selection; any in-flight fetch is invalidated.
      this.request++;
      return;
    }
    if (document.hidden || this.host.closest('main')?.hidden) return;
    const signature = id + ':' + stamp + ':' + this.seconds;
    if (signature === this.signature) return;
    this.signature = signature;
    const changed = id !== this.id;
    this.id = id;
    const request = ++this.request;
    try {
      const view = await window.flowgate.graph({ id, seconds: this.seconds });
      if (request !== this.request || this.paused || document.hidden) return;
      this.view = view;
      const sources = new Set(view.points.map((p) => p.source));
      if (changed && !this.sourceChosen && !sources.has(this.source) && sources.size) {
        this.source = [...sources][0];
        this.selector.value = this.source;
      }
      this.draw();
    } catch (e) {
      this.host.querySelector('#graphStatus')!.textContent = String(e);
    }
  }
  private draw() {
    if (!this.view || document.hidden || this.host.closest('main')?.hidden) return;
    const v = this.view,
      points = v.points.filter((p) => p.source === this.source),
      latest = points.at(-1);
    const current = v.connected && latest && v.now - latest.at < 5000 ? latest : undefined;
    const values = this.host.querySelector('#graphValues')!;
    values.replaceChildren();
    for (const [name, value, color] of [
      ['Download', latest?.downloaded, 'graph-download'],
      ['', undefined, 'graph-selection'],
      ['Upload', latest?.uploaded, 'graph-upload'],
    ] as const) {
      const span = document.createElement('span');
      span.className = color;
      // Chart name follows the Activity selection, as in the reference legend.
      span.textContent =
        color === 'graph-selection'
          ? document.getElementById('selectedName')?.dataset.label ||
            document.getElementById('selectedName')?.textContent ||
            ''
          : `${name} (${displayAmount(value, false, this.unit)}${latest?.partial ? ' *' : ''})`;
      if (color !== 'graph-selection')
        span.title = `Observed socket totals, not Internet usage; ${this.source.toUpperCase()} source only. ${current ? 'Current' : 'Historical/unavailable'} rate: ${displayAmount(color === 'graph-download' ? current?.down : current?.up, true, this.unit)}. ${latest?.note || ''}`;
      values.append(span);
    }
    const status = !v.connected
      ? 'Observer disconnected — gaps; no current rates'
      : !latest
        ? 'No measured history for this source. UDP requires opt-in collection.'
        : latest.note;
    this.host.querySelector('#graphStatus')!.textContent =
      (this.id ? `${status}${latest?.partial ? ' · Partial coverage' : ''}` : v.message) +
      (v.limited ? ' · History shortened by memory bound' : '');
    this.host.title = `${v.label}\n${v.message}\n${latest?.note || ''}`;
    const width = this.canvas.clientWidth,
      height = this.canvas.clientHeight;
    if (!width || !height) return;
    const dpr = window.devicePixelRatio || 1;
    this.canvas.width = Math.round(width * dpr);
    this.canvas.height = Math.round(height * dpr);
    const c = this.canvas.getContext('2d')!;
    c.scale(dpr, dpr);
    const palette = getComputedStyle(this.canvas);
    const tokenColor = (name: string) => palette.getPropertyValue(name).trim();
    c.fillStyle = tokenColor('--fg-content');
    c.fillRect(0, 0, width, height);
    const left = 55,
      right = 55,
      top = 10,
      bottom = 20,
      w = width - left - right,
      h = height - top - bottom;
    const ceilings = { down: 1, up: 1 };
    for (const key of ['down', 'up'] as const) {
      const max = Math.max(1, ...points.map((p) => p[key] ?? 0));
      ceilings[key] = Math.pow(10, Math.ceil(Math.log10(max)));
    }
    c.font = '10px ' + palette.fontFamily;
    c.lineWidth = 1;
    c.strokeStyle = tokenColor('--fg-border');
    for (let i = 0; i <= 2; i++) {
      const y = top + (h * i) / 2;
      c.beginPath();
      c.moveTo(left, y);
      c.lineTo(width - right, y);
      c.stroke();
      c.fillStyle = tokenColor('--fg-chart-down');
      c.fillText(displayAmount(ceilings.down * (1 - i / 2), true, this.unit), 1, y + 3);
      c.fillStyle = tokenColor('--fg-chart-up');
      c.fillText(
        displayAmount(ceilings.up * (1 - i / 2), true, this.unit),
        width - right + 3,
        y + 3,
      );
    }
    c.fillStyle = tokenColor('--fg-muted');
    for (let i = 0; i <= 10; i++) {
      const x = left + (w * i) / 10;
      c.beginPath();
      c.moveTo(x, top);
      c.lineTo(x, top + h);
      c.stroke();
      if (i % 5 === 0) {
        const secondsAgo = this.seconds * (1 - i / 10);
        const text = v.wallNow
          ? new Date(v.wallNow - secondsAgo * 1000).toLocaleTimeString([], {
              hour: '2-digit',
              minute: '2-digit',
              second: '2-digit',
              hour12: false,
            })
          : `${secondsAgo}s ago`;
        c.textAlign = 'center';
        c.fillText(text, x, height - 4);
        c.textAlign = 'start';
      }
    }
    for (const [key, color] of [
      ['down', tokenColor('--fg-chart-down')],
      ['up', tokenColor('--fg-chart-up')],
    ] as const) {
      c.strokeStyle = color;
      c.setLineDash([]);
      c.fillStyle = color;
      c.lineWidth = 1;
      c.beginPath();
      let continuous = false;
      for (const p of points) {
        const value = p[key];
        if (value === undefined) {
          continuous = false;
          continue;
        }
        const x = left + w * (1 - (v.now - p.at) / (this.seconds * 1000)),
          y = top + h * (1 - value / ceilings[key]);
        if (!continuous || p.breakBefore) c.moveTo(x, y);
        else c.lineTo(x, y);
        c.fillRect(x - 1, y - 1, 2, 2);
        continuous = true;
      }
      c.stroke();
    }
    if (this.hoverAt !== undefined) this.sample();
    this.canvas.setAttribute(
      'aria-label',
      `${this.source === 'tcp' ? 'TCP transport payload' : 'UDP API-reported bytes'}; ${values.textContent}; ${status}. Window ${this.seconds} seconds. Gaps are unavailable, not zero.`,
    );
  }
}

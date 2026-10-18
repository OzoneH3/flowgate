import { amount } from './model';
import type { GraphView, Source } from './history';
export class TrafficGraph {
  private id = '';
  private seconds = 60;
  private source: Source = 'tcp';
  private view?: GraphView;
  private request = 0;
  private signature = '';
  private canvas: HTMLCanvasElement;
  private selector: HTMLSelectElement;
  constructor(private host: HTMLElement) {
    host.innerHTML =
      '<h2>Traffic chart</h2><div class="graph-controls"><select id="graphSource" aria-label="Measurement source"><option value="tcp">TCP transport payload</option><option value="udp">UDP API-reported bytes</option></select><select id="graphWindow" aria-label="History window"><option value="60">60 s</option><option value="300">5 min</option></select></div><div id="graphValues" class="graph-values"></div><canvas id="trafficCanvas" role="img" aria-label="Observed upload and download rates over time"></canvas><p id="graphStatus"></p><p class="graph-scope">All observed sockets, independent of table filters. History starts here; gaps are not zero.</p>';
    this.canvas = host.querySelector('canvas')!;
    this.selector = host.querySelector('#graphSource')!;
    this.selector.onchange = () => {
      this.source = this.selector.value as Source;
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
  async update(id: string, stamp: string) {
    if (document.hidden || this.host.closest('main')?.hidden) return;
    const signature = id + ':' + stamp + ':' + this.seconds;
    if (signature === this.signature) return;
    this.signature = signature;
    const changed = id !== this.id;
    this.id = id;
    const request = ++this.request;
    try {
      const view = await window.flowgate.graph({ id, seconds: this.seconds });
      if (request !== this.request || document.hidden) return;
      this.view = view;
      const sources = new Set(view.points.map((p) => p.source));
      if (changed && !sources.has(this.source) && sources.size) {
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
    const current = v.connected && latest && v.now - latest.at < 60000 ? latest : undefined;
    const values = this.host.querySelector('#graphValues')!;
    values.replaceChildren();
    for (const [name, value, color] of [
      ['↓ Download', current?.down, 'graph-download'],
      ['↑ Upload', current?.up, 'graph-upload'],
    ] as const) {
      const span = document.createElement('span');
      span.className = color;
      span.textContent = `${name} ${amount(value, true)}${current?.partial ? ' *' : ''}`;
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
      right = 8,
      top = 18,
      bottom = 22,
      w = width - left - right,
      h = height - top - bottom;
    const max = Math.max(1, ...points.flatMap((p) => [p.up || 0, p.down || 0]));
    const ceiling = Math.pow(2, Math.ceil(Math.log2(max)));
    c.font = '10px ' + palette.fontFamily;
    c.lineWidth = 1;
    c.strokeStyle = tokenColor('--fg-border');
    c.fillStyle = tokenColor('--fg-muted');
    for (let i = 0; i <= 2; i++) {
      const y = top + (h * i) / 2;
      c.beginPath();
      c.moveTo(left, y);
      c.lineTo(width - right, y);
      c.stroke();
      c.fillText(amount(ceiling * (1 - i / 2), true), 1, y + 3);
    }
    for (let i = 0; i <= 2; i++) {
      const x = left + (w * i) / 2;
      c.beginPath();
      c.moveTo(x, top);
      c.lineTo(x, top + h);
      c.stroke();
      c.fillText(
        i === 2 ? 'now' : `${Math.round(this.seconds * (1 - i / 2))}s ago`,
        x - (i === 2 ? 18 : 0),
        height - 5,
      );
    }
    for (const [key, color] of [
      ['down', tokenColor('--fg-chart-down')],
      ['up', tokenColor('--fg-chart-up')],
    ] as const) {
      c.strokeStyle = color;
      c.setLineDash(key === 'up' ? [3, 2] : []);
      c.fillStyle = color;
      c.lineWidth = 1.4;
      c.beginPath();
      let continuous = false;
      for (const p of points) {
        const value = p[key];
        if (value === undefined) {
          continuous = false;
          continue;
        }
        const x = left + w * (1 - (v.now - p.at) / (this.seconds * 1000)),
          y = top + h * (1 - value / ceiling);
        if (!continuous || p.breakBefore) c.moveTo(x, y);
        else c.lineTo(x, y);
        c.fillRect(x - 1, y - 1, 2, 2);
        continuous = true;
      }
      c.stroke();
    }
    this.canvas.setAttribute(
      'aria-label',
      `${this.source === 'tcp' ? 'TCP transport payload' : 'UDP API-reported bytes'}; ${values.textContent}; ${status}. Window ${this.seconds} seconds. Gaps are unavailable, not zero.`,
    );
  }
}

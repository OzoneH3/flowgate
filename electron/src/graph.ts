import { displayAmount, type DisplayUnit } from './display-units';
import type { GraphPoint, GraphView, Source } from './history';
import { chartDefaults, type ChartSettings } from './pane-model';
import { chartRange, shiftedEnd, adjacentSample, observationSpacing } from './chart-view';
interface Controls {
  change?: (patch: Partial<ChartSettings>) => void;
  source?: (source: Source) => void;
}
export class TrafficGraph {
  private id = '';
  private lastId = '';
  private lastStamp = '';
  private unit: DisplayUnit = 'autoByte';
  private source: Source = 'tcp';
  private view?: GraphView;
  private request = 0;
  private signature = '';
  private settings = chartDefaults();
  private hoverAt?: number;
  private paint?: number;
  private header: HTMLElement;
  private canvas: HTMLCanvasElement;
  private selector: HTMLSelectElement;
  private drag?: {
    x: number;
    y: number;
    end: number;
    seconds: number;
    button: number;
    moved: boolean;
  };
  constructor(
    private host: HTMLElement,
    private controls: Controls = {},
    header?: HTMLElement,
  ) {
    host.classList.add('traffic-chart');
    host.innerHTML = `
      <canvas id="trafficCanvas" role="img" tabindex="0" aria-label="Observed upload and download rates over time"></canvas>
      <div id="graphSample" class="graph-sample ui-readout" hidden role="status">
        <span></span><div>
          <button id="graphPrevious" aria-label="Previous observed sample">‹</button>
          <button id="graphNext" aria-label="Next observed sample">›</button>
          <button id="graphSampleClose">Close</button>
        </div>
      </div>`;
    this.header = header ?? document.createElement('header');
    this.header.classList.add('graph-heading');
    if (!header) {
      this.header.innerHTML = '<h2>Traffic chart</h2>';
      host.prepend(this.header);
    }
    this.header.querySelector('h2')!.insertAdjacentHTML('afterend', `
      <div class="graph-controls" hidden>
        <select id="graphSource" aria-label="Measurement source">
          <option value="tcp">TCP transport payload</option><option value="udp">UDP API-reported bytes</option>
        </select>
        <select id="graphWindow" aria-label="History window">
          <option value="60">60 s</option><option value="300">5 min</option><option value="600">10 min</option>
        </select>
      </div>
      <div id="graphValues" class="graph-values"></div>
      <span class="graph-selection"></span>
      <div class="graph-actions">
        <details class="graph-explanation">
          <summary aria-label="Measurement details"><span class="graph-details-prefix">Measurement </span>details</summary>
          <div class="graph-detail-content">
            <p id="graphStatus"></p>
            <p id="graphContext"></p>
            <p class="graph-scope">History starts here; gaps are not zero. TCP transport and UDP API payload are separate sources. Totals include local socket perspectives. Drag to pan; wheel or +/− zoom. Left/Right inspect recorded samples, Page Up/Down pan, Home returns live. Observation spacing is not a delivery verdict or exact one-second accounting.</p>
          </div>
        </details>
        <button id="graphPause" aria-label="Pause chart" aria-pressed="false">❚❚</button>
        <button id="graphLive" title="Return to live (Home)" aria-label="Return to live" disabled>↻</button>
      </div>`);
    this.canvas = host.querySelector('canvas')!;
    this.canvas.setAttribute('aria-description',
      'Drag to pan; wheel/right-drag or +/− to zoom; Left/Right samples; Home live. Pausing never stops collection.');
    this.canvas.oncontextmenu = (e) => e.preventDefault();
    this.canvas.onpointerdown = (e) => {
      if (!this.view || ![0, 2].includes(e.button)) return;
      this.canvas.setPointerCapture(e.pointerId);
      this.drag = {
        x: e.clientX,
        y: e.clientY,
        end: chartRange(this.view, this.settings, this.source).end,
        seconds: this.settings.seconds,
        button: e.button,
        moved: false,
      };
    };
    this.canvas.onpointermove = (e) => {
      if (this.drag && this.view) {
        const d = this.drag,
          dx = e.clientX - d.x,
          dy = e.clientY - d.y;
        if (Math.abs(dx) + Math.abs(dy) > 3) d.moved = true;
        if (!d.moved) return;
        if (d.button === 0)
          this.apply(
            {
              end: shiftedEnd(
                this.view,
                { ...this.settings, end: d.end },
                this.source,
                (-dx / Math.max(1, this.canvas.clientWidth - 110)) * d.seconds * 1000,
              ),
              paused: false,
            },
            false,
          );
        else
          this.apply(
            {
              seconds: Math.max(5, Math.min(600, d.seconds * Math.exp((dx + dy) / 150))),
              end: d.end,
              paused: false,
            },
            false,
          );
      } else if (this.settings.sampleAt === undefined) this.inspect(e.offsetX);
    };
    this.canvas.onpointerup = (e) => {
      const d = this.drag;
      this.drag = undefined;
      if (this.canvas.hasPointerCapture(e.pointerId))
        this.canvas.releasePointerCapture(e.pointerId);
      if (!d) return;
      if (d.moved)
        this.apply({ seconds: this.settings.seconds, end: this.settings.end, paused: false });
      else if (e.button === 0) {
        this.inspect(e.offsetX);
        if (this.hoverAt !== undefined)
          this.apply({ sampleAt: Math.max(0, this.hoverAt) });
      }
    };
    this.canvas.onpointercancel = () => {
      this.drag = undefined;
    };
    this.canvas.onpointerleave = () => {
      if (this.settings.sampleAt === undefined && !this.drag) {
        this.hoverAt = undefined;
        host.querySelector<HTMLElement>('#graphSample')!.hidden = true;
      }
    };
    this.canvas.addEventListener(
      'wheel',
      (e) => {
        e.preventDefault();
        this.zoom(
          e.deltaY > 0 ? 1.25 : 0.8,
          (e.offsetX - 55) / Math.max(1, this.canvas.clientWidth - 110),
        );
      },
      { passive: false },
    );
    this.canvas.onkeydown = (e) => {
      if (e.key === 'ArrowLeft' || e.key === 'ArrowRight') {
        e.preventDefault();
        this.navigate(e.key === 'ArrowLeft' ? -1 : 1);
      } else if (e.key === '+' || e.key === '=' || e.key === '-') {
        e.preventDefault();
        this.zoom(e.key === '-' ? 1.25 : 0.8, 0.5);
      } else if (e.key === 'Home') {
        e.preventDefault();
        this.live();
      } else if ((e.key === 'PageUp' || e.key === 'PageDown') && this.view) {
        e.preventDefault();
        this.apply({
          end: shiftedEnd(
            this.view,
            this.settings,
            this.source,
            this.settings.seconds * 500 * (e.key === 'PageUp' ? -1 : 1),
          ),
          paused: false,
        });
      } else if (e.key === 'Escape') {
        this.hoverAt = undefined;
        this.apply({ sampleAt: undefined });
        host.querySelector<HTMLElement>('#graphSample')!.hidden = true;
      }
    };
    this.header.querySelector<HTMLButtonElement>('#graphPause')!.onclick = () =>
      this.apply({
        paused: !this.settings.paused,
        end: this.settings.paused ? undefined : this.view?.now,
      });
    this.header.querySelector<HTMLButtonElement>('#graphLive')!.onclick = () => this.live();
    host.querySelector<HTMLButtonElement>('#graphPrevious')!.onclick = () => this.navigate(-1);
    host.querySelector<HTMLButtonElement>('#graphNext')!.onclick = () => this.navigate(1);
    host.querySelector<HTMLButtonElement>('#graphSampleClose')!.onclick = () => {
      this.hoverAt = undefined;
      this.apply({ sampleAt: undefined });
      host.querySelector<HTMLElement>('#graphSample')!.hidden = true;
    };
    this.selector = this.header.querySelector('#graphSource')!;
    this.selector.onchange = () => {
      this.setSource(this.selector.value as Source);
      this.controls.source?.(this.source);
    };
    this.header.querySelector<HTMLSelectElement>('#graphWindow')!.onchange = (e) =>
      this.apply({
        seconds: Number((e.target as HTMLSelectElement).value),
        end: undefined,
        paused: false,
        sampleAt: undefined,
      });
    new ResizeObserver(() => {
      if (!document.hidden) this.draw();
    }).observe(this.canvas);
  }
  get paused() {
    return this.settings.paused;
  }
  setUnit(unit: DisplayUnit) {
    if (this.unit === unit) return;
    this.unit = unit;
    this.draw();
  }
  setSource(source: Source) {
    if (source === this.source) return;
    this.source = source;
    this.selector.value = source;
    this.hoverAt = undefined;
    this.draw();
  }
  setPresentation(settings: ChartSettings) {
    if (this.drag) return;
    if (JSON.stringify(this.settings) === JSON.stringify(settings)) return;
    const was = this.settings.paused;
    this.settings = { ...settings };
    this.sync();
    this.draw();
    if (was && !settings.paused) {
      this.signature = '';
      void this.update(this.lastId || this.id, this.lastStamp);
    }
  }
  private apply(patch: Partial<ChartSettings>, emit = true) {
    const was = this.settings.paused;
    this.settings = { ...this.settings, ...patch };
    this.sync();
    this.draw();
    if (was && !this.settings.paused) {
      this.signature = '';
      void this.update(this.lastId || this.id, this.lastStamp);
    }
    if (emit) this.controls.change?.(patch);
  }
  private live() {
    this.hoverAt = undefined;
    this.apply({ end: undefined, paused: false, sampleAt: undefined });
    this.signature = '';
    void this.update(this.lastId || this.id, this.lastStamp);
  }
  private sync() {
    const pause = this.header.querySelector<HTMLButtonElement>('#graphPause')!;
    pause.textContent = this.settings.paused ? '▶' : '❚❚';
    pause.title = this.settings.paused
      ? 'Resume chart'
      : 'Pause chart';
    pause.setAttribute('aria-pressed', String(this.settings.paused));
    this.header.querySelector<HTMLButtonElement>('#graphLive')!.disabled =
      !this.settings.paused && this.settings.end === undefined;
    this.header.querySelector<HTMLSelectElement>('#graphWindow')!.value = String(
      this.settings.seconds,
    );
  }
  private inspect(x: number) {
    if (!this.view) return;
    const range = chartRange(this.view, this.settings, this.source);
    this.hoverAt =
      range.start +
      range.span * Math.max(0, Math.min(1, (x - 55) / Math.max(1, this.canvas.clientWidth - 110)));
    this.sample();
  }
  private navigate(step: -1 | 1) {
    if (!this.view) return;
    const points = this.view.points.filter((p) => p.source === this.source);
    this.apply({ sampleAt: adjacentSample(points, this.settings.sampleAt ?? this.hoverAt, step) });
  }
  private zoom(factor: number, position: number) {
    if (!this.view) return;
    position = Math.max(0, Math.min(1, position));
    const range = chartRange(this.view, this.settings, this.source),
      seconds = Math.max(5, Math.min(600, this.settings.seconds * factor));
    const anchor = range.start + range.span * position,
      end = anchor + seconds * 1000 * (1 - position);
    this.apply({
      seconds,
      end: shiftedEnd(this.view, { ...this.settings, seconds, end }, this.source, 0),
      paused: false,
    });
  }
  private sample() {
    const box = this.host.querySelector<HTMLElement>('#graphSample')!,
      at = this.settings.sampleAt ?? this.hoverAt;
    if (!this.view || at === undefined) {
      box.hidden = true;
      return;
    }
    const points = this.view.points.filter((p) => p.source === this.source);
    const point = points.reduce<(typeof points)[number] | undefined>(
      (best, p) => (!best || Math.abs(p.at - at) < Math.abs(best.at - at) ? p : best),
      undefined,
    );
    box.hidden = false;
    box.classList.toggle('pinned', this.settings.sampleAt !== undefined);
    const requested =
      this.view.wallNow !== undefined ? this.view.wallNow - (this.view.now - at) : undefined;
    if (!point || Math.abs(point.at - at) > 2000)
      box.querySelector('span')!.textContent =
        `${requested ? new Date(requested).toLocaleTimeString() : 'Selected time'} · No observed sample. Gaps are not zero.`;
    else {
      const spacing = observationSpacing(points, point);
      const content = box.querySelector('span')!;
      content.replaceChildren(
        document.createTextNode(
          `${point.wallAt ? new Date(point.wallAt).toLocaleTimeString() : 'Observed sample'} · `,
        ),
      );
      for (const [key, label, value] of [
        ['download', 'Download', point.down],
        ['upload', 'Upload', point.up],
      ] as const) {
        const series = document.createElement('span');
        series.className = 'graph-' + key;
        series.dataset.sampleSeries = key;
        series.textContent = `${label} ${displayAmount(value, true, this.unit)}`;
        content.append(series, document.createTextNode(' · '));
      }
      content.append(
        document.createTextNode(
          `Observation spacing ${spacing !== undefined ? spacing.toFixed(2) + ' s' : 'unavailable (gap/baseline)'} · ${point.note}${point.partial ? ' · Partial coverage' : ''}`,
        ),
      );
    }
    this.host.querySelector<HTMLButtonElement>('#graphPrevious')!.disabled = !points.some(
      (p) => p.at < at,
    );
    this.host.querySelector<HTMLButtonElement>('#graphNext')!.disabled = !points.some(
      (p) => p.at > at,
    );
  }
  async update(id: string, stamp: string) {
    this.lastId = id;
    this.lastStamp = stamp;
    if (this.paused && this.view) {
      this.request++;
      return;
    }
    if (document.hidden || this.host.hidden || this.host.closest('main')?.hidden) return;
    const signature = id + ':' + stamp;
    if (signature === this.signature) return;
    this.signature = signature;
    this.id = id;
    const request = ++this.request;
    try {
      const view = await window.flowgate.graph({ id, seconds: 600 });
      if (request !== this.request || (this.paused && !!this.view) || document.hidden) return;
      this.view = view;
      this.draw();
    } catch (e) {
      this.header.querySelector('#graphStatus')!.textContent = String(e);
    }
  }
  private draw() {
    const view = this.view;
    if (!view || document.hidden || this.host.hidden || this.host.closest('main')?.hidden) return;
    // Publish readable chart state when data arrives. A native window can defer
    // its animation frames even while its renderer reports a visible document.
    this.updatePresentation(view, chartRange(view, this.settings, this.source).points.at(-1));
    if (this.paint !== undefined) return;
    this.paint = requestAnimationFrame(() => {
      this.paint = undefined;
      this.paintNow();
    });
  }
  private updatePresentation(v: GraphView, latest: GraphPoint | undefined) {
    const current = v.connected && latest && v.now - latest.at < 5000 ? latest : undefined;
    const values = this.header.querySelector('#graphValues')!;
    // Reuse legend buttons so polling cannot steal keyboard focus.
    if (!values.childElementCount) {
      for (const [key, label, cls] of [
        ['download', 'Download', 'graph-download'],
        ['upload', 'Upload', 'graph-upload'],
      ] as const) {
        const item = document.createElement('button');
        item.className = cls;
        item.setAttribute('data-series', key);
        item.setAttribute('aria-label', `Toggle ${label.toLowerCase()} series`);
        item.onclick = () => this.apply({ [key]: !this.settings[key] });
        values.append(item);
      }
    }
    for (const key of ['download', 'upload'] as const) {
      const node = values.querySelector<HTMLElement>(`[data-series="${key}"]`)!;
      node.textContent = `${key === 'download' ? 'Download' : 'Upload'} (${displayAmount(key === 'download' ? latest?.downloaded : latest?.uploaded, false, this.unit)}${latest?.partial ? ' *' : ''})`;
      node.setAttribute('aria-pressed', String(this.settings[key]));
      node.title = `${this.source.toUpperCase()} socket measurements · ${current ? 'current' : 'historical/unavailable'} rate: ${displayAmount(key === 'download' ? current?.down : current?.up, true, this.unit)}.`;
    }
    const selection = this.header.querySelector<HTMLElement>('.graph-selection')!;
    selection.textContent = selection.title = v.label;
    const status = !v.connected
      ? 'Observer disconnected — history retained; gaps'
      : !latest
        ? 'No observed samples in this source/window'
        : latest.note;
    this.header.querySelector('#graphStatus')!.textContent =
      `${this.settings.paused ? 'Paused' : this.settings.end !== undefined ? 'Historical' : 'Live'} · ${Math.round(this.settings.seconds)} s · ${status}${latest?.partial ? ' · Partial coverage' : ''}${v.limited ? ' · History shortened by memory bound' : ''}`;
    this.header.querySelector('#graphContext')!.textContent = v.message;
    this.sync();
    this.sample();
    this.canvas.setAttribute(
      'aria-label',
      `${this.source === 'tcp' ? 'TCP transport payload' : 'UDP API-reported bytes'}; ${v.label}; ${Array.from(values.children, (child) => child.textContent).join('; ')}; ${status}. ${this.settings.end !== undefined ? 'Historical' : 'Live'} window ${Math.round(this.settings.seconds)} seconds. Gaps are unavailable, not zero.`,
    );
  }
  private paintNow() {
    if (!this.view || document.hidden || this.host.hidden || this.host.closest('main')?.hidden) return;
    const width = this.canvas.clientWidth,
      height = this.canvas.clientHeight;
    if (!width || !height) return;
    const palette = getComputedStyle(this.canvas);
    const v = this.view,
      range = chartRange(v, this.settings, this.source),
      points = range.points;
    const dpr = window.devicePixelRatio || 1;
    this.canvas.width = Math.round(width * dpr);
    this.canvas.height = Math.round(height * dpr);
    const c = this.canvas.getContext('2d')!;
    c.scale(dpr, dpr);
    const color = (name: string) => palette.getPropertyValue(name).trim();
    c.fillStyle = color('--fg-content');
    c.fillRect(0, 0, width, height);
    const left = 55,
      right = 55,
      top = 10,
      bottom = 20,
      w = width - left - right,
      h = height - top - bottom;
    const axisLabel = (v: number) => {
      const text = displayAmount(v, true, this.unit);
      const [n, u] = text.split(' ');
      return text.length > 13 && Number(n) > 0 ? Number(n).toExponential(0) + ' ' + u : text;
    };
    const ceilings = { down: 1, up: 1 };
    for (const key of ['down', 'up'] as const)
      ceilings[key] = 10 ** Math.ceil(Math.log10(Math.max(1, ...points.map((p) => p[key] ?? 0))));
    c.font = '10px ' + palette.fontFamily;
    c.lineWidth = 1;
    c.strokeStyle = color('--fg-border');
    for (let i = 0; i <= 2; i++) {
      const y = top + (h * i) / 2;
      c.beginPath();
      c.moveTo(left, y);
      c.lineTo(width - right, y);
      c.stroke();
      c.fillStyle = color('--fg-chart-down');
      c.fillText(axisLabel(ceilings.down * (1 - i / 2)), 1, y + 3);
      c.fillStyle = color('--fg-chart-up');
      c.fillText(axisLabel(ceilings.up * (1 - i / 2)), width - right + 3, y + 3);
    }
    c.fillStyle = color('--fg-muted');
    for (let i = 0; i <= 10; i++) {
      const x = left + (w * i) / 10;
      c.beginPath();
      c.moveTo(x, top);
      c.lineTo(x, top + h);
      c.stroke();
      if (i % 5 === 0) {
        const at = range.start + (range.span * i) / 10;
        const text =
          v.wallNow !== undefined
            ? new Date(v.wallNow - (v.now - at)).toLocaleTimeString([], {
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
                hour12: false,
              })
            : `${Math.round((v.now - at) / 1000)}s ago`;
        c.textAlign = 'center';
        c.fillText(text, x, height - 4);
        c.textAlign = 'start';
      }
    }
    for (const [key, token, visible] of [
      ['down', '--fg-chart-down', this.settings.download],
      ['up', '--fg-chart-up', this.settings.upload],
    ] as const) {
      if (!visible) continue;
      c.strokeStyle = color(token);
      c.fillStyle = color(token);
      c.lineWidth = 1;
      c.setLineDash([]);
      c.beginPath();
      let continuous = false;
      for (const p of points) {
        const value = p[key];
        if (value === undefined) {
          continuous = false;
          continue;
        }
        const x = left + (w * (p.at - range.start)) / range.span,
          y = top + h * (1 - value / ceilings[key]);
        const breakBefore = (key === 'up' ? p.breakUpBefore : p.breakDownBefore) ?? p.breakBefore;
        if (!continuous || breakBefore) c.moveTo(x, y);
        else c.lineTo(x, y);
        c.fillRect(x - 1, y - 1, 2, 2);
        continuous = true;
      }
      c.stroke();
    }
  }
}

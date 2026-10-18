import { isDisplayUnit, type DisplayUnit } from './display-units';
import { allRows, hierarchy, overview, networkOverviews, type Row } from './model';
import type { ClientState } from './protocol';
export type PaneKind = 'info' | 'chart';
export type PaneMode = 'docked' | 'detached' | 'hidden';
export interface ChartSettings {
  seconds: number;
  end?: number;
  paused: boolean;
  download: boolean;
  upload: boolean;
  sampleAt?: number;
}
export const chartDefaults = (): ChartSettings => ({
  seconds: 60,
  paused: false,
  download: true,
  upload: true,
});
export interface Presentation {
  revision: number;
  selection: string;
  generation: string;
  source: 'tcp' | 'udp';
  unit: DisplayUnit;
  panes: Record<PaneKind, PaneMode>;
  chart: ChartSettings;
  row?: Row;
}
export interface PaneFrame {
  presentation: Presentation;
  state: ClientState;
}
export interface PresentationPatch {
  selection?: string;
  generation?: string;
  source?: 'tcp' | 'udp';
  unit?: DisplayUnit;
  chart?: Partial<ChartSettings>;
}
export type PolicyEntry =
  | { kind: 'quick'; direction: 'incoming' | 'outgoing'; tier: 'process' | 'application' }
  | { kind: 'new' }
  | { kind: 'edit' | 'delete'; id: string };
export type PaneRuleAction = { selection: string; generation: string } & PolicyEntry;
export function paneKind(v: unknown): PaneKind {
  if (v !== 'info' && v !== 'chart') throw Error('Unknown pane');
  return v;
}
function object(v: unknown): Record<string, unknown> {
  if (!v || typeof v !== 'object' || Array.isArray(v)) throw Error('Invalid pane request');
  return v as Record<string, unknown>;
}
function keys(v: Record<string, unknown>, allowed: string[]) {
  if (Object.keys(v).some((k) => !allowed.includes(k))) throw Error('Unknown pane field');
}
export function chartPatch(raw: unknown): Partial<ChartSettings> {
  const v = object(raw);
  keys(v, ['seconds', 'end', 'paused', 'download', 'upload', 'sampleAt']);
  for (const k of ['seconds', 'end', 'sampleAt'])
    if (
      v[k] !== undefined &&
      (typeof v[k] !== 'number' ||
        !Number.isFinite(v[k]) ||
        (v[k] as number) < 0 ||
        (v[k] as number) > Number.MAX_SAFE_INTEGER)
    )
      throw Error('Invalid chart time');
  if (v.seconds !== undefined && ((v.seconds as number) < 5 || (v.seconds as number) > 600))
    throw Error('Invalid chart window');
  for (const k of ['paused', 'download', 'upload'])
    if (v[k] !== undefined && typeof v[k] !== 'boolean') throw Error('Invalid chart toggle');
  return v as Partial<ChartSettings>;
}
export function ruleAction(raw: unknown): PaneRuleAction {
  const v = object(raw);
  keys(v, ['selection', 'generation', 'kind', 'direction', 'tier', 'id']);
  for (const k of ['selection', 'generation'])
    if (typeof v[k] !== 'string' || (v[k] as string).length > 4096)
      throw Error('Invalid selection context');
  if (v.kind === 'quick') {
    if (
      !['incoming', 'outgoing'].includes(String(v.direction)) ||
      !['process', 'application'].includes(String(v.tier)) ||
      v.id !== undefined
    )
      throw Error('Invalid rule entry');
  } else if (['edit', 'delete'].includes(String(v.kind))) {
    if (
      typeof v.id !== 'string' ||
      !v.id.length ||
      v.id.length > 256 ||
      v.direction !== undefined ||
      v.tier !== undefined
    )
      throw Error('Invalid rule reference');
  } else if (
    v.kind !== 'new' ||
    v.id !== undefined ||
    v.tier !== undefined ||
    v.direction !== undefined
  )
    throw Error('Invalid rule action');
  return v as PaneRuleAction;
}
// Presentation identity is NOT policy authority. Rules.preview/save still revalidate every target.
export class PaneModel {
  value: Presentation;
  constructor(unit: DisplayUnit = 'autoByte') {
    this.value = {
      revision: 0,
      selection: 'overview',
      generation: '',
      source: 'tcp',
      unit,
      panes: { info: 'docked', chart: 'docked' },
      chart: chartDefaults(),
    };
  }
  observe(state: ClientState) {
    const g = state.observation.generation;
    if (this.value.generation && g !== this.value.generation) {
      this.value.selection = 'overview';
      this.value.row = undefined;
      this.value.chart = chartDefaults();
    }
    this.value.generation = g;
    const a = state.observation.activity;
    const row =
      a && [overview(a), ...networkOverviews(), ...allRows(hierarchy(a))].find((r) => r.id === this.value.selection);
    if (row) this.value.row = { ...row, children: [] };
    else if (this.value.row) this.value.row = { ...this.value.row, rows: [], children: [] };
    this.value.revision++;
  }
  update(raw: unknown, main: boolean, state: ClientState) {
    const v = object(raw);
    keys(v, ['selection', 'generation', 'source', 'unit', 'chart']);
    if (v.selection !== undefined) {
      if (
        !main ||
        typeof v.selection !== 'string' ||
        v.selection.length > 4096 ||
        v.generation !== state.observation.generation
      )
        throw Error('Stale or unauthorized selection');
      const a = state.observation.activity;
      if (
        v.selection !== this.value.selection &&
        (!a || ![overview(a), ...networkOverviews(), ...allRows(hierarchy(a))].some((r) => r.id === v.selection))
      )
        throw Error('Selection unavailable');
    } else if (v.generation !== undefined) throw Error('Generation without selection');
    if (v.source !== undefined && v.source !== 'tcp' && v.source !== 'udp')
      throw Error('Unknown accounting source');
    if (v.unit !== undefined && !isDisplayUnit(v.unit)) throw Error('Unknown display units');
    const chart = v.chart === undefined ? undefined : chartPatch(v.chart);
    if (v.selection !== undefined && v.selection !== this.value.selection) {
      this.value.selection = v.selection as string;
      this.value.row = undefined;
      this.value.chart.sampleAt = undefined;
    }
    if (v.source !== undefined && v.source !== this.value.source) {
      this.value.source = v.source;
      this.value.chart.sampleAt = undefined;
    }
    if (v.unit !== undefined) this.value.unit = v.unit as DisplayUnit;
    if (chart) this.value.chart = { ...this.value.chart, ...chart };
    this.observe(state);
  }
  mode(kind: PaneKind, mode: PaneMode) {
    this.value.panes[kind] = mode;
    this.value.revision++;
  }
}
export interface Rect {
  x: number;
  y: number;
  width: number;
  height: number;
}
export function visibleGeometry(
  raw: Partial<Rect> | undefined,
  areas: Rect[],
  fallback: Rect,
): Rect {
  const a =
    areas.find(
      (a) =>
        raw &&
        Number.isFinite(raw.x) &&
        Number.isFinite(raw.y) &&
        raw.x! < a.x + a.width &&
        raw.y! < a.y + a.height &&
        raw.x! + (raw.width || 0) > a.x &&
        raw.y! + (raw.height || 0) > a.y,
    ) ||
    areas[0] ||
    fallback;
  const width = Math.max(
    Math.min(320, a.width),
    Math.min(a.width, Number.isFinite(raw?.width) ? Math.max(320, raw!.width!) : fallback.width),
  );
  const height = Math.max(
    Math.min(220, a.height),
    Math.min(
      a.height,
      Number.isFinite(raw?.height) ? Math.max(220, raw!.height!) : fallback.height,
    ),
  );
  return {
    width,
    height,
    x: Math.max(a.x, Math.min(a.x + a.width - width, Number.isFinite(raw?.x) ? raw!.x! : a.x + 40)),
    y: Math.max(
      a.y,
      Math.min(a.y + a.height - height, Number.isFinite(raw?.y) ? raw!.y! : a.y + 40),
    ),
  };
}

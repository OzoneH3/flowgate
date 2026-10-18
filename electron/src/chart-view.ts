import type { GraphPoint, GraphView } from './history';
import type { ChartSettings } from './pane-model';
export function chartRange(view: GraphView, settings: ChartSettings, source: 'tcp' | 'udp') {
  const points = view.points.filter((p) => p.source === source);
  const first = points[0]?.at ?? view.now;
  const span = Math.max(5, Math.min(600, settings.seconds)) * 1000;
  const end = Math.max(
    Math.min(view.now, first + span),
    Math.min(view.now, settings.end ?? view.now),
  );
  return {
    start: end - span,
    end,
    span,
    first,
    points: points.filter((p) => p.at >= end - span && p.at <= end),
  };
}
export function shiftedEnd(
  view: GraphView,
  settings: ChartSettings,
  source: 'tcp' | 'udp',
  delta: number,
) {
  return chartRange(
    view,
    { ...settings, end: chartRange(view, settings, source).end + delta },
    source,
  ).end;
}
export function adjacentSample(points: GraphPoint[], at: number | undefined, step: -1 | 1) {
  if (!points.length) return undefined;
  if (at === undefined) return points.at(-1)?.at;
  const next =
    step < 0 ? [...points].reverse().find((p) => p.at < at) : points.find((p) => p.at > at);
  return next?.at ?? at;
}
export function observationSpacing(points: GraphPoint[], point: GraphPoint) {
  const index = points.indexOf(point),
    previous = points[index - 1];
  return !point.breakBefore && previous && point.at > previous.at
    ? (point.at - previous.at) / 1000
    : undefined;
}

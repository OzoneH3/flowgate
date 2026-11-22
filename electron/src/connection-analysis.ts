export const CONNECTION_ANALYSIS_CAPABILITY = 'activity-connection-analysis-v1';
export type ConnectionAnalysisMode = 'recheck' | 'watch';

interface Holder {
  pid: number;
  executable: string;
  windowsImage?: { name: string; executable: string; prefix: string };
  windowsImageReason: string;
}

export interface ConnectionObservation {
  at: string;
  category: string;
  reason: string;
  local: string;
  remote: string;
  holders: Holder[];
  holdersTruncated: boolean;
  application?: { name: string; executable: string; pid?: number };
}

interface AnalyzedConnection {
  protocol: string;
  local: string;
  remote: string;
  fromActivity: boolean;
  observations: ConnectionObservation[];
}

export interface ConnectionAnalysis {
  scope: string;
  finished: string;
  baselineCount: number;
  partial: boolean;
  truncated: boolean;
  connections: AnalyzedConnection[];
}

const invalid = () => Error('Invalid connection analysis response.');

function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw invalid();
  return value as Record<string, unknown>;
}

function list<T>(value: unknown, limit: number, parse: (item: unknown) => T): T[] {
  if (!Array.isArray(value) || value.length > limit) throw invalid();
  return value.map(parse);
}

function string(value: unknown): string {
  if (typeof value !== 'string') throw invalid();
  return value;
}

function optionalString(value: unknown): string {
  return value === undefined ? '' : string(value);
}

function date(value: unknown): string {
  const timestamp = string(value);
  if (!Number.isFinite(Date.parse(timestamp))) throw invalid();
  return timestamp;
}

function count(value: unknown, min = 0): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < min) throw invalid();
  return value;
}

function flag(value: unknown): boolean {
  if (typeof value !== 'boolean') throw invalid();
  return value;
}

function parseObservation(value: unknown): ConnectionObservation {
  const state = object(value);
  const holders = list(state.holders, 8, (value) => {
    const holder = object(value);
    const image = holder.windows_image === undefined ? undefined : object(holder.windows_image);
    return {
      pid: count(holder.pid, 1),
      executable: optionalString(holder.executable),
      windowsImage: image && {
        name: string(image.name),
        executable: optionalString(image.executable),
        prefix: optionalString(image.prefix),
      },
      windowsImageReason: optionalString(holder.windows_image_reason),
    };
  });
  const holdersTruncated = flag(state.holders_truncated ?? false);
  let application: ConnectionObservation['application'];
  if (state.verified_application !== undefined) {
    const app = object(state.verified_application);
    if (!string(app.key) || !string(app.revision)) throw invalid();
    // A Wine broker's holder PID identifies a Linux process, not the Windows executable.
    const pid =
      app.source === 'descriptor-holder-census' && !holdersTruncated && holders.length === 1
        ? holders[0].pid
        : undefined;
    application = {
      name: optionalString(app.name),
      executable: optionalString(app.executable),
      pid,
    };
  }
  return {
    at: date(state.observed_at),
    category: string(state.category),
    reason: string(state.reason),
    local: optionalString(state.local),
    remote: optionalString(state.remote),
    holders,
    holdersTruncated,
    application,
  };
}

export function parseConnectionAnalysis(value: unknown): ConnectionAnalysis {
  const response = object(value);
  const scope = string(response.observation_scope);
  if (!['machine', 'self', 'user-visible'].includes(scope)) throw invalid();
  return {
    scope,
    finished: date(response.finished_at),
    baselineCount: count(response.baseline_unidentified),
    partial:
      !list(response.samples, 64, (sample) => flag(object(sample).complete)).every(Boolean) ||
      !flag(response.baseline_complete),
    truncated: flag(response.truncated),
    connections: list(response.connections, 64, (value) => {
      const connection = object(value);
      const socket = object(connection.socket);
      const observations = list(connection.observations, 8, parseObservation);
      if (!observations.length) throw invalid();
      return {
        protocol: string(socket.protocol),
        local: string(socket.local),
        remote: string(socket.remote),
        fromActivity: flag(connection.from_activity),
        observations,
      };
    }),
  };
}

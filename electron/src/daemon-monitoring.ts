import { performance } from 'node:perf_hooks';
import { call, type Backend } from './backend';
import type { ExtendedState } from './protocol';
export const MONITOR_CAPABILITY = 'daemon-udp-monitor-v1';
// Owns no process: all state and attachment belong to the connected Go daemon.
export class DaemonMonitoring {
  private endpoint = '';
  private recognized = false;
  private inFlight = false;
  private pending?: { generation: string; after: number; uncertain: boolean };
  private message = '';
  constructor(private backend: Backend) {}
  supported() {
    const b = this.backend,
      c = b.view().control,
      o = b.view().observation;
    const endpoint = b.controller || b.observer;
    if (endpoint !== this.endpoint) {
      this.endpoint = endpoint;
      this.recognized = false;
      this.pending = undefined;
      this.message = '';
    }
    if (
      c.capabilities?.includes(MONITOR_CAPABILITY) ||
      o.capabilities?.includes(MONITOR_CAPABILITY)
    )
      this.recognized = true;
    return this.recognized;
  }
  view(): ExtendedState {
    this.supported();
    const { control: c, observation: o } = this.backend.view();
    const primary = !!this.backend.controller;
    const connected = primary ? c.connected : o.connected;
    const monitor = connected ? (primary ? c.trafficMonitor : o.trafficMonitor) : undefined;
    if (this.pending && !this.inFlight && c.connected) {
      if (this.pending.generation !== c.generation) {
        this.message =
          'Daemon session changed; old operation outcome discarded. No automatic restart.';
        this.pending = undefined;
      } else if ((c.snapshotStarted || 0) > this.pending.after) {
        this.message = this.pending.uncertain
          ? 'Authoritative status refreshed after an uncertain response; original operation was not replayed.'
          : this.message;
        this.pending = undefined;
      }
    }
    const busy = this.inFlight || !!this.pending || monitor?.state === 'stopping';
    const canControl =
      connected &&
      primary &&
      c.mode !== 'host-monitor' &&
      !c.readOnly &&
      c.permissions?.can_control_traffic === true &&
      !!c.capabilities?.includes(MONITOR_CAPABILITY);
    const state = !connected
      ? 'unknown'
      : !monitor
        ? 'unsupported'
        : !monitor.available && monitor.state === 'disabled'
          ? 'unsupported'
          : monitor.state;
    return {
      mode: 'daemon',
      busy,
      state,
      partial: monitor?.partial || false,
      canView: (primary ? c.permissions : o.permissions)?.can_view_measurements === true,
      canControl,
      canEnable:
        canControl &&
        o.connected &&
        o.generation === c.generation &&
        !!o.capabilities?.includes(MONITOR_CAPABILITY) &&
        !busy &&
        !!monitor?.available &&
        ['disabled', 'failed'].includes(state),
      canStop: canControl && !busy && ['active', 'starting', 'failed'].includes(state),
      message: [
        !connected
          ? 'Daemon disconnected; collector state unknown.'
          : !monitor
            ? 'Collector metadata unavailable; no legacy fallback.'
            : `${monitor.reason_code}: ${monitor.reason}`,
        this.message,
        primary && o.generation !== c.generation
          ? 'Activity must use this daemon companion; collection sources are never combined.'
          : '',
        !canControl ? 'Collector control is not authorized on this connection.' : '',
        'UDP API-reported bytes per socket across all peers; separate from TCP transport bytes.',
      ]
        .filter(Boolean)
        .join(' '),
    };
  }
  async action(value: unknown) {
    if (value !== 'enable' && value !== 'stop') throw Error('Invalid extended monitoring action');
    const view = this.view(),
      c = this.backend.view().control;
    if (!(value === 'enable' ? view.canEnable : view.canStop))
      throw Error(
        'Collector action unavailable, unauthorized or pending; refresh authoritative status.',
      );
    const endpoint = this.backend.controller!,
      generation = c.generation,
      collector = c.trafficMonitor!.generation;
    this.inFlight = true;
    this.message = 'Request pending; attachment is confirmed only by backend status.';
    let uncertain = false;
    try {
      const r = await call(endpoint, {
        operation: value === 'enable' ? 'traffic-start' : 'traffic-stop',
        generation,
        collector_generation: collector,
      });
      if (
        endpoint !== this.backend.controller ||
        generation !== this.backend.view().control.generation ||
        r.generation !== generation
      )
        throw Error('Stale lifecycle response discarded');
      if (r.error)
        this.message = `${r.error_code}: ${r.error}. Refresh and review before another action.`;
      else if (!r.traffic_monitor) throw Error('Missing collector acknowledgement');
      else
        this.message = `Backend responded ${r.traffic_monitor.state}; awaiting refreshed status. No firewall change.`;
    } catch (e) {
      uncertain = true;
      this.message = `Outcome uncertain: ${String(e)}. Refreshing status; no automatic retry or legacy fallback.`;
    } finally {
      this.inFlight = false;
      if (endpoint === this.backend.controller)
        this.pending = {
          generation,
          after: performance.now(),
          uncertain,
        };
      await this.backend.pollControl();
    }
  }
}

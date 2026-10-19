import { call, type Backend } from './backend';
import { canManageRules, parseRule, type Rule } from './protocol';
import {
  AUTOMATIC_ZONE_MODEL,
  LEGACY_ZONE_MODEL,
  ZONE_MIGRATION_CAPABILITY,
} from './network-zones';
export interface MigrationTarget {
  generation: string;
  id: string;
  version: number;
}
export interface ZoneMigrationPreview {
  token: string;
  expires_at: string;
  rule_id: string;
  old_version: number;
  zone_revision: string;
  old_model: string;
  new_model: string;
  old_prefixes: string[];
  new_prefixes: string[];
  added_prefixes: string[];
  removed_prefixes: string[];
  samples: { address: string; old_zone: string; new_zone: string; reason: string }[];
  scope_preview: string;
  rule: Rule;
}
export interface MigrationView {
  phase: 'idle' | 'checking' | 'review' | 'saving' | 'acknowledged' | 'rejected' | 'unknown';
  message: string;
  supported: boolean;
  connected: boolean;
  canConfirm: boolean;
  target?: MigrationTarget;
  original?: Rule;
  preview?: ZoneMigrationPreview;
}
const obj = (v: unknown): Record<string, unknown> => {
  if (!v || typeof v !== 'object' || Array.isArray(v)) throw Error('Invalid zone migration');
  return v as Record<string, unknown>;
};
const text = (v: unknown, max = 4096) => {
  if (typeof v !== 'string' || v.length > max) throw Error('Invalid migration text');
  return v;
};
export const sameMigrationRule = (a: Rule, b: Rule) =>
  JSON.stringify(parseRule(a)) === JSON.stringify(parseRule(b));
export function parseZoneMigration(
  raw: unknown,
  original: Rule,
  target: MigrationTarget,
  revision: string,
  now: number,
): ZoneMigrationPreview {
  const p = obj(raw),
    rule = parseRule(p.rule);
  if (
    !text(p.token, 256) ||
    p.rule_id !== target.id ||
    p.old_version !== target.version ||
    !Number.isSafeInteger(p.old_version) ||
    p.zone_revision !== revision ||
    p.old_model !== LEGACY_ZONE_MODEL ||
    p.new_model !== AUTOMATIC_ZONE_MODEL ||
    !Number.isFinite(Date.parse(String(p.expires_at))) ||
    Date.parse(String(p.expires_at)) <= now ||
    Date.parse(String(p.expires_at)) > now + 35000 ||
    rule.id !== original.id ||
    rule.version !== original.version + 1 ||
    !Number.isSafeInteger(rule.version) ||
    rule.schema !== 6 ||
    rule.filter.zone_model !== AUTOMATIC_ZONE_MODEL ||
    !rule.filter.network_zone
  )
    throw Error('Migration preview changed target, version, model or expiry');
  const preserved = structuredClone(rule);
  preserved.schema = original.schema;
  preserved.version = original.version;
  delete preserved.filter.zone_model;
  // Legacy empty peer constraint and explicit * are the same Any predicate.
  // Accept only this canonicalization; exact/CIDR/legacy endpoint scopes stay frozen.
  if (!original.filter.remote_address && !original.filter.remote && preserved.filter.remote_address === '*')
    preserved.filter.remote_address = original.filter.remote_address;
  if (!sameMigrationRule(preserved, original))
    throw Error('Migration changed immutable rule fields; nothing saved');
  const lists = {} as Pick<
    ZoneMigrationPreview,
    'old_prefixes' | 'new_prefixes' | 'added_prefixes' | 'removed_prefixes'
  >;
  let count = 0;
  for (const key of [
    'old_prefixes',
    'new_prefixes',
    'added_prefixes',
    'removed_prefixes',
  ] as const) {
    if (!Array.isArray(p[key]) || (p[key] as unknown[]).length > 16384)
      throw Error('Invalid migration coverage');
    lists[key] = (p[key] as unknown[]).map((v) => text(v, 128));
    count += lists[key].length;
  }
  if (count > 16384 || !Array.isArray(p.samples) || p.samples.length > 256)
    throw Error('Migration review exceeds budget');
  const samples = p.samples.map((raw) => {
    const s = obj(raw);
    if (
      !['', 'local', 'internet'].includes(String(s.old_zone)) ||
      !['', 'local', 'internet'].includes(String(s.new_zone))
    )
      throw Error('Invalid migration sample');
    return {
      address: text(s.address, 256),
      old_zone: String(s.old_zone),
      new_zone: String(s.new_zone),
      reason: text(s.reason),
    };
  });
  return {
    token: String(p.token),
    expires_at: String(p.expires_at),
    rule_id: target.id,
    old_version: target.version,
    zone_revision: revision,
    old_model: LEGACY_ZONE_MODEL,
    new_model: AUTOMATIC_ZONE_MODEL,
    ...lists,
    samples,
    scope_preview: text(p.scope_preview, 32768),
    rule,
  };
}
export class ZoneMigration {
  private phase: MigrationView['phase'] = 'idle';
  private message = 'Select a legacy zone rule to review migration.';
  private held?: {
    target: MigrationTarget;
    original: Rule;
    endpoint: string;
    revision: string;
    preview?: ZoneMigrationPreview;
  };
  private busy = false;
  constructor(private backend: Backend) {}
  private authority(target: MigrationTarget) {
    const c = this.backend.view().control;
    if (!this.backend.controller || !canManageRules(c) || c.permissions?.can_manage_rules !== true)
      throw Error('Connect the primary controller with rule-management permission');
    if (
      !c.capabilities?.includes(ZONE_MIGRATION_CAPABILITY) ||
      c.networkZones?.model !== AUTOMATIC_ZONE_MODEL
    )
      throw Error('Backend update required for reviewed automatic-zone migration');
    if (c.generation !== target.generation)
      throw Error('Daemon generation changed; reopen the rule');
    const original = c.rules?.find((r) => r.id === target.id);
    if (!original || original.version !== target.version)
      throw Error('Rule changed or disappeared; close and select its current version');
    if (
      original.schema !== 4 ||
      original.filter.zone_model ||
      !original.filter.network_zone ||
      original.preset
    )
      throw Error('Only legacy configured-zone rules can be migrated');
    if (original.filter.all_uids && !c.permissions?.can_manage_machine_rules)
      throw Error('Machine rule requires administrator authority');
    if (
      original.filter.process &&
      !original.disabled &&
      c.rule_states?.[original.id]?.state !== 'active'
    )
      throw Error('Process target is inactive; migration cannot reactivate it');
    return { c, original, endpoint: this.backend.controller };
  }
  private confirmable() {
    const h = this.held;
    if (!h?.preview) throw Error('Fresh migration preview required');
    const { c, original, endpoint } = this.authority(h.target);
    if (endpoint !== h.endpoint || c.networkZones?.revision !== h.revision)
      throw Error('Network classification changed; review migration again');
    if (!sameMigrationRule(original, h.original))
      throw Error('Original rule changed; reopen the current version');
    if (Date.parse(h.preview.expires_at) <= this.backend.now())
      throw Error('Migration preview expired; review again');
    return h;
  }
  view(): MigrationView {
    const c = this.backend.view().control;
    let canConfirm = false,
      message = this.message;
    if (this.phase === 'review' && !this.busy) {
      try {
        this.confirmable();
        canConfirm = true;
      } catch (error) {
        message = String((error as Error).message);
      }
    }
    return {
      phase: this.phase,
      message,
      supported: !!c.capabilities?.includes(ZONE_MIGRATION_CAPABILITY),
      connected: c.connected,
      canConfirm,
      ...(this.held
        ? { target: this.held.target, original: this.held.original, preview: this.held.preview }
        : {}),
    };
  }
  async preview(raw: unknown) {
    if (this.busy || this.phase === 'unknown')
      throw Error('Resolve the current migration result before opening another');
    const v = obj(raw);
    if (
      Object.keys(v).sort().join(',') !== 'generation,id,version' ||
      ![v.generation, v.id].every(
        (x) => typeof x === 'string' && x.length > 0 && x.length <= 256,
      ) ||
      !Number.isSafeInteger(v.version) ||
      Number(v.version) < 0
    )
      throw Error('Invalid migration target');
    const target = {
      generation: String(v.generation),
      id: String(v.id),
      version: Number(v.version),
    };
    const { c, original, endpoint } = this.authority(target);
    this.held = {
      target,
      original: structuredClone(original),
      endpoint,
      revision: c.networkZones!.revision,
    };
    const h = this.held;
    this.busy = true;
    this.phase = 'checking';
    this.message = 'Checking exact scope changes…';
    try {
      const r = await call(endpoint, {
        operation: 'zone-migration-preview',
        generation: target.generation,
        id: target.id,
        expected_version: target.version,
        zone_revision: h.revision,
      });
      if (r.error) throw Error(`${r.error_code}: ${r.error}`);
      if (r.generation !== target.generation) throw Error('Daemon generation changed');
      const current = this.authority(target);
      if (
        current.endpoint !== endpoint ||
        current.c.networkZones?.revision !== h.revision ||
        !sameMigrationRule(current.original, h.original)
      )
        throw Error('Rule or network changed during review; refresh explicitly');
      h.preview = parseZoneMigration(
        r.zone_migration,
        h.original,
        target,
        h.revision,
        this.backend.now(),
      );
      this.phase = 'review';
      this.message = 'Review exact additions/removals, then explicitly confirm. No rule changed.';
    } catch (error) {
      this.phase = 'rejected';
      this.message = String((error as Error).message);
    } finally {
      this.busy = false;
    }
    return this.view();
  }
  async confirm(token: unknown) {
    if (
      this.busy ||
      this.phase !== 'review' ||
      typeof token !== 'string' ||
      token !== this.held?.preview?.token
    )
      throw Error('Confirm the original reviewed migration');
    const h = this.confirmable();
    this.busy = true;
    this.phase = 'saving';
    this.message = 'Waiting for migration acknowledgement…';
    try {
      await this.backend.ruleMutation(async () => {
        const r = await call(h.endpoint, {
          operation: 'zone-migration-save',
          generation: h.target.generation,
          id: h.target.id,
          expected_version: h.target.version,
          zone_revision: h.revision,
          preview_token: h.preview!.token,
        });
        if (r.generation !== h.target.generation) throw Error('Daemon generation changed');
        if (r.error) {
          this.phase = 'rejected';
          this.message = `${r.error_code}: ${r.error}`;
          return;
        }
        if (
          !r.saved_rule ||
          !sameMigrationRule(r.saved_rule, h.preview!.rule) ||
          r.scope_preview !== h.preview!.scope_preview
        )
          throw Error('Migration acknowledgement differs from the reviewed rule');
        this.phase = 'acknowledged';
        this.message = 'Migration confirmed. Enforcement state is shown separately.';
      });
    } catch (error) {
      this.phase = 'unknown';
      this.message =
        'Migration outcome unknown. Check result; no save will be replayed. ' +
        String((error as Error).message);
    } finally {
      this.busy = false;
    }
    return this.view();
  }
  async reconcile() {
    const h = this.held,
      c = this.backend.view().control;
    if (this.busy || this.phase !== 'unknown' || !h?.preview)
      throw Error('No unresolved migration');
    if (
      !c.connected ||
      c.generation !== h.target.generation ||
      this.backend.controller !== h.endpoint
    )
      throw Error(
        'Original controller unavailable; inspect rule ID/version after reconnect. No replay sent.',
      );
    this.busy = true;
    try {
      const r = await call(h.endpoint, { operation: 'list' });
      if (r.error || r.generation !== h.target.generation)
        throw Error(r.error || 'Daemon generation changed');
      const rule = r.rules.find((v) => v.id === h.target.id);
      if (rule && sameMigrationRule(rule, h.preview.rule)) {
        this.phase = 'acknowledged';
        this.message = 'Exact migrated rule confirmed in authoritative inventory.';
      } else
        this.message = rule
          ? 'Rule differs from reviewed result; outcome remains unknown. Inspect inventory; no retry sent.'
          : 'Rule is absent; outcome remains unknown. No retry sent.';
    } catch (error) {
      this.message = 'Still unresolved: ' + String((error as Error).message);
    } finally {
      this.busy = false;
    }
    return this.view();
  }
}

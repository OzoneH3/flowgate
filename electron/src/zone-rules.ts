import { randomUUID } from 'node:crypto';
import { call, type Backend } from './backend';
import {
  canManageRules,
  validateEdit,
  STORED_ASK_CAPABILITY,
  type RuleSource,
  type RuleDraft,
  type Rule,
  type RulePreview,
  type Attempt,
} from './protocol';
import { ZONE_CAPABILITY, type ZoneSource } from './network-zones';
type Draft = RuleDraft & { target: ZoneSource; endpoint: string; locked: boolean };
type Receipt = {
  draft: Draft;
  request: object;
  rule: Rule;
  expires: number;
  sent: boolean;
  uncertain: boolean;
};
const equal = (a: Rule, b: Rule) => JSON.stringify(a) === JSON.stringify(b);
export class ZoneRules {
  private drafts = new Map<string, Draft>();
  private receipts = new Map<string, Receipt>();
  private busy = false;
  constructor(private backend: Backend) {}
  ownsDraft(v: unknown) {
    return typeof v === 'string' && this.drafts.has(v);
  }
  ownsReceipt(v: unknown) {
    return typeof v === 'string' && this.receipts.has(v);
  }
  private authority(target: ZoneSource) {
    const c = this.backend.view().control;
    if (
      !c.connected ||
      !canManageRules(c) ||
      !c.capabilities?.includes(ZONE_CAPABILITY) ||
      !this.backend.controller
    )
      throw Error('Network-zone rule control unavailable or read-only');
    if (c.generation !== target.generation || c.networkZones?.revision !== target.revision)
      throw Error('Zone definition or generation changed; review again');
    if (target.scope === 'machine' && !c.permissions?.can_manage_machine_rules)
      throw Error('Machine rules require administrator authority');
    return c;
  }
  async draft(source: unknown): Promise<RuleDraft> {
    const t = source as ZoneSource;
    if (
      !t ||
      Object.keys(t).sort().join(',') !== 'direction,generation,revision,scope,zone' ||
      !['local', 'internet'].includes(t.zone) ||
      !['machine', 'self'].includes(t.scope) ||
      !['incoming', 'outgoing'].includes(t.direction) ||
      ![t.generation, t.revision].every(
        (v) => typeof v === 'string' && v.length > 0 && v.length < 256,
      )
    )
      throw Error('Invalid zone target');
    this.authority(t);
    if (this.drafts.size >= 32) {
      const stale = [...this.drafts].find(([, value]) => !value.locked);
      if (!stale) throw Error('Resolve outstanding zone saves before opening another');
      this.drafts.delete(stale[0]);
      for (const [key, receipt] of this.receipts)
        if (receipt.draft.token === stale[0] && !receipt.sent) this.receipts.delete(key);
    }
    const token = randomUUID();
    const d: Draft = {
      token,
      generation: t.generation,
      target: structuredClone(t),
      endpoint: this.backend.controller!,
      locked: false,
      source: 'Configured policy zone · all programs',
      rule: {
        id: '',
        version: 0,
        schema: 4,
        executable: '',
        created: '',
        priority: 100,
        disabled: false,
        action: 'block',
        expires: '0001-01-01T00:00:00Z',
        filter: {
          application: '',
          revision: '',
          uid: 0,
          all_programs: true,
          all_uids: t.scope === 'machine' || undefined,
          network_zone: t.zone,
          direction: t.direction,
          protocol: '*',
          remote_address: '*',
          local_port: 0,
          remote_port: 0,
        },
      },
    };
    this.drafts.set(token, d);
    return { token, generation: d.generation, source: d.source, rule: structuredClone(d.rule) };
  }
  async preview(raw: unknown): Promise<RulePreview> {
    const e = validateEdit(raw),
      d = this.drafts.get(e.token);
    if (!d || d.locked || d.endpoint !== this.backend.controller)
      throw Error('Fresh zone draft required');
    this.authority(d.target);
    if (
      e.action === 'ask' &&
      !this.backend.view().control.capabilities?.includes(STORED_ASK_CAPABILITY)
    )
      throw Error('Backend update required for stored Ask (stored-ask-v1)');
    if (e.priority !== 100 || (e.network_zone !== undefined && e.network_zone !== d.target.zone))
      throw Error('Zone target and priority are fixed');
    const observed_draft = {
      direction: d.target.direction,
      protocol: e.protocol,
      action: e.action,
      remote_address: e.remote_address,
      local_port: e.local_port,
      remote_port: e.remote_port,
      disabled: e.disabled,
      expires:
        e.expiry === 'hour'
          ? new Date(this.backend.now() + 3600000).toISOString()
          : e.expiry === 'preserve'
            ? d.rule.expires
            : '0001-01-01T00:00:00Z',
    };
    const request = {
      generation: d.generation,
      zone_revision: d.target.revision,
      zone_target: { zone: d.target.zone, scope: d.target.scope },
      observed_draft,
    };
    const r = await call(d.endpoint, { operation: 'zone-rule-preview', ...request });
    this.authority(d.target);
    if (r.error || !r.zone_preview || r.generation !== d.generation)
      throw Error(`${r.error_code}: ${r.error || 'Zone preview missing'}`);
    const p = r.zone_preview,
      f = p.rule.filter;
    if (
      p.network_zones.revision !== d.target.revision ||
      !f.all_programs ||
      !!f.all_uids !== (d.target.scope === 'machine') ||
      f.network_zone !== d.target.zone ||
      f.application ||
      f.process ||
      f.direction !== d.target.direction ||
      p.rule.action !== e.action ||
      f.protocol !== e.protocol ||
      p.rule.disabled !== e.disabled ||
      Date.parse(p.expires_at) <= this.backend.now()
    )
      throw Error('Zone preview changed; review again');
    for (const [key, value] of this.receipts)
      if (value.draft.token === d.token && !value.sent) this.receipts.delete(key);
    if (this.receipts.size >= 32) throw Error('Resolve outstanding zone saves');
    const receipt = randomUUID();
    this.receipts.set(receipt, {
      draft: d,
      request: { ...request, preview_token: p.token },
      rule: p.rule,
      expires: Date.parse(p.expires_at),
      sent: false,
      uncertain: false,
    });
    return { receipt, preview: p.scope_preview, expiresAt: p.expires_at, verifiedRule: p.rule };
  }
  async save(token: unknown): Promise<Attempt> {
    const r = typeof token === 'string' ? this.receipts.get(token) : undefined;
    if (!r || r.sent || this.busy || r.draft.endpoint !== this.backend.controller)
      throw Error('Fresh zone preview required');
    this.authority(r.draft.target);
    if (r.expires <= this.backend.now()) throw Error('Preview expired; refresh and review');
    r.sent = true;
    r.draft.locked = true;
    this.busy = true;
    try {
      const reply = await call(r.draft.endpoint, { operation: 'zone-rule-save', ...r.request });
      if (reply.error) {
        this.receipts.delete(token as string);
        r.draft.locked = false;
        return { phase: 'rejected', message: `${reply.error_code}: ${reply.error}` };
      }
      if (
        reply.generation !== r.draft.generation ||
        !reply.saved_rule ||
        !equal(reply.saved_rule, r.rule)
      )
        throw Error('Acknowledgement differs from reviewed rule');
      this.drafts.delete(r.draft.token);
      this.receipts.delete(token as string);
      return {
        phase: 'acknowledged',
        rule: reply.saved_rule,
        message: 'Saved. Enforcement state is shown separately.',
      };
    } catch (e) {
      r.uncertain = true;
      return {
        phase: 'unknown',
        reconcile: token as string,
        message: 'Outcome uncertain. Check the reserved rule ID; do not repeat Save. ' + String(e),
      };
    } finally {
      this.busy = false;
      await this.backend.pollControl();
    }
  }
  async reconcile(token: unknown): Promise<Attempt> {
    const p = typeof token === 'string' ? this.receipts.get(token) : undefined;
    if (!p?.uncertain) throw Error('No unresolved zone save');
    const r = await call(p.draft.endpoint, { operation: 'list' });
    if (r.generation !== p.draft.generation)
      return {
        phase: 'unknown',
        reconcile: token as string,
        message:
          'Generation changed; inspect the reserved rule in the new session. No creation replayed.',
      };
    if (r.error) return { phase: 'unknown', reconcile: token as string, message: r.error };
    const found = r.rules.find((rule) => rule.id === p.rule.id);
    if (found && equal(found, p.rule)) {
      p.uncertain = false;
      this.drafts.delete(p.draft.token);
      this.receipts.delete(token as string);
      return {
        phase: 'acknowledged',
        rule: found,
        message: 'Saved rule confirmed in authoritative inventory.',
      };
    }
    return {
      phase: 'unknown',
      reconcile: token as string,
      message: found
        ? 'Reserved rule changed; inspect current inventory.'
        : 'Reserved rule not found; outcome remains uncertain. No retry was sent.',
    };
  }
}

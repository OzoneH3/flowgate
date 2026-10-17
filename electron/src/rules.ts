import { randomUUID } from 'node:crypto';
import { Backend, call } from './backend';
import { validateEdit, type Rule, type RuleDraft, type RuleEdit, type Attempt } from './protocol';
// Draft identity, generation and version remain in main, never trusted from renderer.
export class Rules {
  private drafts = new Map<string, RuleDraft & { event?: string; id?: string }>();
  private receipts = new Map<
    string,
    { draft: string; request: object; rule: Rule; generation: string; id?: string }
  >();
  private busy = false;
  constructor(private backend: Backend) {}
  private authority() {
    const c = this.backend.view().control;
    if (!c.connected || c.readOnly || !this.backend.controller)
      throw Error('Controller unavailable or read-only');
    return c;
  }
  async draft(source: unknown): Promise<RuleDraft> {
    if (!source || typeof source !== 'object' || Array.isArray(source))
      throw Error('Invalid source');
    const s = source as { id?: string; event?: string };
    if (
      Object.keys(s).length !== 1 ||
      ![s.id, s.event].some((v) => typeof v === 'string' && v.length > 0 && v.length <= 256)
    )
      throw Error('Invalid source');
    await this.backend.pollControl();
    const c = this.authority();
    let rule: Rule;
    if (s.id) {
      const r = c.rules?.find((r) => r.id === s.id);
      if (!r) throw Error('Rule no longer exists');
      rule = structuredClone(r);
    } else {
      const e = c.events.find((e) => e.id === s.event);
      if (!e?.remembered_filter || e.state !== 'awaiting-decision' || e.remainingMs <= 0)
        throw Error('Pending attributable request required');
      rule = {
        version: 0,
        id: '',
        created: '0001-01-01T00:00:00Z',
        schema: 2,
        executable: e.attribution.application?.executable || '',
        filter: structuredClone(e.remembered_filter),
        action: 'allow',
        disabled: false,
        priority: 0,
        expires: new Date(this.backend.now() + 3600000).toISOString(),
      };
    }
    // Convert legacy exact endpoints without widening their scope.
    if (rule.filter.remote && !rule.filter.remote_address) {
      const match = /^(?:\[([^\]]+)\]|([^:]+)):(\d+)$/.exec(rule.filter.remote);
      if (!match) throw Error('Legacy endpoint cannot be edited safely');
      rule.filter.remote_address = match[1] || match[2];
      rule.filter.remote_port = Number(match[3]);
      rule.filter.remote = '';
    }
    const token = randomUUID(),
      draft = {
        token,
        generation: c.generation,
        rule,
        source: s.id ? 'Saved rule' : 'Pending request',
        ...s,
      };
    if (this.drafts.size >= 64) this.drafts.delete(this.drafts.keys().next().value!);
    this.drafts.set(token, draft);
    return draft;
  }
  async preview(value: unknown) {
    const e: RuleEdit = validateEdit(value),
      d = this.drafts.get(e.token),
      c = this.authority();
    if (!d || d.generation !== c.generation)
      throw Error('Generation changed; reopen editor with current rule');
    for (const [k, v] of this.receipts) if (v.draft === e.token) this.receipts.delete(k);
    const rule = structuredClone(d.rule);
    Object.assign(rule, {
      schema: 2,
      action: e.action,
      disabled: e.disabled,
      priority: e.priority,
    });
    Object.assign(rule.filter, {
      protocol: e.protocol,
      remote_address: e.remote_address,
      local_port: e.local_port,
      remote_port: e.remote_port,
      remote: '',
    });
    if (e.expiry !== 'preserve')
      rule.expires =
        e.expiry === 'hour'
          ? new Date(this.backend.now() + 3600000).toISOString()
          : '0001-01-01T00:00:00Z';
    const request = {
      generation: d.generation,
      id: d.id || '',
      event_id: d.event || '',
      expected_version: d.id ? d.rule.version : undefined,
      rule,
    };
    const r = await call(this.backend.controller!, { operation: 'rule-preview', ...request });
    if (r.error || !r.saved_rule || !r.scope_preview || r.generation !== d.generation)
      throw Error(r.error || 'Preview not acknowledged');
    const receipt = randomUUID();
    this.receipts.set(receipt, {
      draft: e.token,
      request,
      rule: r.saved_rule,
      generation: d.generation,
      id: d.id,
    });
    return { receipt, preview: r.scope_preview };
  }
  async save(receipt: unknown): Promise<Attempt> {
    if (typeof receipt !== 'string' || receipt.length > 128) throw Error('Invalid preview receipt');
    const p = this.receipts.get(receipt);
    this.receipts.delete(receipt);
    if (!p || this.busy) throw Error('Fresh preview required');
    const c = this.authority();
    if (c.generation !== p.generation) throw Error('Generation changed; reopen editor');
    this.busy = true;
    try {
      const r = await call(this.backend.controller!, { operation: 'rule-save', ...p.request });
      if (r.error)
        return {
          phase: 'rejected',
          message:
            r.error +
            '; preview again. For a version conflict, reload the current version before previewing.',
        };
      if (!r.saved_rule || r.generation !== p.generation)
        throw Error('Missing save acknowledgement');
      this.drafts.delete(p.draft);
      return { phase: 'acknowledged', message: 'Rule saved by backend' };
    } catch (e) {
      return {
        phase: 'unknown',
        message:
          'Save outcome unresolved. Do not resubmit. Inspect saved rules after reconnect: ' +
          String(e),
      };
    } finally {
      this.busy = false;
      await this.backend.pollControl();
    }
  }
  async delete(value: unknown): Promise<Attempt> {
    const v = value as { id: string; generation: string; version: number };
    if (
      !v ||
      Object.keys(v).sort().join(',') !== 'generation,id,version' ||
      typeof v.id !== 'string' ||
      v.id.length > 256 ||
      typeof v.generation !== 'string' ||
      !Number.isSafeInteger(v.version)
    )
      throw Error('Invalid deletion');
    await this.backend.pollControl();
    const c = this.authority();
    if (
      this.busy ||
      c.generation !== v.generation ||
      !c.rules?.some((r) => r.id === v.id && r.version === v.version)
    )
      throw Error('Rule changed; review current version');
    this.busy = true;
    try {
      const r = await call(this.backend.controller!, {
        operation: 'rule',
        id: v.id,
        action: 'delete',
      });
      if (r.error) return { phase: 'rejected', message: r.error };
      if (r.generation !== v.generation) throw Error('Generation changed');
      return { phase: 'acknowledged', message: 'Rule deleted' };
    } catch (e) {
      return {
        phase: 'unknown',
        message: 'Delete outcome unresolved; inspect authoritative list. ' + String(e),
      };
    } finally {
      this.busy = false;
      await this.backend.pollControl();
    }
  }
}

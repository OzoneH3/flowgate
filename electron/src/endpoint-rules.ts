import { randomUUID } from 'node:crypto';
import { call, type Backend } from './backend';
import type { Attempt, Rule } from './protocol';
import { canManageEndpoints, sameEndpointRule, validateEndpointDraft, type EndpointDraft, type EndpointReview } from './endpoint-policy';
type Receipt = {
  endpoint: string; generation: string; inventory: string; draft: EndpointDraft;
  rule: Rule; previewToken: string; until: number; sent: boolean; uncertain: boolean;
};
export class EndpointRules {
  private receipts = new Map<string, Receipt>();
  private busy = false;
  constructor(private backend: Backend) {}
  private authority() {
    const c = this.backend.view().control;
    if (!canManageEndpoints(c) || !this.backend.controller || !c.generation || !c.rules)
      throw Error('Endpoint permissions require a connected administrator controller and network-endpoint-policy-v1.');
    return c;
  }
  async preview(raw: unknown): Promise<EndpointReview> {
    if (this.busy) throw Error('An endpoint operation is in progress');
    this.busy = true;
    try { return await this.previewInner(raw); } finally { this.busy = false; }
  }
  private async previewInner(raw: unknown): Promise<EndpointReview> {
    await this.backend.pollControl();
    const c = this.authority(), endpoint = this.backend.controller!, generation = c.generation;
    const draft = validateEndpointDraft(raw, this.backend.now()), inventory = JSON.stringify(c.rules);
    for (const [key, r] of this.receipts) if (!r.sent && this.backend.now() >= r.until) this.receipts.delete(key);
    if (this.receipts.size >= 32) throw Error('Resolve outstanding endpoint previews before opening another.');
    const r = await call(endpoint, { operation: 'endpoint-rule-preview', generation, endpoint_draft: draft });
    const current = this.authority();
    if (r.error || r.error_code) throw Error([r.error_code, r.error].filter(Boolean).join(': '));
    const p = r.endpoint_preview, now = this.backend.now();
    if (this.backend.controller !== endpoint || current.generation !== generation || r.generation !== generation || JSON.stringify(current.rules) !== inventory ||
      !p || !p.rule.network_endpoint || p.rule.action !== draft.action || p.rule.filter.remote_address !== draft.remote_address || p.rule.filter.remote_port !== draft.remote_port ||
      p.rule.disabled || Date.parse(p.rule.expires) !== Date.parse(draft.expires) || Date.parse(p.expires_at) <= now || Date.parse(p.expires_at) > now + 31000)
      throw Error('Endpoint preview changed scope or context; obtain a fresh preview.');
    const receipt = randomUUID();
    this.receipts.set(receipt, {endpoint,generation,inventory,draft,rule:structuredClone(p.rule),previewToken:p.token,until:Date.parse(p.expires_at),sent:false,uncertain:false});
    return {receipt,rule:structuredClone(p.rule),scope:p.scope_preview,enforcement:p.enforcement,expiresAt:Date.parse(p.expires_at)};
  }
  async save(raw: unknown): Promise<Attempt> {
    const v = raw as {receipt?: unknown; acknowledge_scope?: unknown};
    if (!v || Object.keys(v).sort().join(',') !== 'acknowledge_scope,receipt' || typeof v.receipt !== 'string' || v.acknowledge_scope !== true)
      throw Error('Confirm the all-users/programs endpoint scope before saving.');
    return this.backend.ruleMutation ? this.backend.ruleMutation(() => this.saveInner(v.receipt as string)) : this.saveInner(v.receipt);
  }
  private async saveInner(token: string): Promise<Attempt> {
    const p = this.receipts.get(token), c = this.authority();
    if (!p) throw Error('Fresh endpoint preview required');
    if (p.sent) return {phase:'unknown',reconcile:token,message:'Save was already submitted. Check its result; no repeat was sent.'};
    if (this.busy || p.endpoint !== this.backend.controller || c.generation !== p.generation || this.backend.now() >= p.until || JSON.stringify(c.rules) !== p.inventory)
      throw Error('Endpoint context, policy or preview changed. Review again.');
    this.busy = true; p.sent = true;
    try {
      const r = await call(p.endpoint, {operation:'endpoint-rule-save',generation:p.generation,endpoint_draft:p.draft,preview_token:p.previewToken});
      const current = this.authority();
      if (this.backend.controller !== p.endpoint || current.generation !== p.generation) throw Error('Controller or generation changed during save; inspect reserved inventory.');
      if (r.error || r.error_code) {
        this.receipts.delete(token);
        return {phase:'rejected',message:[r.error_code,r.error].filter(Boolean).join(': ')};
      }
      if (r.generation !== p.generation || !r.saved_rule || !sameEndpointRule(r.saved_rule,p.rule)) throw Error('Save acknowledgement differs from reviewed endpoint rule');
      this.receipts.delete(token);
      return {phase:'acknowledged',rule:r.saved_rule,message:'Endpoint rule saved. It covers all matching users and programs. Enforcement is shown separately.'};
    } catch (e) {
      p.uncertain = true;
      return {phase:'unknown',reconcile:token,message:'Endpoint save outcome unknown. Check the reserved rule; do not repeat Save. '+String(e)};
    } finally {
      this.busy = false;
      await this.backend.pollControl().catch(() => {});
    }
  }
  async reconcile(token: unknown): Promise<Attempt> {
    const p = typeof token === 'string' ? this.receipts.get(token) : undefined;
    if (p && !p.sent) { this.receipts.delete(token as string); return {phase:'rejected',message:'Save was never submitted by this client. Obtain a new preview.'}; }
    if (!p?.sent || !p.uncertain) throw Error('No unresolved endpoint save; inspect the reserved rule in inventory.');
    this.authority();
    if (this.backend.controller !== p.endpoint) return {phase:'unknown',reconcile:token as string,message:'Controller changed. No creation was replayed.'};
    try {
      const r = await call(p.endpoint,{operation:'list'});
      const current = this.authority();
      if (this.backend.controller !== p.endpoint || current.generation !== p.generation) throw Error('Controller or generation changed during result check');
      if (r.error || r.error_code || r.generation !== p.generation) throw Error(r.error || 'Generation changed; inspect current inventory.');
      const found = r.rules.find(rule => rule.id === p.rule.id);
      if (found && sameEndpointRule(found,p.rule)) {
        this.receipts.delete(token as string);
        return {phase:'acknowledged',rule:found,message:'Reviewed endpoint rule confirmed in authoritative inventory.'};
      }
      return {phase:'unknown',reconcile:token as string,message:found ? 'Reserved rule changed. Inspect current inventory; no creation replayed.' : 'Reserved rule is absent. Outcome remains unknown; no creation replayed.'};
    } catch (e) { return {phase:'unknown',reconcile:token as string,message:String(e)}; }
  }
}

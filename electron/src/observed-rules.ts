import {
  ANY_PROTOCOL_CAPABILITY,
  PROCESS_CAPABILITY,
  sameProcessTarget,
  type ProcessTarget,
} from './process-rules';
import { randomUUID } from 'node:crypto';
import { call, type Backend } from './backend';
import { APPLICATION_POLICY_CAPABILITY } from './policy';
import {
  canManageRules,
  validateEdit,
  STORED_ASK_CAPABILITY,
  type RuleDraft,
  type ObservedSource,
  type RulePreview,
  type Rule,
  type ObservedPreview,
  type Attempt,
} from './protocol';
export const CREATE_CAPABILITY = 'observed-rule-create-v1';
type Draft = RuleDraft & {
  target: ObservedSource;
  endpoint: string;
  locked: boolean;
  startTicks: string;
  pid: number;
  boundTarget?: ProcessTarget;
};
type Receipt = {
  draft: Draft;
  value: object;
  preview: ObservedPreview;
  sent: boolean;
  unresolved: boolean;
};
const ruleFields = (r: Rule) => [
  r.id,
  r.version,
  r.executable,
  r.action,
  r.disabled,
  r.priority,
  r.expires,
  r.filter.application,
  r.filter.revision,
  r.filter.uid,
  r.filter.direction,
  r.filter.protocol,
  r.filter.remote_address || '',
  r.filter.remote || '',
  r.filter.local_port || 0,
  r.filter.remote_port || 0,
  r.filter.process,
  r.filter.network_zone,
  r.filter.all_programs,
  r.filter.all_uids,
];
const sameRule = (a: Rule, b: Rule) =>
  JSON.stringify(ruleFields(a)) === JSON.stringify(ruleFields(b));
export class ObservedRules {
  private drafts = new Map<string, Draft>();
  private receipts = new Map<string, Receipt>();
  private busy = false;
  constructor(private backend: Backend) {}
  ownsDraft(token: unknown) {
    return typeof token === 'string' && this.drafts.has(token);
  }
  ownsReceipt(token: unknown) {
    return typeof token === 'string' && this.receipts.has(token);
  }
  private authority() {
    const c = this.backend.view().control;
    if (!this.backend.controller || !canManageRules(c))
      throw Error('Stored-rule creation unavailable or read-only');
    if (!c.capabilities?.includes(CREATE_CAPABILITY))
      throw Error('Backend update required: observed-rule-create-v1');
    return c;
  }
  async draft(raw: unknown): Promise<RuleDraft> {
    const s = raw as ObservedSource;
    if (
      !s ||
      typeof s !== 'object' ||
      Object.keys(s)
        .filter((k) => k !== 'target_scope')
        .sort()
        .join(',') !== 'direction,generation,process_id,row_id' ||
      (s.target_scope !== undefined && !['application', 'process'].includes(s.target_scope)) ||
      !['incoming', 'outgoing'].includes(s.direction) ||
      ![s.generation, s.row_id, s.process_id].every(
        (v) => typeof v === 'string' && v.length > 0 && v.length <= 1024,
      )
    )
      throw Error('Invalid observed selection');
    const c = this.authority(),
      o = this.backend.view().observation;
    if (s.target_scope === 'process' && !c.capabilities?.includes(PROCESS_CAPABILITY))
      throw Error('Backend update required for This process; no application fallback');
    if (!o.connected || c.generation !== s.generation || o.generation !== s.generation)
      throw Error('Generation changed; select the application again');
    const row = o.activity?.rows.find((r) => r.id === s.row_id),
      p = o.activity?.processes[s.process_id];
    if (
      !row ||
      row.owners.length !== 1 ||
      row.owners[0] !== s.process_id ||
      !p?.application.key ||
      !p.application.revision
    )
      throw Error('Supported single-holder observation required');
    if (this.drafts.size >= 64) {
      const old = [...this.drafts].find(([, d]) => !d.locked);
      if (!old) throw Error('Resolve outstanding saves before opening another editor');
      this.drafts.delete(old[0]);
      for (const [k, r] of this.receipts)
        if (r.draft.token === old[0] && !r.unresolved) this.receipts.delete(k);
    }
    // Display basis only. It is never sent as permission identity; Go verifies target.
    const token = randomUUID(),
      d: Draft = {
        token,
        generation: s.generation,
        source: 'Activity observation · identity verification required at Preview',
        observed: true,
        targetScope: s.target_scope || 'application',
        processID: s.process_id,
        startTicks: p.start_ticks,
        pid: p.pid,
        boundTarget:
          s.target_scope === 'process'
            ? c.policy?.processes?.find(
                (entry) =>
                  entry.process_id === p.id &&
                  entry.state === 'active' &&
                  !!entry.target.instance_id,
              )?.target
            : undefined,
        target: structuredClone(s),
        endpoint: this.backend.controller!,
        locked: false,
        rule: {
          id: '',
          version: 0,
          schema: 2,
          created: '0001-01-01T00:00:00Z',
          executable: p.application.executable,
          action: 'block',
          disabled: false,
          priority: 100,
          expires: new Date(this.backend.now() + 3600000).toISOString(),
          filter: {
            application: p.application.key,
            revision: p.application.revision,
            uid: p.uid,
            direction: s.direction,
            protocol: row.socket.protocol,
            remote_address: '',
            local_port: 0,
            remote_port: 0,
          },
        },
      };
    this.drafts.set(token, d);
    return {
      token: d.token,
      generation: d.generation,
      source: d.source,
      observed: true,
      targetScope: d.targetScope,
      processID: s.process_id,
      rule: structuredClone(d.rule),
    };
  }
  async preview(raw: unknown): Promise<RulePreview> {
    const e = validateEdit(raw),
      d = this.drafts.get(e.token),
      c = this.authority();
    if (!d || d.locked) throw Error('Resolve the outstanding save before creating another preview');
    if (d.generation !== c.generation || d.endpoint !== this.backend.controller)
      throw Error('Generation/endpoint changed; close editor and select again');
    // '*' means TCP + UDP only and must be explicit; it needs the backend's any-protocol capability.
    const protocols = c.capabilities?.some((cap) =>
      [ANY_PROTOCOL_CAPABILITY, 'network-zone-policy-v1', APPLICATION_POLICY_CAPABILITY].includes(
        cap,
      ),
    )
      ? ['tcp', 'udp', '*']
      : ['tcp', 'udp'];
    if (e.action === 'ask' && !c.capabilities?.includes(STORED_ASK_CAPABILITY))
      throw Error('Backend update required for stored Ask (stored-ask-v1)');
    // NetLimiter quick setter: the ONE canonical whole-target rule, created or updated in place by
    // the backend (preview.replaces); never a scoped rule.
    const policy = e.creation_scope === 'policy';
    if (policy && !c.capabilities?.includes(APPLICATION_POLICY_CAPABILITY))
      throw Error('Backend update required: application-policy-v1');
    if (!protocols.includes(e.protocol) || e.priority !== 100 || !e.creation_scope)
      throw Error(
        `Choose explicit scope and ${protocols.includes('*') ? 'TCP, UDP or TCP + UDP' : 'TCP or UDP'}; priority is backend-fixed`,
      );
    if (
      policy &&
      (e.protocol !== '*' ||
        e.remote_address !== '*' ||
        e.local_port !== 0 ||
        e.remote_port !== 0 ||
        e.expiry !== 'permanent')
    )
      throw Error('Application policy is TCP+UDP, any endpoint, persistent');
    if (
      e.creation_scope === 'application' &&
      (e.remote_address !== '*' || e.local_port !== 0 || e.remote_port !== 0)
    )
      throw Error(
        'Application scope must explicitly cover any endpoints for the selected protocol',
      );
    if (
      e.creation_scope === 'custom' &&
      (!e.remote_address || (e.remote_address === '*' && e.local_port === 0 && e.remote_port === 0))
    )
      throw Error('Specify an address or port, or explicitly choose all endpoints');
    for (const [key, r] of this.receipts)
      if (r.draft.token === e.token && !r.sent) this.receipts.delete(key);
    if (this.receipts.size >= 64) throw Error('Outstanding receipt limit reached');
    if (d.targetScope === 'process' && !c.capabilities?.includes(PROCESS_CAPABILITY))
      throw Error('Process capability lost; no fallback');
    const value = {
      ...(c.capabilities?.includes(PROCESS_CAPABILITY) ? { target_scope: d.targetScope } : {}),
      ...(e.network_zone
        ? { network_zone: e.network_zone, zone_revision: c.networkZones?.revision }
        : {}),
      direction: d.target.direction,
      protocol: e.protocol,
      action: e.action,
      remote_address: e.remote_address,
      local_port: e.local_port,
      remote_port: e.remote_port,
      disabled: e.disabled,
      ...(policy ? { application_policy: true } : {}),
      expires:
        e.expiry === 'preserve'
          ? d.rule.expires
          : e.expiry === 'hour'
            ? new Date(this.backend.now() + 3600000).toISOString()
            : '0001-01-01T00:00:00Z',
    };
    if (e.network_zone && !c.capabilities?.includes('network-zone-policy-v1'))
      throw Error('Backend update required for network-zone scope');
    const r = await call(d.endpoint, {
      operation: 'observed-rule-preview',
      generation: d.generation,
      observed_target: { row_id: d.target.row_id, process_id: d.target.process_id },
      observed_draft: value,
    });
    const p = r.observed_preview;
    if (r.error) throw Error(`${r.error_code}: ${r.error}`);
    if (
      this.backend.controller !== d.endpoint ||
      this.authority().generation !== d.generation ||
      r.generation !== d.generation ||
      !p ||
      p.process_id !== d.target.process_id ||
      Date.parse(p.expires_at) <= this.backend.now()
    )
      throw Error('Preview changed or expired; review again');
    if (
      p.rule.filter.application !== d.rule.filter.application ||
      p.rule.filter.revision !== d.rule.filter.revision ||
      p.rule.filter.uid !== d.rule.filter.uid ||
      p.rule.executable !== d.rule.executable ||
      p.rule.filter.direction !== d.target.direction ||
      (p.rule.filter.network_zone || '') !== (e.network_zone || '')
    )
      throw Error('Verified identity changed; close editor and select again');
    if (d.targetScope === 'process') {
      const t = p.rule.filter.process;
      if (d.boundTarget && !sameProcessTarget(d.boundTarget, t))
        throw Error('Process instance binding changed; close and reselect');
      if (
        !t ||
        t.pid !== d.pid ||
        t.start_ticks !== d.startTicks ||
        t.uid !== d.rule.filter.uid ||
        t.executable !== d.rule.executable ||
        t.revision !== d.rule.filter.revision
      )
        throw Error('Verified process instance changed; close and reselect');
      d.boundTarget = t;
    } else if (p.rule.filter.process)
      throw Error('Unexpected process target in application preview');
    const replaces = p.replaces ?? null;
    if (
      policy &&
      (p.rule.action !== e.action ||
        p.rule.filter.protocol !== '*' ||
        (p.rule.filter.remote_address || '*') !== '*' ||
        p.rule.filter.remote ||
        p.rule.filter.local_port ||
        p.rule.filter.remote_port ||
        !p.rule.expires.startsWith('0001-') ||
        (replaces
          ? typeof replaces.id !== 'string' ||
            !Number.isSafeInteger(replaces.version) ||
            p.rule.id !== replaces.id ||
            p.rule.version !== replaces.version + 1
          : p.rule.version !== 1))
    )
      throw Error('Backend preview is not the canonical application rule; nothing saved');
    const receipt = randomUUID();
    this.receipts.set(receipt, { draft: d, value, preview: p, sent: false, unresolved: false });
    return {
      receipt,
      preview: p.scope_preview + `\nEnforcement: ${p.enforcement.state} · ${p.enforcement.reason}`,
      expiresAt: p.expires_at,
      verifiedRule: p.rule,
      processID: p.process_id,
      ...(policy ? { replaces } : {}),
    };
  }
  private message(rule: Rule, reconciled = false) {
    const c = this.backend.view().control;
    const summary = c.policy?.applications.find(
      (a) =>
        a.identity.key === rule.filter.application &&
        a.identity.revision === rule.filter.revision &&
        a.identity.uid === rule.filter.uid,
    )?.[rule.filter.direction as 'incoming' | 'outgoing'];
    if (!summary && c.enforcement?.state === 'stopped')
      return `${reconciled ? 'Authoritative rules confirm the reviewed rule exists.' : 'Saved by backend.'} Stored ${rule.filter.direction} rule; enforcement is stopped.`;
    return `${reconciled ? 'Authoritative rules confirm the reviewed rule exists.' : 'Saved by backend.'} ${summary ? (summary.enforcement.covered ? `${rule.filter.direction} enforcement currently covers this direction.` : `Stored policy only for ${rule.filter.direction}: ${summary.enforcement.reason}`) : 'Enforcement coverage is not confirmed; saving does not activate protection.'}`;
  }
  async save(token: unknown): Promise<Attempt> {
    const r = typeof token === 'string' ? this.receipts.get(token) : undefined;
    if (!r || r.sent || this.busy || r.draft.locked)
      throw Error('Fresh reviewed preview required; creation is never replayed');
    const c = this.authority();
    if (c.generation !== r.draft.generation || this.backend.controller !== r.draft.endpoint)
      throw Error('Generation/endpoint changed; no save sent');
    if (r.draft.targetScope === 'process') {
      if (!c.capabilities?.includes(PROCESS_CAPABILITY))
        throw Error('Process capability lost; no save or fallback');
      const p = this.backend.view().observation.activity?.processes[r.draft.target.process_id];
      if (
        !p ||
        p.pid !== r.draft.pid ||
        p.start_ticks !== r.draft.startTicks ||
        p.uid !== r.draft.rule.filter.uid ||
        p.application.revision !== r.draft.rule.filter.revision
      )
        throw Error('Process instance no longer available; draft retained, no save sent');
    }
    if (Date.parse(r.preview.expires_at) <= this.backend.now())
      throw Error('Preview expired; preview again');
    r.sent = true;
    r.draft.locked = true;
    this.busy = true;
    try {
      const reply = await call(r.draft.endpoint, {
        operation: 'observed-rule-save',
        generation: r.draft.generation,
        preview_token: r.preview.token,
        observed_draft: r.value,
      });
      if (reply.error) {
        r.draft.locked = false;
        this.receipts.delete(String(token));
        return {
          phase: 'rejected',
          message: `${reply.error_code}: ${reply.error}. Review a fresh preview before saving again.`,
        };
      }
      if (
        reply.generation !== r.draft.generation ||
        !reply.saved_rule ||
        !sameRule(reply.saved_rule, r.preview.rule)
      )
        throw Error('Save acknowledgement does not match the reviewed rule');
      this.drafts.delete(r.draft.token);
      this.receipts.delete(String(token));
      await this.backend.pollControl();
      return {
        phase: 'acknowledged',
        rule: reply.saved_rule,
        message: this.message(reply.saved_rule),
      };
    } catch (e) {
      r.unresolved = true;
      return {
        phase: 'unknown',
        reconcile: String(token),
        message:
          'Save outcome unknown. Check authoritative rules; no creation is replayed. ' + String(e),
      };
    } finally {
      this.busy = false;
      await this.backend.pollControl();
    }
  }
  async reconcile(token: unknown): Promise<Attempt> {
    const r = typeof token === 'string' ? this.receipts.get(token) : undefined;
    if (!r?.sent || !r.unresolved) throw Error('No unresolved creation receipt');
    if (this.backend.controller !== r.draft.endpoint)
      throw Error('Reconnect to the original endpoint to inspect saved rules');
    await this.backend.pollControl();
    const c = this.backend.view().control,
      rule = c.rules?.find((rule) => rule.id === r.preview.rule.id);
    if (c.connected && rule && sameRule(rule, r.preview.rule)) {
      r.unresolved = false;
      this.drafts.delete(r.draft.token);
      this.receipts.delete(String(token));
      return { phase: 'acknowledged', rule, message: this.message(rule, true) };
    }
    return {
      phase: 'unknown',
      reconcile: String(token),
      message: c.connected
        ? rule
          ? 'The preview rule ID now has different contents. Inspect it; creation will not be replayed.'
          : 'Reviewed rule is not listed. Its absence does not prove creation failed. No replay; inspect after reconnect.'
        : 'Controller disconnected; save outcome remains unknown. No replay.',
    };
  }
}

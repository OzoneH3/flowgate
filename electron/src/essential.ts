import { call, type Backend } from './backend';
import {
  ESSENTIAL_CAPABILITY,
  essentialDefaults,
  essentialOptions,
  essentialPreview,
  essentialReceipt,
  essentialStatus,
  agreesWithEssential,
  sameEssentialOptions,
  type EssentialView,
  type EssentialPreview,
  type EssentialReceipt,
} from './essential-model';
// One main-owned review/mutation context. Renderer never supplies rules, peers or executable IDs.
export class Essential {
  private busy = false;
  private generation = '';
  private endpoint = '';
  private phase: EssentialView['phase'] = 'idle';
  private message = 'No policy changes. Preview the detected components before applying.';
  private status?: EssentialView['status'];
  private preview?: EssentialPreview;
  private receipt?: EssentialReceipt;
  constructor(private backend: Backend) {}
  view(): EssentialView {
    const snapshot = this.backend.view(),
      c = snapshot.control,
      source = this.backend.controller ? c : snapshot.observation;
    if (
      this.generation !== source.generation ||
      this.endpoint !== (this.backend.controller || this.backend.observer)
    ) {
      const previous = this.generation;
      this.generation = source.generation;
      this.endpoint = this.backend.controller || this.backend.observer;
      this.preview = undefined;
      this.receipt = undefined;
      this.status = undefined;
      this.phase = 'idle';
      if (previous)
        this.message = 'Daemon session changed. Old reviews and actions cannot be replayed.';
    }
    const supported = !!source.capabilities?.includes(ESSENTIAL_CAPABILITY),
      readable =
        source.connected &&
        supported &&
        source.permissions?.role === 'administrator' &&
        source.permissions.policy_scope === 'machine',
      permitted =
        !!this.backend.controller &&
        c.connected &&
        !c.readOnly &&
        supported &&
        c.permissions?.role === 'administrator' &&
        c.permissions.policy_scope === 'machine' &&
        c.permissions.can_manage_rules === true;
    const stopped = c.protection
      ? c.protection.state === 'stopped' &&
        c.protection.desired_mode === 'monitoring' &&
        ['confirmed', 'not_needed'].includes(c.protection.cleanup)
      : c.enforcement?.state === 'stopped';
    const evaluationBusy =
      !!c.evaluation && ['starting', 'active', 'stopping', 'degraded'].includes(c.evaluation.state);
    const monitoring = stopped && !evaluationBusy;
    const expired =
      this.phase === 'review' &&
      this.preview &&
      Date.parse(this.preview.expires_at) <= (c.serverNow || Date.now());
    return {
      monitoring,
      supported,
      connected: source.connected,
      permitted,
      canStatus: readable && !this.busy,
      generation: source.generation,
      busy: this.busy,
      phase: this.phase,
      message:
        (expired ? 'Review expired. Request a new preview; no mutation was sent.' : this.message) +
        (permitted && !monitoring
          ? ' Stop protection explicitly and confirm monitoring before Apply or Remove. No automatic Stop is sent.'
          : ''),
      status: this.status,
      preview: this.preview,
      receipt: this.receipt,
      canApply:
        permitted &&
        monitoring &&
        !this.busy &&
        this.phase === 'review' &&
        !!this.preview &&
        this.preview.rules.length > 0 &&
        Date.parse(this.preview.expires_at) > (c.serverNow || Date.now()),
      canReconcile: permitted && !this.busy && this.phase === 'unknown' && !!this.preview,
    };
  }
  async action(action: unknown, raw: unknown): Promise<EssentialView> {
    if (
      !['status', 'preview', 'apply', 'remove-preview', 'remove', 'reconcile'].includes(
        String(action),
      )
    )
      throw Error('Unknown Essential operation');
    const v = this.view(),
      q = raw as { generation?: unknown; options?: unknown; token?: unknown };
    if (
      !q ||
      typeof q !== 'object' ||
      Array.isArray(q) ||
      Object.keys(q).some((k) => !['generation', 'options', 'token'].includes(k)) ||
      q.generation !== v.generation
    )
      throw Error('Essential session changed; review current status.');
    if (!(action === 'status' ? v.canStatus : v.permitted) || this.busy)
      throw Error('Essential networking requires the primary machine administrator connection.');
    if (this.phase === 'unknown' && !['status', 'reconcile'].includes(String(action)))
      throw Error('Previous outcome is unknown; check its receipt before another mutation.');
    const generation = v.generation,
      endpoint = this.backend.controller || this.backend.observer;
    const fresh = () => {
      const s = this.backend.view(),
        c = this.backend.controller ? s.control : s.observation;
      if (
        (this.backend.controller || this.backend.observer) !== endpoint ||
        c.generation !== generation
      )
        throw Error('Daemon changed; stale Essential response discarded.');
    };
    const request = async (operation: string, extra: Record<string, unknown> = {}) => {
      const r = await call(endpoint, { operation, generation, ...extra }, 20000);
      fresh();
      if (r.generation !== generation)
        throw Error('Daemon changed; stale Essential response discarded.');
      return r;
    };
    this.busy = true;
    try {
      if (action === 'status' || action === 'reconcile') {
        if (
          action === 'reconcile' &&
          (!this.preview || q.token !== this.preview.token || this.phase !== 'unknown')
        )
          throw Error('Unknown Essential receipt');
        const p = this.preview,
          r = await request(
            'essential-status',
            action === 'reconcile' ? { preview_token: p!.token } : {},
          );
        if (r.essential_status) this.status = essentialStatus(r.essential_status);
        if (r.error || r.error_code) throw Error(`${r.error_code}: ${r.error}`);
        if (action === 'reconcile') {
          const receipt = essentialReceipt(r.essential_receipt);
          if (!agreesWithEssential(p!, receipt))
            throw Error('Receipt differs from the exact reviewed Essential operation.');
          this.receipt = receipt;
          this.phase = 'confirmed';
          this.message = 'Authoritative receipt confirmed. No operation replayed.';
          await this.backend.pollControl();
          fresh();
        } else if (this.phase !== 'unknown')
          this.message = 'Detected status refreshed. Protection was not started.';
      } else if (action === 'preview' || action === 'remove-preview') {
        const options = action === 'preview' ? essentialOptions(q.options) : essentialDefaults();
        this.preview = undefined;
        this.receipt = undefined;
        this.phase = 'idle';
        const r = await request(
          action === 'preview' ? 'essential-preview' : 'essential-remove-preview',
          { essential_options: options },
        );
        if (r.error || r.error_code) throw Error(`${r.error_code}: ${r.error}`);
        const p = essentialPreview(r.essential_preview);
        if (
          p.operation !== (action === 'preview' ? 'apply' : 'remove') ||
          (action === 'preview' && !sameEssentialOptions(p.options, options)) ||
          !p.token ||
          !p.revision ||
          Date.parse(p.expires_at) <= (this.backend.view().control.serverNow || Date.now())
        )
          throw Error(
            'Essential preview scope, operation or expiry disagrees with the requested review.',
          );
        this.preview = p;
        this.phase = 'review';
        this.message =
          p.operation === 'apply'
            ? 'Review these exact permissions, then Apply. This does not start protection.'
            : 'Review these exact unedited preset records, then Remove. Other rules are preserved.';
      } else {
        const p = this.preview;
        if (
          !p ||
          !v.canApply ||
          q.token !== p.token ||
          p.operation !== (action === 'apply' ? 'apply' : 'remove')
        )
          throw Error('Fresh exact Essential preview required.');
        if (action === 'apply' && !sameEssentialOptions(essentialOptions(q.options), p.options))
          throw Error('Options changed; obtain a fresh review.');
        let sent = false;
        try {
          await this.backend.ruleMutation(async () => {
            sent = true;
            const r = await request(action === 'apply' ? 'essential-apply' : 'essential-remove', {
              preview_token: p.token,
              essential_options: p.options,
            });
            if (r.error || r.error_code) {
              sent = false;
              throw Error(`${r.error_code}: ${r.error}`);
            }
            const receipt = essentialReceipt(r.essential_receipt);
            if (!agreesWithEssential(p, receipt))
              throw Error('Acknowledgement differs from the reviewed Essential operation.');
            this.receipt = receipt;
            this.phase = 'confirmed';
            this.message =
              action === 'apply'
                ? 'Exact preset permissions saved. Protection state is unchanged.'
                : 'Exact reviewed preset records removed. Other rules preserved.';
          });
          fresh();
        } catch (e) {
          if (sent) {
            this.phase = 'unknown';
            this.message = `Outcome unknown: ${String(e)} No retry sent; check the receipt.`;
          } else throw e;
        }
      }
    } catch (e) {
      this.message = String(e);
      if (this.phase !== 'unknown') this.phase = 'error';
    } finally {
      this.busy = false;
    }
    return this.view();
  }
}

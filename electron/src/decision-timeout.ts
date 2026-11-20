import { call, type Backend } from './backend';

const CAPABILITY = 'decision-timeout-settings-v1';
const validRevision = (revision: unknown): revision is string =>
  typeof revision === 'string' && /^[1-9][0-9]{0,19}$/.test(revision);

export interface DecisionTimeoutEdit {
  seconds: number;
  generation: string;
  expectedRevision: string;
}

export interface DecisionTimeoutView {
  generation: string;
  seconds: number;
  revision: string;
  writable: boolean;
}

export async function decisionTimeout(backend: Backend, edit?: unknown): Promise<DecisionTimeoutView> {
  const target = () => {
    const { control } = backend.view();
    if (!backend.controller || !control.connected || !control.capabilities?.includes(CAPABILITY))
      throw Error('Permission popup timeout is unavailable from this daemon.');
    return {
      path: backend.controller,
      generation: control.generation,
      writable: !control.readOnly && control.permissions?.role === 'administrator'
        && control.permissions.can_manage_machine_rules === true,
    };
  };
  const current = target();
  const request = { operation: 'decision-timeout-status', generation: current.generation };
  let change: DecisionTimeoutEdit | undefined;
  if (edit !== undefined) {
    if (!current.writable) throw Error('Administrator access is required to change this setting.');
    const v = edit as Partial<DecisionTimeoutEdit> | null;
    if (!v || typeof v.seconds !== 'number' || !Number.isInteger(v.seconds)
      || v.seconds < 2 || v.seconds > 60 || !validRevision(v.expectedRevision))
      throw Error('Enter a whole number from 2 to 60 seconds.');
    if (v.generation !== current.generation) throw Error('Daemon changed. Refresh before saving.');
    change = { seconds: v.seconds, generation: v.generation, expectedRevision: v.expectedRevision };
  }
  const reply = await call(current.path, change ? {
    ...request,
    operation: 'decision-timeout-configure',
    decision_timeout: { seconds: change.seconds, expected_revision: change.expectedRevision },
  } : request);
  const after = target();
  if (after.generation !== current.generation || reply.generation !== current.generation)
    throw Error('Daemon changed. Refresh settings.');
  if (reply.error || reply.error_code) throw Error(reply.error || reply.error_code);
  const settings = reply.decision_timeout as { seconds?: unknown; revision?: unknown } | undefined;
  if (typeof settings?.seconds !== 'number' || !Number.isFinite(settings.seconds)
    || settings.seconds < 1 || settings.seconds > 60 || !validRevision(settings.revision))
    throw Error('Invalid permission popup timeout from the daemon.');
  if (change && (settings.seconds !== change.seconds
    || BigInt(settings.revision) !== BigInt(change.expectedRevision) + 1n))
    throw Error('The daemon did not confirm the requested change.');
  return { generation: reply.generation, seconds: settings.seconds, revision: settings.revision, writable: after.writable };
}

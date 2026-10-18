// Backend-issued immutable binding. Display/echo validation only, never policy matching.
export const PROCESS_CAPABILITY = 'process-instance-rules-v1';
export interface ProcessTarget {
  instance_id: string;
  session: string;
  boot_id: string;
  pid: number;
  start_ticks: string;
  uid: number;
  netns: string;
  mountns: string;
  pidns: string;
  executable: string;
  revision: string;
}
export function parseProcessTarget(value: unknown, provisional = false): ProcessTarget | undefined {
  if (value === undefined) return undefined;
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw Error('Invalid process binding');
  const v = value as Record<string, unknown>;
  const text = (k: string) => {
    if (typeof v[k] !== 'string' || !v[k] || v[k].length > 16384)
      throw Error('Invalid process binding: ' + k);
    return v[k] as string;
  };
  const integer = (k: string) => {
    if (!Number.isSafeInteger(v[k]) || Number(v[k]) < 0)
      throw Error('Invalid process binding: ' + k);
    return Number(v[k]);
  };
  const result = {
    instance_id: provisional && v.instance_id === '' ? '' : text('instance_id'),
    session: text('session'),
    boot_id: text('boot_id'),
    pid: integer('pid'),
    start_ticks: text('start_ticks'),
    uid: integer('uid'),
    netns: text('netns'),
    mountns: text('mountns'),
    pidns: text('pidns'),
    executable: text('executable'),
    revision: text('revision'),
  };
  if (
    (!(provisional && result.instance_id === '') && !/^[a-f0-9]{32}$/.test(result.instance_id)) ||
    !result.pid ||
    !/^(0|[1-9][0-9]{0,19})$/.test(result.start_ticks) ||
    BigInt(result.start_ticks) > 18446744073709551615n
  )
    throw Error('Invalid native process identity');
  return result;
}
export const sameProcessTarget = (a?: ProcessTarget, b?: ProcessTarget) =>
  JSON.stringify(a) === JSON.stringify(b);
export const targetLabel = (target?: ProcessTarget) =>
  target
    ? `This process · PID ${target.pid} · start ${target.start_ticks}`
    : 'Application · all instances';

import { execFile } from 'node:child_process';

// NSS lookup is bounded and never used for attribution or authorization.
const cache = new Map<number, {name: string | null; until: number}>();
const pending = new Map<number, Promise<string | null>>();
let active = 0;
const queue: Array<() => void> = [];
function run(uid: number): Promise<string | null> {
  return new Promise(resolve => {
    const start = () => {
      active++;
      execFile('getent', ['passwd', String(uid)], {timeout: 2000, maxBuffer: 4096}, (error, output) => {
        let name: string | null = null;
        if (!error) {
          const lines = output.trimEnd().split('\n');
          const fields = lines[0]?.split(':') || [];
          if (lines.length === 1 && fields.length >= 7 && fields[2] === String(uid) && fields[0].length <= 256 && /^[^:\x00-\x1f\x7f]+$/.test(fields[0])) name = fields[0];
        }
        active--;
        queue.shift()?.();
        resolve(name);
      });
    };
    if (active < 4) start(); else queue.push(start);
  });
}
export function accountName(uid: unknown): Promise<string | null> {
  if (typeof uid !== 'number' || !Number.isSafeInteger(uid) || uid < 0 || uid > 0xffffffff) return Promise.reject(Error('Invalid UID'));
  const found = cache.get(uid);
  if (found && found.until > Date.now()) return Promise.resolve(found.name);
  if (pending.has(uid)) return pending.get(uid)!;
  if (pending.size >= 128) return Promise.resolve(null);
  const lookup = run(uid).then(name => {
    if (cache.size >= 512) cache.delete(cache.keys().next().value!);
    cache.set(uid, {name, until: Date.now() + (name ? 60000 : 5000)});
    return name;
  }).finally(() => pending.delete(uid));
  pending.set(uid, lookup);
  return lookup;
}

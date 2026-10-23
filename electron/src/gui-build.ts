import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { HEX40, type GuiBuild } from './build-info';

// Main process only: compares the running GUI's files with its release manifest
// (<bundle>/matched-manifest.json next to <bundle>/electron). Matching listed
// files identifies the prepared release; it is not proof of source authenticity.
const MAX_FILES = 4096;
const MAX_MANIFEST_BYTES = 4 * 1024 * 1024;
const ISO = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?(Z|[+-]\d\d:\d\d)$/;
const plain = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);

export function readGuiBuild(appPath: string): GuiBuild {
  let app: string, bundle: string;
  try {
    app = fs.realpathSync(appPath);
    bundle = path.dirname(app);
  } catch {
    return { state: 'unverified', reason: 'GUI application path unreadable.' };
  }
  const manifestPath = path.join(bundle, 'matched-manifest.json');
  let text: string;
  try {
    const fd = fs.openSync(manifestPath, 'r');
    try {
      const buffer = Buffer.alloc(MAX_MANIFEST_BYTES + 1);
      const size = fs.readSync(fd, buffer, 0, buffer.length, 0);
      if (size > MAX_MANIFEST_BYTES) return { state: 'unverified', reason: 'Release manifest exceeds its size bound.' };
      text = buffer.subarray(0, size).toString('utf8');
    } finally {
      fs.closeSync(fd);
    }
  } catch (e) {
    // Only an absent manifest means "not a release" (development run).
    return (e as NodeJS.ErrnoException).code === 'ENOENT'
      ? { state: 'unavailable', reason: 'Not running from a prepared release bundle (no release manifest).' }
      : { state: 'unverified', reason: 'Release manifest unreadable.' };
  }
  let manifest: unknown;
  try {
    manifest = JSON.parse(text);
  } catch {
    return { state: 'unverified', reason: 'Release manifest is not valid JSON.' };
  }
  if (!plain(manifest) || !plain(manifest.files))
    return { state: 'unverified', reason: 'Release manifest has an unexpected shape.' };
  const source = typeof manifest.source === 'string' && HEX40.test(manifest.source) ? manifest.source : undefined;
  const gui = Object.entries(manifest.files).filter(([name]) => name.startsWith('electron/'));
  if (!source || !gui.some(([name]) => name === 'electron/dist/main.cjs') || gui.length > MAX_FILES)
    return { state: 'unverified', reason: 'Release manifest does not identify this GUI.' };
  for (const [name, expected] of gui) {
    if (typeof expected !== 'string' || !/^[0-9a-f]{64}$/.test(expected))
      return { state: 'unverified', reason: 'Release manifest entry is invalid: ' + name };
    let actual: string;
    try {
      // The real path must stay inside this GUI's application directory
      // (a symlinked entry cannot point elsewhere).
      const real = fs.realpathSync(path.join(bundle, name));
      if (!real.startsWith(app + path.sep)) return { state: 'unverified', reason: 'GUI file outside its application: ' + name };
      actual = crypto.createHash('sha256').update(fs.readFileSync(real)).digest('hex');
    } catch {
      return { state: 'unverified', reason: 'GUI file missing from its release: ' + name };
    }
    if (actual !== expected) return { state: 'unverified', reason: 'GUI file differs from its release manifest: ' + name };
  }
  const builtAt =
    typeof manifest.built_at === 'string' && ISO.test(manifest.built_at) && Number.isFinite(Date.parse(manifest.built_at))
      ? manifest.built_at
      : undefined;
  return { state: 'verified', source, builtAt, reason: 'GUI files match the release manifest.' };
}

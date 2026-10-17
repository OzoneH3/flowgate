import { build } from 'esbuild';
import { mkdir, copyFile } from 'node:fs/promises';
await mkdir('dist', { recursive: true });
await build({
  entryPoints: ['src/main.ts'],
  bundle: true,
  platform: 'node',
  format: 'cjs',
  external: ['electron'],
  outfile: 'dist/main.cjs',
});
await build({
  entryPoints: ['src/preload.ts'],
  bundle: true,
  platform: 'node',
  format: 'cjs',
  external: ['electron'],
  outfile: 'dist/preload.cjs',
});
await build({
  entryPoints: ['src/renderer.ts'],
  bundle: true,
  platform: 'browser',
  format: 'iife',
  outfile: 'dist/renderer.js',
});
await build({
  entryPoints: ['src/model.ts', 'src/backend.ts', 'src/extended.ts', 'src/rules.ts'],
  bundle: true,
  platform: 'node',
  format: 'cjs',
  outdir: 'dist/test',
  outExtension: { '.js': '.cjs' },
});
for (const file of ['index.html', 'style.css']) await copyFile(`src/${file}`, `dist/${file}`);

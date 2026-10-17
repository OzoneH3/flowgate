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
  entryPoints: [
    'src/model.ts',
    'src/policy.ts',
    'src/editor-presentation.ts',
    'src/icons.ts',
    'src/rule-status.ts',
    'src/backend.ts',
    'src/extended.ts',
    'src/daemon-monitoring.ts',
    'src/rules.ts',
    'src/observed-rules.ts',
    'src/notifications.ts',
    'src/history.ts',
    'src/decision-log.ts',
    'src/evaluation-model.ts',
    'src/daemon-evaluation.ts',
    'src/evaluation.ts',
  ],
  bundle: true,
  platform: 'node',
  format: 'cjs',
  outdir: 'dist/test',
  outExtension: { '.js': '.cjs' },
});
for (const file of ['index.html', 'style.css']) await copyFile(`src/${file}`, `dist/${file}`);

await copyFile('assets/flowgate-tray.png', 'dist/flowgate-tray.png');

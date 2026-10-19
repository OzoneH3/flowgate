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
    'src/connection-presentation.ts',
    'src/automatic-prompts.ts',
    'src/decision-remember.ts',
    'src/request-rule.ts',
    'src/process-lease.ts',
    'src/prompt-decision.ts',
    'src/prompt-card.ts',
    'src/provenance.ts',
    'src/local-pair.ts',
    'src/prompt-placement.ts',
    'src/assets.ts',
    'src/pane-model.ts',
    'src/chart-view.ts',
    'src/graph.ts',
    'src/popup-position.ts',
    'src/network-zones.ts',
    'src/zone-rules.ts',
    'src/zone-migration.ts',
    'src/display-units.ts',
    'src/initiation.ts',
    'src/protocol.ts',
    'src/process-rules.ts',
    'src/activity-policy.ts',
    'src/policy.ts',
    'src/editor-presentation.ts',
    'src/icons.ts',
    'src/rule-status.ts',
    'src/rule-chip.ts',
    'src/backend.ts',
    'src/inventory-coherence.ts',
    'src/state-clock.ts',
    'src/publication.ts',
    'src/row-structure.ts',
    'src/keyed-rows.ts',
    'src/protection-model.ts',
    'src/essential-model.ts',
    'src/essential.ts',
    'src/protection.ts',
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
await build({entryPoints:['src/pane-preload.ts'],bundle:true,platform:'node',format:'cjs',external:['electron'],outfile:'dist/pane-preload.cjs'});
await build({entryPoints:['src/pane-renderer.ts'],bundle:true,platform:'browser',format:'iife',outfile:'dist/pane.js'});
for (const file of ['index.html', 'pane.html', 'style.css']) await copyFile(`src/${file}`, `dist/${file}`);

await copyFile('assets/flowgate-tray.png', 'dist/flowgate-tray.png');
await mkdir('dist/fonts', { recursive: true });
for (const f of ['selawk.ttf', 'selawkb.ttf', 'selawksb.ttf', 'LICENSE-Selawik-OFL.txt'])
  await copyFile(`assets/fonts/${f}`, `dist/fonts/${f}`);

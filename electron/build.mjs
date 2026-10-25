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
    'src/session-exit.ts',
    'src/attribution-reason.ts',
    'src/endpoint-policy.ts',
    'src/endpoint-rules.ts',
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
    'src/flatpak-names.ts',
    'src/icon-ico.ts',
    'src/icon-pe.ts',
    'src/desktop-game.ts',
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
    'src/prompt-summary.ts',
    'src/permission-results.ts',
    'src/runtime-checks.ts',
    'src/queue-health.ts',
    'src/card-result.ts',
    'src/build-info.ts',
    'src/gui-build.ts',
    'src/inactive-rules.ts',
    'src/observed-usage.ts',
    'src/usage-history.ts',
    'src/usage-history-client.ts',
    'src/observed-usage-client.ts',
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
await copyFile('assets/flowgate.png', 'dist/flowgate.png');
await copyFile('assets/flowgate-tray-off.png', 'dist/flowgate-tray-off.png');
await copyFile('assets/flowgate-off.png', 'dist/flowgate-off.png');
await mkdir('dist/fonts', { recursive: true });
for (const f of ['selawk.ttf', 'selawkb.ttf', 'selawksb.ttf', 'LICENSE-Selawik-OFL.txt'])
  await copyFile(`assets/fonts/${f}`, `dist/fonts/${f}`);

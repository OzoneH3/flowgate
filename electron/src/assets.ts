// This is a fixed asset table, not a filesystem read API. Unknown paths never reach readFile.
const assets: Record<string, string> = {
  'index.html': 'text/html',
  'prompt.html': 'text/html',
  'permission-popup.css': 'text/css',
  'style.css': 'text/css',
  'renderer.js': 'text/javascript',
  'pane.html': 'text/html',
  'pane.js': 'text/javascript',
  'flowgate.png': 'image/png',
  'flowgate-off.png': 'image/png',
  'fonts/selawk.ttf': 'font/ttf',
  'fonts/selawksb.ttf': 'font/ttf',
  'fonts/selawkb.ttf': 'font/ttf',
};
export function bundledAsset(name: string): string | undefined {
  return Object.hasOwn(assets, name) ? assets[name] : undefined;
}

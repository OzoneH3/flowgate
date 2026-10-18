// This is a fixed asset table, not a filesystem read API. Unknown paths never reach readFile.
const assets: Record<string, string> = {
  'index.html': 'text/html',
  'style.css': 'text/css',
  'renderer.js': 'text/javascript',
  'fonts/selawk.ttf': 'font/ttf',
  'fonts/selawksb.ttf': 'font/ttf',
  'fonts/selawkb.ttf': 'font/ttf',
};
export function bundledAsset(name: string): string | undefined {
  return Object.hasOwn(assets, name) ? assets[name] : undefined;
}

import fs from 'node:fs';
import path from 'node:path';

// This is a fixed asset table, not a filesystem read API. Unknown paths never reach readFile.
const assets: Record<string, string> = {
  'index.html': 'text/html',
  'prompt.html': 'text/html',
  'permission-popup.css': 'text/css',
  'theme.css': 'text/css',
  'popup-theme.css': 'text/css',
  'style.css': 'text/css',
  'tooltip.css': 'text/css',
  'desktop-layout.css': 'text/css',
  'pane.css': 'text/css',
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

const userStyles: Record<string, string> = {
  'theme.css': 'theme.css',
  'popup-theme.css': 'popup-theme.css',
  'user-style.css': 'style.css',
  'user-desktop-layout.css': 'desktop-layout.css',
  'user-pane.css': 'pane.css',
  'user-permission-popup.css': 'permission-popup.css',
};
const maxStyleBytes = 1024 * 1024;

// Only the listed routes can read user configuration. Missing or invalid files
// skip the override. Theme slots fall back to their bundled asset.
export function userStylesheet(name: string, directory: string): string | undefined {
  if (!Object.hasOwn(userStyles, name)) return undefined;
  const fallback = bundledAsset(name) ? undefined : '';
  try {
    const fd = fs.openSync(
      path.join(directory, userStyles[name]),
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK,
    );
    try {
      const file = fs.fstatSync(fd);
      if (!file.isFile() || file.size > maxStyleBytes) return fallback;
      const bytes = Buffer.alloc(file.size + 1);
      const length = fs.readSync(fd, bytes);
      return length === file.size ? bytes.toString('utf8', 0, length) : fallback;
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    return fallback;
  }
}

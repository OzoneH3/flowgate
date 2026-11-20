import fs from 'node:fs';
import path from 'node:path';

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

const userStyles: Record<string, string> = {
  'user-style.css': 'style.css',
  'user-permission-popup.css': 'permission-popup.css',
};
const maxStyleBytes = 1024 * 1024;

// Only these two routes can read user configuration. Missing or invalid files
// serve an empty stylesheet so the bundled theme can still load.
export function userStylesheet(name: string, directory: string): string | undefined {
  if (!Object.hasOwn(userStyles, name)) return undefined;
  try {
    const fd = fs.openSync(
      path.join(directory, userStyles[name]),
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK,
    );
    try {
      const file = fs.fstatSync(fd);
      if (!file.isFile() || file.size > maxStyleBytes) return '';
      const bytes = Buffer.alloc(file.size + 1);
      const length = fs.readSync(fd, bytes);
      return length === file.size ? bytes.toString('utf8', 0, length) : '';
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    return '';
  }
}

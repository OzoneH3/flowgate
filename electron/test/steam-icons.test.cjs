// Steam game icons come only from a verified install directory + exact app manifest + local Steam icon.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { ApplicationIcons, iconKey } = require('../dist/test/icons.cjs');
const roots = [];
process.on('exit', () => roots.forEach((r) => fs.rmSync(r, { recursive: true, force: true })));

// 1x1 PNG.
const png = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGNgYGD4DwABBAEAwS2OUAAAAABJRU5ErkJggg==',
  'base64',
);
function fixture() {
  const root = fs.mkdtempSync(path.join(__dirname, '../../.workspace/steam-icons-'));
  roots.push(root);
  const home = path.join(root, 'home'),
    lib = path.join(root, 'mnt/Games/SteamLibrary'),
    mount = path.join(root, 'run-media-link');
  fs.mkdirSync(path.join(home, '.local/share/Steam/steamapps'), { recursive: true });
  fs.mkdirSync(path.join(lib, 'steamapps/common/Slay the Spire 2'), { recursive: true });
  fs.mkdirSync(path.join(lib, 'steamapps/common/Other Game'), { recursive: true });
  fs.mkdirSync(path.join(lib, 'steamapps/common/No Art'), { recursive: true });
  fs.mkdirSync(path.join(lib, 'steamapps/common/Twice'), { recursive: true });
  fs.symlinkSync(path.join(root, 'mnt/Games'), mount); // library configured through a symlinked mount path
  fs.writeFileSync(
    path.join(home, '.local/share/Steam/steamapps/libraryfolders.vdf'),
    `"libraryfolders"\n{\n "0"\n {\n  "path"\t\t"${home}/.local/share/Steam"\n }\n "1"\n {\n  "path"\t\t"${mount}/SteamLibrary"\n }\n "2"\n {\n  "path"\t\t"${root}/disconnected/SteamLibrary"\n }\n}\n`,
  );
  const manifest = (id, dir, name) =>
    fs.writeFileSync(
      path.join(lib, `steamapps/appmanifest_${id}.acf`),
      `"AppState"\n{\n\t"appid"\t\t"${id}"\n\t"name"\t\t"${name}"\n\t"installdir"\t\t"${dir}"\n}\n`,
    );
  manifest(2868840, 'Slay the Spire 2', 'Slay the Spire 2');
  manifest(111, 'Other Game', 'Other Game');
  manifest(222, 'No Art', 'No Art');
  manifest(333, 'Twice', 'Twice A');
  manifest(334, 'Twice', 'Twice B');
  const exe = (dir, name) => {
    const f = path.join(lib, 'steamapps/common', dir, name);
    fs.writeFileSync(f, '#!/bin/sh\n');
    fs.chmodSync(f, 0o755);
    return path.join(mount, 'SteamLibrary/steamapps/common', dir, name);
  };
  for (const [id, color] of [
    [2868840, 1],
    [111, 2],
    [333, 3],
  ]) {
    const d = path.join(home, '.local/share/icons/hicolor/32x32/apps');
    fs.mkdirSync(d, { recursive: true });
    fs.writeFileSync(path.join(d, `steam_icon_${id}.png`), Buffer.concat([png, Buffer.from([color])]));
  }
  fs.writeFileSync(
    path.join(home, '.local/share/icons/hicolor/index.theme'),
    '[Icon Theme]\nName=hicolor\nDirectories=32x32/apps\n[32x32/apps]\nSize=32\n',
  );
  const icons = new ApplicationIcons(home, [path.join(home, '.local/share')], []);
  const apps = {
    sts: { key: 'k1', revision: 'r', name: 'SlayTheSpire2', executable: exe('Slay the Spire 2', 'SlayTheSpire2') },
    other: { key: 'k2', revision: 'r', name: 'other', executable: exe('Other Game', 'other') },
    noart: { key: 'k3', revision: 'r', name: 'noart', executable: exe('No Art', 'noart') },
    twice: { key: 'k4', revision: 'r', name: 'twice', executable: exe('Twice', 'twice') },
    outside: { key: 'k5', revision: 'r', name: 'SlayTheSpire2', executable: path.join(root, 'SlayTheSpire2') },
  };
  fs.writeFileSync(apps.outside.executable, '#!/bin/sh\n');
  fs.chmodSync(apps.outside.executable, 0o755);
  icons.observe({
    observation: { activity: { processes: Object.fromEntries(Object.entries(apps).map(([k, a]) => [k, { application: a }])), rows: [] } },
    control: { events: [] },
  });
  return { icons, apps, home, root };
}

test('Steam game icon and name from exact installdir manifest; spaces and symlinked /run/media-style library', async () => {
  const { icons, apps, home } = fixture();
  const keys = Object.values(apps).map(iconKey);
  const m = await icons.metadata(keys);
  const sts = m[iconKey(apps.sts)];
  assert.match(sts.icon, /^flowgate:\/\/app\/icons\/[0-9a-f]{64}\.png$/);
  assert.equal(sts.name, 'Slay the Spire 2');
  assert.equal(sts.source, 'steam-manifest');
  const id = sts.icon.split('/').pop();
  const expected = fs.readFileSync(path.join(home, '.local/share/icons/hicolor/32x32/apps/steam_icon_2868840.png'));
  assert.deepEqual(icons.asset(id).data, expected, 'icon is this app ID, not another game');
  assert.notEqual(m[iconKey(apps.other)].icon, sts.icon, 'other game keeps its own icon');
});

test('missing artwork, ambiguous manifests, executable outside a library and disconnected drives fall back neutrally', async () => {
  const { icons, apps } = fixture();
  const m = await icons.metadata(Object.values(apps).map(iconKey));
  assert.equal(m[iconKey(apps.noart)].icon, null);
  assert.equal(m[iconKey(apps.noart)].name, 'No Art');
  assert.equal(m[iconKey(apps.twice)].icon, null, 'two manifests claim the same installdir: no guess');
  assert.equal(m[iconKey(apps.twice)].source, 'unavailable');
  assert.equal(m[iconKey(apps.outside)].icon, null, 'same name outside a Steam library is not the game');
  assert.equal(m[iconKey(apps.outside)].source, 'unavailable');
});

test('renderer cannot request icons for unobserved paths', async () => {
  const { icons } = fixture();
  const forged = JSON.stringify(['x', 'r', '/etc/passwd']);
  assert.equal((await icons.request([forged]))[forged], null);
});

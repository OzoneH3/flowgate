const assert = require('node:assert/strict');
const path = require('node:path');
const { test } = require('node:test');
const vm = require('node:vm');
const { buildSync } = require('esbuild');

const [{ text: background }] = buildSync({
  entryPoints: [path.join(__dirname, '../src/background.ts')],
  bundle: true,
  platform: 'node',
  format: 'cjs',
  external: ['electron'],
  write: false,
}).outputFiles;

test('only File → Quit from a visible, focused, unminimized main window skips activation', async (t) => {
  for (const [name, windowState, fromFileMenu, shouldShow] of [
    ['File with focused main window', {}, true, false],
    ['File with hidden main window', { visible: false }, true, true],
    ['File with minimized main window', { minimized: true }, true, true],
    ['File with unfocused main window', { focused: false }, true, true],
    ['other Quit entry points with focused main window', {}, undefined, true],
  ]) {
    await t.test(name, async () => {
      const events = [];
      const main = {
        isVisible: () => windowState.visible ?? true,
        isMinimized: () => windowState.minimized ?? false,
        isFocused: () => windowState.focused ?? true,
      };
      const module = { exports: {} };
      const electron = {
        nativeImage: { createFromPath: () => ({}) },
        dialog: {
          showMessageBox: async (parent, options) => {
            assert.equal(parent, main);
            assert.equal(options.title, 'Quit FlowGate UI');
            assert.equal(options.buttons[options.defaultId], 'Keep running');
            assert.equal(options.cancelId, options.defaultId);
            events.push('confirmation');
            return { response: options.defaultId };
          },
        },
      };
      vm.runInNewContext(background, {
        module, __dirname: path.dirname(__dirname),
        require: name => {
          if (name === 'electron') return electron;
          if (name === 'node:child_process') return { execFile: () => {} };
          return require(name);
        },
        setInterval, clearInterval,
      });
      const instance = new module.exports.Background(main, new Set(), () => ({
        control: { connected: true, events: [{ state: 'awaiting-decision', remainingMs: 1000 }] },
      }), () => events.push('show'), () => {}, () => events.push('quit'), () => {});
      try {
        await instance.requestQuit(fromFileMenu);
        assert.deepEqual(events, shouldShow ? ['show', 'confirmation'] : ['confirmation']);
      } finally {
        instance.close();
      }
    });
  }
});

# Local-only Electron UI

The UI loads bundled `flowgate://app/` assets and uses Unix sockets for daemon
IPC. It does not need an Internet Allow rule. CSP and the session request guard
reject external page requests; sandboxing and restricted IPC remain enabled.
Chromium background networking, component updates and domain reliability are
disabled. The app-local resolver disables DNS-over-HTTPS, and the default
session has no spellchecking languages and spellchecking disabled before windows
are created. The existing per-window `spellcheck: false` alone was insufficient.

A startup NetLog captured a download of
`https://redirector.gvt1.com/edgedl/chrome/dict/en-us-10-1.bdic` even with per-window
spellchecking disabled. Each fresh profile retried the dictionary download.
Separately, release-specific application bundle paths mean existing firewall
rules do not cover a new UI release. The fix removes the unnecessary download;
it does not migrate rules, exempt FlowGate from enforcement, or change other
Electron applications' permissions. Existing stored rules are left untouched.

After building, run from the desktop session:

```sh
npm --prefix electron run build
python3 scripts/checks/check-ui-offline-startup.py
```

The check starts and closes only its own two sandboxed Wayland observer windows,
with fresh profiles, and records NetLogs under `.workspace/offline-ui-*`. It
asserts rendering and no TCP/UDP connect/send or HTTP/WebSocket request events
during each ten-second startup. This is bounded startup coverage, not a claim
about every possible future action. It never attaches the control API or changes
host protection or stored rules.

Electron API reference:
https://www.electronjs.org/docs/latest/api/session#sessetspellcheckerlanguageslanguages

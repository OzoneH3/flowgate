// Superseded: this runner drove the process-scoped quick setter (round 1 inline setter), whose controls were replaced by the
// Rule Status popup. The same real journey (select target → set/change exact rule →
// inspect fallback → disable/delete → stale action → exit) now lives in rule-status-workflow.mjs.
// Kept as a thin alias so documented commands still run against a held disposable fixture.
if (!process.env.FLOWGATE_TEST_READY)
  throw Error(
    'Superseded by rule-status-workflow.mjs: set FLOWGATE_TEST_READY=<held fixture>/ready.json (scripts/acceptance/process-rules-isolated.py --hold). Never the host daemon.',
  );
await import('./rule-status-workflow.mjs');

# Development handoff

Read [STATUS.md](STATUS.md) for maintained scope and operational status. Earlier
session-by-session records are retained in [HANDOFF-HISTORY.md](HANDOFF-HISTORY.md).
Their installed hashes, “current” banners and pending steps are historical.

Before changing shared source, read `AGENTS.md` and current coordination notes in
`.workspace/coordination/`. Agree file/hunk ownership with other active sessions;
retain their changes and stage only reviewed work. Keep scratch output in
`.workspace/`, never commit private runtime/rule evidence.

Use verifiable process generations, executable/runtime and socket evidence.
Permissions do not transfer from names, command lines, parents, launchers or
ambiguous holders. Preserve explicit user, prefix and direction separation.

Native/kernel checks run sequentially in a capped TCG guest, with no host network
or filesystem sharing. Keep source/binary hashes and actual receiver assertions.
A model result is not a native UI check; a saved rule is not proof that Once works.
Use the project release workflow and [DAILY-DEPLOYMENT.md](DAILY-DEPLOYMENT.md) for
an explicitly requested deployment. Inspect the live state instead of restoring a
mode from historical prose. Updates preserve the current mode by default.

Contract entry points: [SEMANTICS.md](SEMANTICS.md), [RULES.md](RULES.md),
[ATTRIBUTION.md](ATTRIBUTION.md), [TRAFFIC.md](TRAFFIC.md),
[DIAGNOSTICS.md](DIAGNOSTICS.md), [NETWORK-ENDPOINTS.md](NETWORK-ENDPOINTS.md).

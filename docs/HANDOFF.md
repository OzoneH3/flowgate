# Development handoff

Read [STATUS.md](STATUS.md) for maintained scope and operational status.

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

## Historical records

These records describe the revisions tested at the time. A full clone can read
them offline, for example with `git show f17f443b8f:docs/HANDOFF-HISTORY.md`.

- [Pre-desktop backend evidence](https://github.com/OzoneH3/flowgate/blob/f17f443b8f221e2bf6fabbd756f4af4329096875/docs/HISTORY.md)
- [Session handoffs](https://github.com/OzoneH3/flowgate/blob/f17f443b8f221e2bf6fabbd756f4af4329096875/docs/HANDOFF-HISTORY.md)
- [Integration results](https://github.com/OzoneH3/flowgate/blob/f17f443b8f221e2bf6fabbd756f4af4329096875/docs/INTEGRATION-HISTORY.md)
- [Release status snapshots](https://github.com/OzoneH3/flowgate/blob/f17f443b8f221e2bf6fabbd756f4af4329096875/docs/STATUS-HISTORY.md)
- [Early implementation plan](https://github.com/OzoneH3/flowgate/blob/f17f443b8f221e2bf6fabbd756f4af4329096875/docs/PLAN.md)
- [Early NetLimiter parity matrix](https://github.com/OzoneH3/flowgate/blob/f17f443b8f221e2bf6fabbd756f4af4329096875/docs/NETLIMITER-PARITY.md)
- [23 October 2026 NetLimiter audit](https://github.com/OzoneH3/flowgate/blob/f17f443b8f221e2bf6fabbd756f4af4329096875/docs/NETLIMITER-AUDIT-2026-10-23.md)

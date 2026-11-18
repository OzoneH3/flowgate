# Integration map

[STATUS.md](STATUS.md) maintains current scope and the last recorded deployment.
Source, installed daemon and GUI are independently versioned artifacts; compare
actual build metadata before interpreting a feature or acceptance result.
[Historical integration results](https://github.com/OzoneH3/flowgate/blob/f17f443b8f221e2bf6fabbd756f4af4329096875/docs/INTEGRATION-HISTORY.md) record earlier release pairings and test runs.

- API and authorization: [API.md](API.md), [RULES.md](RULES.md).
- Attribution and runtime bounds: [ATTRIBUTION.md](ATTRIBUTION.md), [WINE.md](WINE.md).
- Observation/accounting: [TRAFFIC.md](TRAFFIC.md), [OBSERVED-USAGE.md](OBSERVED-USAGE.md).
- Continuous protection/recovery: [CONTINUOUS.md](CONTINUOUS.md).
- Build/update/rollback: [DAILY-DEPLOYMENT.md](DAILY-DEPLOYMENT.md).
- Prerequisite diagnostics: [DIAGNOSTICS.md](DIAGNOSTICS.md).

A release manifest establishes source/hash consistency. Store/engine tests,
actual receiver delivery, synthetic UI journeys and installed-host acceptance
are separate evidence scopes; report exactly which were exercised. Editing this
checkout does not deploy a binary or alter the installed daemon's protection.

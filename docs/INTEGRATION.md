# Integration map

[STATUS.md](STATUS.md) maintains current scope and the last recorded deployment.
Source, installed daemon and GUI are independently versioned artifacts; compare
actual build metadata before interpreting a feature or acceptance result.
Historical release pairings and integration journeys are retained in
[INTEGRATION-HISTORY.md](INTEGRATION-HISTORY.md).

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

# FlowGate development rules

## Fix shared mechanisms, not individual applications

- Fix attribution, permission handling, process grouping, launcher integration and
  artwork lookup in their shared layers. A reported application is a reproducer,
  not a special case to add to production code.
- Do not hard-code game/application names, executable names, launcher paths,
  Wine prefixes, server addresses or ports to make a reported application work.
  Do not add application-specific bypasses, automatic Allows or inherited
  parent/launcher permissions.
- Keep permissions independent for each verified executable, user and Wine
  prefix. Preserve incoming/outgoing separation and existing explicit scopes.
- Use verifiable runtime, process-generation, socket and executable evidence.
  A display name, command line, parent process or launch context alone must not
  become permission authority. Missing or ambiguous evidence must stay explicit.
- Implement runtime-specific support by documented, validated capabilities or
  supported runtime versions/builds, not by the identity of the game using them.
- Regression tests for Wine/Proton attribution changes must cover at least two
  distinct synthetic Windows applications and separate prefixes, including
  negative checks that permissions do not transfer between them. Keep actual
  application names/paths in local evidence or reproduction fixtures only.
- Report the scope actually tested. A receiver test with Remember enabled does
  not prove ordinary Allow avoids repeat prompts; API acknowledgement does not
  prove delivery; model tests do not prove native UI behavior.

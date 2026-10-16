# Implementation plan

Authoritative plan for milestone 1. Branding is a CLI build variable; core concepts do not depend on desktop or init system.

1. Inspect capabilities and bounded upstream reuse assessment.
2. Implement structured process/socket snapshots, native identities and conservative Wine evidence.
3. Implement filters/rules, bounded pending lifecycle, authenticated v1 Unix API and CLI.
4. Connect NFQUEUE in a disposable namespace; deny unknown/ambiguous ownership, recheck delayed decisions.
5. Verify receiver behavior for native and available Wine fixtures; document exact limitations and reproducible commands.

Future: desktop prompts/pending queue; application/process/connection tree and quick controls; durable SQLite rules/history and editor; launcher adapters and games; distribution/service packaging; charts; bandwidth controls.

## Current increment: transparent Wine observation experiment

1. Inspect Wine 11.19 handle census and installed `lwp`/dwproton setup.
2. Probe existing TCP owner-table snapshots before considering tracing; identify failure and completeness boundaries using actual fixtures.
3. Test ordinary listeners, UDP and dormant inheritance in an isolated namespace with workspace-only prefixes; add a bounded executable experiment, not a policy exception.
4. Integrate only if the evidence supports exclusive ownership and stale-decision invalidation; otherwise document the exact boundary and smallest next experiment.
5. Preserve existing policy/retention code and evidence; update WINE, STATUS and HANDOFF with reproducible results.

Outcome: steps 1–5 complete. Result B: explicitly configured public-runtime census
passes ordinary IPv4 TCP and UDP receiver tests on Wine 11.19 and dwproton-11.0-4,
including dormant inheritance and stale/lost observation checks. See STATUS.md
for evidence and HANDOFF.md for the bounded remaining lifecycle work.

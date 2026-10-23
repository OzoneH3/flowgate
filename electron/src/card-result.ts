import type { Attempt } from './protocol';

// Result text a card shows for its own submission. A decision result records its
// phase and the daemon generation it was submitted under (stored only if that
// generation was still current when the reply arrived).
export interface CardResult {
  text: string;
  detail: string;
  phase?: Attempt['phase'];
  generation?: string;
}

/** Whether the card's locally recorded result is still the one to show.
 *  It yields to the authoritative attempt when that is unknown (an unresolved
 *  outcome is never hidden), when the local result was itself unknown and the
 *  same generation's attempt was since confirmed from its receipt, and it is
 *  never shown for another daemon generation. */
export function showsLocalResult(local: CardResult | undefined, attempt: Attempt | undefined, generation: string): boolean {
  if (!local) return false;
  if (local.generation !== undefined && local.generation !== generation) return false;
  if (attempt?.phase === 'unknown') return false;
  if (local.phase === 'unknown' && attempt?.phase === 'acknowledged') return false;
  return true;
}

/** Records a decision/receipt result for its card only if the daemon generation
 *  it was submitted under is still current when the reply arrives. A reply from
 *  before a restart is never stored (or relabelled) as current. */
export function recordDecisionResult(
  results: Map<string, CardResult>,
  id: string,
  submittedGeneration: string,
  currentGeneration: string,
  result: { text: string; detail: string; phase: CardResult['phase'] },
): boolean {
  if (submittedGeneration !== currentGeneration) return false;
  results.set(id, { ...result, generation: submittedGeneration });
  return true;
}

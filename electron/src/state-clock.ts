import type { ClientState } from './protocol';
// Clock messages carry no authority or inventory. Reject late ticks from another daemon.
export function advanceClock(
  state: ClientState | undefined,
  clock: { generation: string; serverNow: number; publication?: number },
): ClientState | undefined {
  if (
    !state ||
    (clock.publication !== undefined &&
      state.publication !== undefined &&
      clock.publication < state.publication) ||
    state.control.generation !== clock.generation ||
    !Number.isFinite(clock.serverNow) ||
    clock.serverNow < (state.control.serverNow ?? -Infinity)
  )
    return state;
  const now = clock.serverNow;
  return {
    ...state,
    publication: clock.publication ?? state.publication,
    control: {
      ...state.control,
      serverNow: now,
      policy:
        state.control.policy?.snapshot.valid_until &&
        Date.parse(state.control.policy.snapshot.valid_until) <= now
          ? undefined
          : state.control.policy,
      events: state.control.events.map((e) => ({
        ...e,
        remainingMs: Math.max(0, Date.parse(e.deadline) - now),
      })),
    },
  };
}

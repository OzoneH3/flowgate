package policy

// Precedence of matching rules, shared by the evaluator and every explanation
// (editor preview, policy explanation, documentation) so they cannot drift.

// PrecedenceSentence states the evaluator's order (see Precedes).
const PrecedenceSentence = NetworkEndpointPrecedence + " Among matching active rules (the newest saved setting of each program scope): higher target weight wins (process 4 › application 3 › zone 2 › all programs 1); then higher priority; then a Local or Internet rule over an All networks rule; then Deny › Allow › Ask; then a user rule over a preset; then the smaller rule ID."

// LoopbackSentence explains the same-host exception (DefaultLoopback).
const LoopbackSentence = "Traffic to this machine itself (loopback or this exact host address) is allowed by default; only rules naming a loopback address or this exact host address apply to it, so a rule for any address does not."

// Precedes reports whether rule a is applied before rule b when both match.
func Precedes(a, b Rule) bool {
	if wa, wb := a.Weight(), b.Weight(); wa != wb {
		return wa > wb
	}
	if a.Priority != b.Priority {
		return a.Priority > b.Priority
	}
	if az, bz := a.Filter.NetworkZone != "", b.Filter.NetworkZone != ""; az != bz {
		return az
	}
	if ra, rb := actionRank(a.Action), actionRank(b.Action); ra != rb {
		return ra < rb
	}
	if (a.Preset == nil) != (b.Preset == nil) {
		return a.Preset == nil
	}
	return a.ID < b.ID
}

// DecidingFactor names the criterion that orders the two rules (winner first
// per Precedes). No periods or parentheses: it is embedded in overlap lists.
func DecidingFactor(a, b Rule) string {
	switch {
	case a.Weight() != b.Weight():
		return "higher target weight"
	case a.Priority != b.Priority:
		return "higher priority"
	case (a.Filter.NetworkZone != "") != (b.Filter.NetworkZone != ""):
		return "Local or Internet rule overrides All networks rule at equal priority"
	case actionRank(a.Action) != actionRank(b.Action):
		return "Deny › Allow › Ask at equal weight and priority"
	case (a.Preset == nil) != (b.Preset == nil):
		return "user rule over preset"
	default:
		return "smaller rule ID"
	}
}

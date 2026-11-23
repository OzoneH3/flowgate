package daemon

import (
	"encoding/json"
	"flowgate/internal/identity"
	"flowgate/internal/policy"
)

// follows_updates is read-only presentation metadata. It is never persisted
// with a rule and a client-supplied value cannot change matching authority.
type projectedRule struct {
	policy.Rule
	FollowsUpdates        bool `json:"follows_updates"`
	NativeShapingIdentity bool `json:"native_shaping_identity,omitempty"`
}

// A process rule can identify the application for shaping configuration. Its
// firewall permission stays bound to the original process.
func nativeShapingIdentity(rule policy.Rule) bool {
	f := rule.Filter
	return rule.Preset == nil && !rule.NetworkEndpoint && !f.AllPrograms && !f.AllUIDs &&
		f.Revision != "" && identity.MatchesSavedNativeKey(f.UID, f.Application, rule.Executable)
}

func (r Response) MarshalJSON() ([]byte, error) {
	type plain Response
	project := func(rule policy.Rule) projectedRule {
		return projectedRule{rule, rule.FollowsUpdates(), nativeShapingIdentity(rule)}
	}
	var rules []projectedRule
	for _, rule := range r.Rules {
		rules = append(rules, project(rule))
	}
	var saved *projectedRule
	if r.SavedRule != nil {
		v := project(*r.SavedRule)
		saved = &v
	}
	return json.Marshal(struct {
		plain
		Rules     []projectedRule `json:"rules,omitempty"`
		SavedRule *projectedRule  `json:"saved_rule,omitempty"`
	}{plain(r), rules, saved})
}

package policy

import (
	"flowgate/internal/identity"
	"fmt"
	"sort"
	"time"
)

type Filter struct {
	Application string `json:"application"`
	Revision    string `json:"revision"`
	Direction   string `json:"direction"`
	Protocol    string `json:"protocol"`
	Remote      string `json:"remote,omitempty"`
	UID         uint32 `json:"uid"`
}
type Rule struct {
	ID       string    `json:"id"`
	Priority int       `json:"priority"`
	Filter   Filter    `json:"filter"`
	Action   string    `json:"action"`
	Expires  time.Time `json:"expires"`
}

func (r Rule) Validate() error {
	if r.ID == "" || r.Filter.Application == "" || r.Filter.Revision == "" {
		return fmt.Errorf("rule needs ID, application and revision")
	}
	if r.Action != "allow" && r.Action != "block" && r.Action != "ask" {
		return fmt.Errorf("invalid action")
	}
	if r.Filter.Direction != "incoming" && r.Filter.Direction != "outgoing" {
		return fmt.Errorf("invalid direction")
	}
	if r.Filter.Protocol != "tcp" && r.Filter.Protocol != "udp" {
		return fmt.Errorf("invalid protocol")
	}
	return nil
}
func Evaluate(rules []Rule, f identity.Flow, a identity.Attribution, now time.Time) (string, string, []string) {
	if a.Application == nil || len(a.Owners) != 1 {
		return "block", "unsafe-attribution", nil
	}
	var matches []Rule
	for _, r := range rules {
		x := r.Filter
		if !r.Expires.IsZero() && !now.Before(r.Expires) {
			continue
		}
		if x.Application != a.Application.Key || x.Revision != a.Application.Revision || x.UID != a.Owners[0].UID || x.Direction != f.Direction || x.Protocol != f.Protocol {
			continue
		}
		if x.Remote != "" && x.Remote != f.Remote.String() {
			continue
		}
		matches = append(matches, r)
	}
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].Priority != matches[j].Priority {
			return matches[i].Priority > matches[j].Priority
		}
		return matches[i].ID < matches[j].ID
	})
	var ids []string
	for _, r := range matches {
		ids = append(ids, r.ID)
	}
	if len(matches) == 0 {
		return "ask", "default-ask", ids
	}
	return matches[0].Action, matches[0].ID, ids
}

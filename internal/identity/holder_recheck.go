package identity

import (
	"encoding/json"
	"errors"
	"slices"
)

// HolderRecheck scopes stale evidence. Err means the census as a whole cannot
// exclude hidden holders. Groups names stale groups; Appeared names sockets
// newly held by a rescanned group. None of these may authorize a Resolve result.
type HolderRecheck struct {
	Err      error
	Groups   map[int]string
	Appeared []string
}

// A transient exit before any wanted descriptor was observed can be handled by
// one fresh full scan of that group. The retry shares the original deadline and
// all task/descriptor budgets. It never splices old and new table observations.
// Once a wanted descriptor has been observed, any change refuses that attempt.
func (p holderProc) scanStableGroup(tgid int, wanted map[string]bool, lim holderLimits, total, fdCount *int) (*holderGroup, string) {
	start, zombie, err := p.stat(tgid, tgid)
	if holderGone(err) {
		return nil, ""
	}
	if err != nil {
		return nil, "group_unreadable"
	}
	var g *holderGroup
	var code string
	for attempt := 0; attempt < 2; attempt++ {
		if p.late() {
			return g, "time_limit"
		}
		g, code = p.scanGroup(tgid, wanted, lim, total, fdCount)
		// A later group exit cannot erase an already observed visibility error.
		if code != "" && !holderTopologyChange(code) {
			return g, code
		}
		end, z, err := p.stat(tgid, tgid)
		if err != nil && !holderGone(err) {
			return g, "group_unreadable"
		}
		if holderGone(err) && (g == nil || len(g.paths) == 0) {
			return nil, ""
		}
		if err != nil || end != start || z != zombie {
			return g, "group_changed"
		}
		if code == "" && g != nil {
			if err := p.recheckGroup(tgid, g); err != nil {
				code = err.Error()
			}
		}
		if code == "" {
			return g, ""
		}
		if code != "membership_changed" && code != "table_changed" {
			return g, code
		}
		if g != nil && len(g.paths) > 0 {
			return g, code
		}
	}
	return g, code
}

func holderSet(g *holderGroup, tgid int) []string {
	var out []string
	for _, h := range g.holders(tgid) {
		// FD numbers and representatives can differ between equivalent scans; the
		// entire member generation set, sharing proof and socket must be identical.
		b, _ := json.Marshal(struct {
			Socket  string
			Proven  bool
			Members []HolderMember
		}{h.Socket, h.Proven, h.Members})
		out = append(out, string(b))
	}
	slices.Sort(out)
	return out
}

// RecheckDetail preserves unrelated groups' display metadata without accepting
// a partial holder set. Changed topology is fully rescanned and bookended, then
// its complete wanted-holder set must equal the inspected set. A new member of
// a holding table therefore refuses, even if its executable might be the same.
func (c HolderCensus) RecheckDetail() HolderRecheck {
	d := HolderRecheck{Groups: map[int]string{}}
	if !c.Complete {
		d.Err = errors.New("census_incomplete")
	}
	p := c.src
	global := func(code string) {
		// A directly observed global failure must not be hidden by the initial
		// census marker, which may describe only a retryable topology change.
		if d.Err == nil || d.Err.Error() == "census_incomplete" {
			d.Err = errors.New(code)
		}
	}
	appeared := func(g *holderGroup) {
		if g == nil {
			return
		}
		for _, socket := range g.paths {
			if !slices.Contains(d.Appeared, socket) {
				d.Appeared = append(d.Appeared, socket)
			}
		}
	}
	if p.late() {
		global("time_limit")
		return d
	}
	budget := c.budget
	if budget == nil {
		budget = &holderBudget{deadline: c.deadline}
	}
	for tgid, old := range c.groups {
		if len(old.paths) == 0 {
			continue
		}
		if p.late() {
			global("time_limit")
			return d
		}
		err := p.recheckGroup(tgid, old)
		if err == nil {
			continue
		}
		cause := err.Error()
		code := cause
		if code != "membership_changed" && code != "table_changed" {
			d.Groups[tgid] = code
			continue
		}
		// A full rescan proves no table was omitted. Its generation must still be
		// the original group's, and only non-holder topology is allowed to differ.
		fresh, code := p.scanStableGroup(tgid, c.wanted, c.lim, &budget.tasks, &budget.fds)
		if code == "stop" {
			global("recheck_budget")
			return d
		}
		if code == "time_limit" {
			global(code)
			return d
		}
		if code != "" {
			d.Groups[tgid] = code
			continue
		}
		if fresh == nil || fresh.start != old.start || fresh.leaderExited != old.leaderExited {
			d.Groups[tgid] = "group_changed"
			continue
		}
		if !slices.Equal(holderSet(old, tgid), holderSet(fresh, tgid)) {
			d.Groups[tgid] = cause
			// This includes newly observed tables and members, and cannot be merged
			// into the earlier identity inspection.
			appeared(fresh)
		}
	}
	groups, err := p.groups()
	if err != nil {
		global("group_list_unreadable")
		return d
	}
	if len(groups) > c.lim.Groups {
		global("group_limit")
		return d
	}
	for _, tgid := range groups {
		if p.late() {
			global("time_limit")
			return d
		}
		old, known := c.groups[tgid]
		if known && len(old.paths) > 0 {
			continue
		}
		if known {
			err := p.sameTopology(tgid, old)
			if err == nil {
				continue
			}
			if !holderTopologyChange(err.Error()) {
				global(err.Error())
				continue
			}
		}
		fresh, code := p.scanStableGroup(tgid, c.wanted, c.lim, &budget.tasks, &budget.fds)
		if code == "stop" {
			global("recheck_budget")
			return d
		}
		if code != "" {
			global(code)
			continue
		}
		appeared(fresh)
	}
	if p.late() {
		global("time_limit")
	}
	slices.Sort(d.Appeared)
	return d
}

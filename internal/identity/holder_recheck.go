package identity

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// HolderRecheck scopes stale evidence. Err means the census as a whole cannot
// exclude hidden holders. Groups names stale groups; Appeared names sockets
// newly held by a rescanned group. None of these may authorize a Resolve result.
type HolderRecheck struct {
	Err      error
	Groups   map[int]string
	Appeared []string
	// Reconcilable lists the fresh holders of groups whose only change since the
	// census is same-table membership of the same live, kcmp-proven thread group
	// (threads joined or left an already inspected table; same class set, same
	// representatives, same sockets). Nothing here is verified: every member must
	// be re-read, runtime classification re-run and verify called before any of
	// it is used. Recheck() still reports the original cause for callers that do
	// not perform that verification.
	Reconcilable map[int][]Holder
	verify       map[int]func() error // final topology/descriptor check of the fresh group
}

// holderRep is the representative task whose table was read for this holder.
func holderRep(h Holder) (int, bool) {
	var tgid, rep, fd int
	if _, err := fmt.Sscanf(h.FDPath, "/proc/%d/task/%d/fd/%d", &tgid, &rep, &fd); err != nil || tgid != h.TGID {
		return 0, false
	}
	return rep, true
}

// classSet identifies a group's holding tables by representative and socket,
// ignoring which tasks currently use each table.
func classSet(g *holderGroup, tgid int) []string {
	var out []string
	for _, h := range g.holders(tgid) {
		rep, ok := holderRep(h)
		if !ok {
			return nil
		}
		out = append(out, fmt.Sprintf("%d %s", rep, h.Socket))
	}
	slices.Sort(out)
	return out
}

// reconcilableChurn is true only when a live, kcmp-proven group kept the exact
// same holding tables (by representative) for the exact same sockets and merely
// gained or lost tasks in those tables. New tables, lost sockets, exited or
// unproven leaders and unproven groups are never reconcilable.
func reconcilableChurn(old, fresh *holderGroup, tgid int) bool {
	if old == nil || fresh == nil || !old.proven || !fresh.proven || old.leaderExited || fresh.leaderExited || old.start != fresh.start {
		return false
	}
	o, f := classSet(old, tgid), classSet(fresh, tgid)
	return len(o) > 0 && slices.Equal(o, f)
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
// its complete wanted-holder set must equal the inspected set. The one
// exception is same-table membership churn of a live, proven group with an
// unchanged class set: that fresh set is reported as Reconcilable for complete
// re-verification by identity inspection, never accepted here. Any other
// difference (new or lost tables, lost sockets, exited leader, unproven group)
// refuses the group.
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
			if cause == "membership_changed" && reconcilableChurn(old, fresh, tgid) {
				// Same tables, same sockets, different task set: offered for full
				// re-verification by identity inspection, never accepted here.
				if d.Reconcilable == nil {
					d.Reconcilable = map[int][]Holder{}
					d.verify = map[int]func() error{}
				}
				holders := fresh.holders(tgid)
				slices.SortFunc(holders, func(a, b Holder) int {
					if a.Members[0].TID != b.Members[0].TID {
						return a.Members[0].TID - b.Members[0].TID
					}
					return strings.Compare(a.Socket, b.Socket)
				})
				d.Reconcilable[tgid] = holders
				g := fresh
				d.verify[tgid] = func() error { return p.recheckGroup(tgid, g) }
				continue
			}
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

package identity

import (
	"errors"
	"slices"
	"testing"
	"time"
)

func TestHolderRetryNewMemberGetsFreshIdentityChecks(t *testing.T) {
	first := newHolderIdentityFixture([]int{100})
	first.check = func() HolderRecheck {
		return HolderRecheck{Groups: map[int]string{100: "membership_changed"}, Appeared: []string{"socket:[1]"}}
	}
	for _, badCredentials := range []bool{false, true} {
		t.Run(map[bool]string{false: "sameidentity", true: "changedcredentials"}[badCredentials], func(t *testing.T) {
			second := newHolderIdentityFixture([]int{100, 101})
			reads := 0
			inspections := 0
			rechecks := 0
			if badCredentials {
				v := second.facts[101]
				v.Credentials = "other-credentials"
				second.facts[101] = v
			}
			second.read = func(_ Holder, m HolderMember) (holderTaskFacts, error) {
				if m.TID == 101 {
					reads++
				}
				return second.facts[m.TID], nil
			}
			second.inspect = func(tid int) (Process, error) { inspections++; return second.processes[tid], nil }
			second.check = func() HolderRecheck { rechecks++; return HolderRecheck{} }
			attempts, refreshes := 0, 0
			now := time.Unix(1, 0)
			_, out := retryHolderIdentities(func() time.Time { return now }, defaultHolderLimits, func() { refreshes++ }, func(b *holderBudget) (HolderCensus, holderIdentities) {
				attempts++
				if attempts == 1 {
					return first.c, first.run()
				}
				return second.c, second.run()
			})
			if attempts != 2 || refreshes != 1 {
				t.Fatalf("attempts=%d refreshes=%d", attempts, refreshes)
			}
			if badCredentials {
				if out.Complete || len(out.Owners["socket:[1]"]) != 0 || inspections != 0 {
					t.Fatalf("changed credentials accepted: %+v inspections=%d", out, inspections)
				}
			} else {
				if !out.Complete || len(out.Owners["socket:[1]"]) != 1 || reads != 2 || inspections != 1 || rechecks != 1 {
					t.Fatalf("new member not fully checked: %+v reads=%d inspect=%d recheck=%d", out, reads, inspections, rechecks)
				}
			}
		})
	}
}

func TestHolderRetryNeverRetriesIdentityOrVisibilityFailures(t *testing.T) {
	for _, mode := range []string{"global", "credentials", "runtime", "initial-io", "unproven"} {
		t.Run(mode, func(t *testing.T) {
			f := newHolderIdentityFixture([]int{100, 101})
			switch mode {
			case "global":
				f.check = func() HolderRecheck { return HolderRecheck{Err: errors.New("group_list_unreadable")} }
			case "credentials":
				v := f.facts[101]
				v.Credentials = "changed"
				f.facts[101] = v
			case "runtime":
				f = newHolderIdentityFixture([]int{101})
				p := f.processes[101]
				p.Application.Hosted = &Hosted{State: "unverified"}
				f.processes[101] = p
			case "initial-io":
				f.c.Complete = false
				f.c.Issues = []string{"fd_table_unreadable"}
				f.check = func() HolderRecheck {
					return HolderRecheck{Err: errors.New("census_incomplete"), Groups: map[int]string{100: "membership_changed"}}
				}
			case "unproven":
				f.c.Holders[0].Proven = false
			}
			attempts := 0
			_, out := retryHolderIdentities(func() time.Time { return time.Unix(1, 0) }, defaultHolderLimits, func() { t.Fatal("unexpected metadata refresh") }, func(*holderBudget) (HolderCensus, holderIdentities) { attempts++; return f.c, f.run() })
			if attempts != 1 || out.Complete {
				t.Fatalf("failure retried/accepted: %d %+v", attempts, out)
			}
		})
	}
}

func TestHolderRetryCapsAttemptsAndSharesDeadlineAndCounters(t *testing.T) {
	f := newHolderIdentityFixture([]int{100})
	f.check = func() HolderRecheck { return HolderRecheck{Groups: map[int]string{100: "membership_changed"}} }
	now := time.Unix(1, 0)
	start := now
	attempts, refreshes := 0, 0
	var shared *holderBudget
	_, out := retryHolderIdentities(func() time.Time { return now }, defaultHolderLimits, func() { refreshes++ }, func(b *holderBudget) (HolderCensus, holderIdentities) {
		attempts++
		if shared != nil && shared != b {
			t.Fatal("budget reset")
		}
		shared = b
		if !b.deadline.Equal(start.Add(defaultHolderLimits.Time)) {
			t.Fatal("deadline reset")
		}
		if b.tasks != attempts-1 || b.fds != (attempts-1)*2 {
			t.Fatal("scan counters reset")
		}
		b.tasks++
		b.fds += 2
		now = now.Add(100 * time.Millisecond)
		return f.c, f.run()
	})
	if attempts != 2 || refreshes != 1 || out.Complete {
		t.Fatalf("uncapped retry: %d %d %+v", attempts, refreshes, out)
	}
}

func TestHolderRetryOriginalTimeAndScanLimits(t *testing.T) {
	for _, mode := range []string{"time", "refresh-time", "tasks", "fds", "late-success"} {
		t.Run(mode, func(t *testing.T) {
			f := newHolderIdentityFixture([]int{100})
			f.check = func() HolderRecheck { return HolderRecheck{Groups: map[int]string{100: "membership_changed"}} }
			now := time.Unix(1, 0)
			attempts := 0
			_, out := retryHolderIdentities(func() time.Time { return now }, defaultHolderLimits, func() {
				if mode == "refresh-time" {
					now = now.Add(time.Hour)
				}
			}, func(b *holderBudget) (HolderCensus, holderIdentities) {
				attempts++
				switch mode {
				case "time", "late-success":
					now = now.Add(time.Hour)
				case "tasks":
					b.tasks = defaultHolderLimits.Tasks
				case "fds":
					b.fds = defaultHolderLimits.FDs
				}
				if mode == "late-success" {
					f.check = func() HolderRecheck { return HolderRecheck{} }
				}
				return f.c, f.run()
			})
			if attempts != 1 || out.Complete {
				t.Fatalf("limit ignored: %d %+v", attempts, out)
			}
			if (mode == "time" || mode == "refresh-time" || mode == "late-success") && !slices.Contains(out.Issues, "time_limit") {
				t.Fatalf("deadline not explicit: %+v", out)
			}
		})
	}
}

func TestHolderRetryScanBudgetIncludesCensusAndRescans(t *testing.T) {
	f := holderFixture()
	p := f.proc()
	lim := defaultHolderLimits
	b := &holderBudget{deadline: f.now.Add(lim.Time)}
	c := p.censusBudget(censusWanted, lim, b)
	if !c.Complete {
		t.Fatal(c.Issues)
	}
	tasks, fds := b.tasks, b.fds
	f.groups[60][61] = &censusTask{"6001", false, 8}
	if d := c.RecheckDetail(); d.Err != nil || len(d.Groups) != 0 || len(d.Appeared) != 0 {
		t.Fatalf("unrelated rescan: %+v", d)
	}
	if b.tasks <= tasks || b.fds <= fds {
		t.Fatal("recheck rescan not charged")
	}
	lim.Tasks = b.tasks + 1
	c = p.censusBudget(censusWanted, lim, b)
	if c.Complete || !slices.Contains(c.Issues, "task_limit") {
		t.Fatalf("second census reset original budget: %+v", c.Issues)
	}
}

func TestHolderRetryInitialTopologyOnlyCanBeReobserved(t *testing.T) {
	first := newHolderIdentityFixture([]int{100})
	first.c.Complete = false
	first.c.Issues = []string{"membership_changed"}
	first.check = func() HolderRecheck { return HolderRecheck{Err: errors.New("census_incomplete")} }
	second := newHolderIdentityFixture([]int{100})
	attempts := 0
	_, out := retryHolderIdentities(func() time.Time { return time.Unix(1, 0) }, defaultHolderLimits, nil, func(*holderBudget) (HolderCensus, holderIdentities) {
		attempts++
		if attempts == 1 {
			return first.c, first.run()
		}
		return second.c, second.run()
	})
	if attempts != 2 || !out.Complete {
		t.Fatalf("topology omission not fully reobserved: %d %+v", attempts, out)
	}
}

func TestHolderRetryInitialTopologyDoesNotMaskGlobalFailure(t *testing.T) {
	for _, mode := range []string{"group_list_unreadable", "time_limit", "group_limit"} {
		t.Run(mode, func(t *testing.T) {
			f := holderFixture()
			c := f.proc().census(censusWanted, defaultHolderLimits)
			if !c.Complete {
				t.Fatal(c.Issues)
			}
			c.Complete = false
			c.Issues = []string{"membership_changed"}
			switch mode {
			case "group_list_unreadable":
				c.src.groups = func() ([]int, error) { return nil, errors.New("unreadable") }
			case "time_limit":
				f.now = f.now.Add(time.Hour)
			case "group_limit":
				c.lim.Groups = 0
			}
			d := c.RecheckDetail()
			if d.Err == nil || d.Err.Error() != mode || retryableHolderTopology(c, d) {
				t.Fatalf("global failure masked: %+v", d)
			}
			attempts := 0
			_, out := retryHolderIdentities(func() time.Time { return time.Unix(1, 0) }, defaultHolderLimits, nil, func(*holderBudget) (HolderCensus, holderIdentities) {
				attempts++
				return c, holderIdentities{Complete: false, retryTopology: retryableHolderTopology(c, d)}
			})
			if attempts != 1 || out.Complete {
				t.Fatalf("mixed global failure retried: attempts=%d %+v", attempts, out)
			}
		})
	}
}

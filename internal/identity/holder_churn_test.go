package identity

import (
	"errors"
	"fmt"
	"slices"
	"syscall"
	"testing"
	"time"
)

// Pure in-memory model of census → inspection → recheck with same-table
// membership churn between the census and the recheck. No /proc, sockets or
// processes: censusProc models the kernel view, the facts/inspect/descriptor
// closures model the identity reads. Every trace records the exact read order.
type churnModel struct {
	f           *censusProc
	exe         map[int]string // per thread group; default /native
	creds       map[int]string // per task override
	factsErr    map[int]error
	trace       []string
	onFacts     func(m *churnModel, tid int) // after each facts read
	inspectHook func(m *churnModel, tid int, p *Process)
	inspects    int
}

const churnS1, churnS2, churnS3, churnS4, churnS5 = "socket:[201]", "socket:[202]", "socket:[203]", "socket:[204]", "socket:[205]"

var churnWanted = map[string]bool{churnS1: true, churnS2: true, churnS3: true, churnS4: true, churnS5: true}

// Group 10: live leader 10 and thread 11 share table 1 holding S1 and S4; thread
// 12 holds S2 in its private table 2 (worker-only native holder). Group 20:
// exited leader, workers 21/22 share table 3 holding S3. Group 30: live leader 30
// and thread 31 share table 5 holding S5 (a second reconcilable group). Group
// 60: unrelated. Group 70: a different executable, holding nothing yet.
func newChurnModel() *churnModel {
	return &churnModel{
		f: &censusProc{
			groups: map[int]map[int]*censusTask{
				10: {10: {"1000", false, 1}, 11: {"1001", false, 1}, 12: {"1002", false, 2}},
				20: {20: {"2000", true, 0}, 21: {"2001", false, 3}, 22: {"2002", false, 3}},
				30: {30: {"3000", false, 5}, 31: {"3001", false, 5}},
				60: {60: {"6000", false, 8}},
				70: {70: {"7000", false, 9}},
			},
			tables: map[int]map[int]string{
				1: {3: churnS1, 4: "pipe:[9]", 6: churnS4}, 2: {5: churnS2}, 3: {6: churnS3}, 5: {3: churnS5}, 8: {3: "socket:[999]"}, 9: {},
			},
			statErr: map[int]error{}, fdErr: map[int]error{}, hidden: map[int]bool{}, now: time.Unix(0, 0),
		},
		exe: map[int]string{70: "/other"}, creds: map[int]string{}, factsErr: map[int]error{},
	}
}

func (m *churnModel) groupOf(tid int) (int, *censusTask) {
	for tgid, g := range m.f.groups {
		if t := g[tid]; t != nil {
			return tgid, t
		}
	}
	return 0, nil
}

func (m *churnModel) executable(tgid int) string {
	if e, ok := m.exe[tgid]; ok {
		return e
	}
	return "/native"
}

func (m *churnModel) facts(h Holder, mem HolderMember) (holderTaskFacts, error) {
	m.trace = append(m.trace, fmt.Sprintf("facts:%d", mem.TID))
	defer func() {
		if m.onFacts != nil {
			m.onFacts(m, mem.TID)
		}
	}()
	if err := m.factsErr[mem.TID]; err != nil {
		return holderTaskFacts{}, err
	}
	tgid, t := m.groupOf(mem.TID)
	if t == nil || tgid != h.TGID || t.start != mem.Start {
		return holderTaskFacts{}, errors.New("holder generation changed")
	}
	creds := "1:1:1:1/1:1:1:1/groups:1"
	if c, ok := m.creds[mem.TID]; ok {
		creds = c
	}
	return holderTaskFacts{Group: tgid, Start: t.start, Exe: m.executable(tgid), Revision: "r1", NetNS: "net", MountNS: "mnt", PIDNS: "pid", Credentials: creds, UID: 1}, nil
}

func (m *churnModel) inspect(tid int) (Process, error) {
	m.inspects++
	m.trace = append(m.trace, fmt.Sprintf("inspect:%d", tid))
	tgid, t := m.groupOf(tid)
	if t == nil {
		return Process{}, errors.New("gone")
	}
	exe := m.executable(tgid)
	p := Process{PID: tid, ThreadGroup: tgid, Start: t.start, UID: 1, BootID: "boot", Executable: exe, ExecutableRevision: "r1", NetNS: "net", MountNS: "mnt", PIDNS: "pid",
		Application: Application{Kind: "native", Key: "app" + exe, Revision: "r1", Executable: exe}}
	if m.inspectHook != nil {
		m.inspectHook(m, tid, &p)
	}
	return p, nil
}

// run performs one census, inspects every member, then applies mutate (the
// churn that happens after inspection, as the recheck starts) and rechecks
// exactly as resolveHolderIdentities does.
func (m *churnModel) run(mutate func(), lim holderLimits) (HolderCensus, holderIdentities) {
	p := m.f.proc()
	c := p.censusBudget(churnWanted, lim, &holderBudget{deadline: p.now().Add(lim.Time)})
	descriptor := func(path, socket string) bool {
		m.trace = append(m.trace, "descriptor")
		target, err := p.readlink(path)
		return err == nil && target == socket
	}
	recheck := func() HolderRecheck {
		m.trace = append(m.trace, "recheck")
		if mutate != nil {
			mutate()
		}
		return c.RecheckDetail()
	}
	return c, inspectHolderIdentitiesWith(c, m.inspect, m.facts, descriptor, recheck)
}

func churnOwnerPIDs(out holderIdentities, socket string) []int {
	var pids []int
	for _, p := range out.Owners[socket] {
		pids = append(pids, p.PID)
	}
	return pids
}

func addThread(m *churnModel, tgid, tid int, start string, table int) {
	m.f.groups[tgid][tid] = &censusTask{start, false, table}
}

func TestHolderChurnJoinSameTableReconciles(t *testing.T) {
	m := newChurnModel()
	c, out := m.run(func() { addThread(m, 10, 13, "1003", 1) }, defaultHolderLimits)
	if !c.Complete {
		t.Fatal(c.Issues)
	}
	if !out.Complete || len(out.Issues) != 0 || out.Reconciled != 2 || len(out.SocketIssues) != 0 {
		t.Fatalf("%+v", out)
	}
	if pids := churnOwnerPIDs(out, churnS1); !slices.Equal(pids, []int{10}) {
		t.Fatalf("S1 owners %v", pids)
	}
	if pids := churnOwnerPIDs(out, churnS2); !slices.Equal(pids, []int{12}) {
		t.Fatalf("S2 owners %v", pids)
	}
	if out.Owners[churnS1][0].HolderWitness != "" {
		t.Fatal("live leader class gained a witness")
	}
	if pids := churnOwnerPIDs(out, churnS4); !slices.Equal(pids, []int{10}) {
		t.Fatalf("S4 (same table) owners %v", pids)
	}
	// Exact re-verification order after the recheck, once per table class of the
	// group: every current member read, the inspected task re-classified, one
	// descriptor read per socket of the class, every member read again. The
	// unchanged S2 class is re-verified too (group-atomic), identity once.
	want := []string{"recheck",
		"facts:10", "facts:11", "facts:13", "inspect:10", "descriptor", "descriptor", "facts:10", "facts:11", "facts:13",
		"facts:12", "inspect:12", "descriptor", "facts:12"}
	got := m.trace[len(m.trace)-len(want):]
	if !slices.Equal(got, want) {
		t.Fatalf("trace tail %v", got)
	}
	if out.Reconciled != 2 {
		t.Fatalf("both sockets of the changed table are reconciled: %d", out.Reconciled)
	}
}

// Identity or I/O failures are terminal for the whole attempt even when a
// later (or earlier) reconcilable group fails only on topology. Groups are
// reconciled in ascending TGID order: 10 is the lower group, 30 the higher.
func TestHolderChurnMixedFailuresAcrossGroupsNeverRetryIdentity(t *testing.T) {
	type failure func(m *churnModel, hooks map[int]func(*churnModel), tgid, tid int, table int)
	identity := func(m *churnModel, _ map[int]func(*churnModel), _, tid, _ int) { m.creds[tid] = "2:2:2:2/2:2:2:2/groups:2" }
	unreadable := func(m *churnModel, _ map[int]func(*churnModel), _, tid, _ int) { m.factsErr[tid] = syscall.EACCES }
	topology := func(_ *churnModel, hooks map[int]func(*churnModel), tgid, tid, table int) {
		// Another task joins while this group's fresh members are being read.
		hooks[tid] = func(m *churnModel) { addThread(m, tgid, tid+1, fmt.Sprint(tid+1), table) }
	}
	for _, tc := range []struct {
		name        string
		lower, high failure
		retry       bool
	}{
		{"identity in lower group then topology in higher", identity, topology, false},
		{"topology in lower group then identity in higher", topology, identity, false},
		{"unreadable in lower group then topology in higher", unreadable, topology, false},
		{"topology in lower group then unreadable in higher", topology, unreadable, false},
		{"topology in both", topology, topology, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newChurnModel()
			hooks := map[int]func(*churnModel){}
			m.onFacts = func(m *churnModel, tid int) {
				if h := hooks[tid]; h != nil {
					delete(hooks, tid)
					h(m)
				}
			}
			tc.lower(m, hooks, 10, 13, 1)
			tc.high(m, hooks, 30, 33, 5)
			_, out := m.run(func() {
				addThread(m, 10, 13, "1003", 1)
				addThread(m, 30, 33, "3003", 5)
			}, defaultHolderLimits)
			if out.Complete || out.Reconciled != 0 || len(out.Owners[churnS1]) != 0 || len(out.Owners[churnS5]) != 0 {
				t.Fatalf("%+v", out)
			}
			if out.retryTopology != tc.retry {
				t.Fatalf("retryTopology %v want %v (issues %v socket issues %v)", out.retryTopology, tc.retry, out.Issues, out.SocketIssues)
			}
		})
	}
}

func TestHolderChurnLeaveSameTableReconciles(t *testing.T) {
	m := newChurnModel()
	_, out := m.run(func() { delete(m.f.groups[10], 11) }, defaultHolderLimits)
	// S1 and S4 share the changed table: both holders are reconciled.
	if !out.Complete || out.Reconciled != 2 || !slices.Equal(churnOwnerPIDs(out, churnS1), []int{10}) || !slices.Equal(churnOwnerPIDs(out, churnS4), []int{10}) {
		t.Fatalf("%+v", out)
	}
}

func TestHolderChurnWorkerClassWitnessFollowsMembers(t *testing.T) {
	base := newChurnModel()
	_, before := base.run(nil, defaultHolderLimits)
	m := newChurnModel()
	_, out := m.run(func() { addThread(m, 10, 14, "1004", 2) }, defaultHolderLimits)
	if !out.Complete || out.Reconciled != 1 || !slices.Equal(churnOwnerPIDs(out, churnS2), []int{12}) {
		t.Fatalf("%+v", out)
	}
	w0, w1 := before.Owners[churnS2][0].HolderWitness, out.Owners[churnS2][0].HolderWitness
	if w0 == "" || w1 == "" || w0 == w1 {
		t.Fatalf("worker witness must be recomputed from the current member set: %q -> %q", w0, w1)
	}
	if fingerprint([]Process{before.Owners[churnS1][0]}, nil) != fingerprint([]Process{out.Owners[churnS1][0]}, nil) {
		t.Fatal("untouched class changed")
	}
}

func TestHolderChurnMixedClassesOnlyChangedClassReconciles(t *testing.T) {
	base := newChurnModel()
	_, before := base.run(nil, defaultHolderLimits)
	m := newChurnModel()
	_, out := m.run(func() { addThread(m, 10, 13, "1003", 1) }, defaultHolderLimits)
	if !out.Complete || out.Reconciled != 2 {
		t.Fatalf("%+v", out)
	}
	if before.Owners[churnS2][0].HolderWitness != out.Owners[churnS2][0].HolderWitness {
		t.Fatal("unchanged worker class must keep its witness")
	}
}

// Group-atomic: a failing class withdraws every holder of the group, including
// a class that would have passed on its own.
func TestHolderChurnSecondClassFailureInvalidatesFirst(t *testing.T) {
	m := newChurnModel()
	m.creds[14] = "2:2:2:2/2:2:2:2/groups:2"
	_, out := m.run(func() {
		addThread(m, 10, 13, "1003", 1) // S1 class: identical identity
		addThread(m, 10, 14, "1004", 2) // S2 class: per-thread credentials differ
	}, defaultHolderLimits)
	if out.Complete || out.Reconciled != 0 || len(out.Owners[churnS1]) != 0 || len(out.Owners[churnS2]) != 0 {
		t.Fatalf("%+v", out)
	}
	if out.SocketIssues[churnS1] != "holder_identity_ambiguous" || out.SocketIssues[churnS2] != "holder_identity_ambiguous" {
		t.Fatalf("%+v", out.SocketIssues)
	}
	if out.retryTopology {
		t.Fatal("identity failure must not be retried as topology")
	}
}

func TestHolderChurnRefusals(t *testing.T) {
	for _, tc := range []struct {
		name, code string
		setup      func(m *churnModel) func()
		retry      bool
	}{
		{"new member with different credentials", "holder_identity_ambiguous", func(m *churnModel) func() {
			m.creds[13] = "2:2:2:2/2:2:2:2/groups:2"
			return func() { addThread(m, 10, 13, "1003", 1) }
		}, false},
		{"surviving TID reused at another generation", "holder_inspection_changed", func(m *churnModel) func() {
			return func() { m.f.groups[10][11].start = "1099" }
		}, false},
		{"unreadable new member", "holder_inspection_changed", func(m *churnModel) func() {
			m.factsErr[13] = syscall.EACCES
			return func() { addThread(m, 10, 13, "1003", 1) }
		}, false},
		{"descriptor retargeted after the fresh scan", "holder_inspection_changed", func(m *churnModel) func() {
			return func() {
				addThread(m, 10, 13, "1003", 1)
				m.onFacts = func(m *churnModel, tid int) {
					if tid == 13 {
						m.f.tables[1][3] = "socket:[555]"
						m.onFacts = nil
					}
				}
			}
		}, false},
		{"runtime classification changed", "holder_inspection_changed", func(m *churnModel) func() {
			return func() {
				addThread(m, 10, 13, "1003", 1)
				// Installed at recheck time: the next classification of the inspected
				// task is the re-verification bookend.
				m.inspectHook = func(m *churnModel, tid int, p *Process) {
					if tid == 10 {
						p.Application.Key = "other"
					}
				}
			}
		}, false},
		// The class set changed (table 1 is now represented by 11), so this is an
		// ordinary refusal; the appeared marker is applied last.
		{"inspected task left the table", "holder_appeared", func(m *churnModel) func() {
			return func() {
				delete(m.f.groups[10], 10)
				m.f.groups[10][10] = &censusTask{"1000", false, 7} // leader moved to a new private table
				m.f.tables[7] = map[int]string{}
				addThread(m, 10, 13, "1003", 1)
			}
		}, true},
		{"repeated churn during re-verification", "membership_changed", func(m *churnModel) func() {
			return func() {
				addThread(m, 10, 13, "1003", 1)
				m.onFacts = func(m *churnModel, tid int) {
					if tid == 13 {
						addThread(m, 10, 14, "1004", 1)
						m.onFacts = nil
					}
				}
			}
		}, true},
		{"new member in a new table holding the socket", "holder_appeared", func(m *churnModel) func() {
			return func() {
				m.f.tables[11] = map[int]string{3: churnS1}
				addThread(m, 10, 13, "1003", 11)
			}
		}, true},
		{"deadline during re-verification", "time_limit", func(m *churnModel) func() {
			return func() {
				addThread(m, 10, 13, "1003", 1)
				m.onFacts = func(m *churnModel, tid int) {
					if tid == 13 {
						m.f.now = m.f.now.Add(time.Hour)
					}
				}
			}
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newChurnModel()
			mutate := tc.setup(m)
			_, out := m.run(mutate, defaultHolderLimits)
			if out.Complete || out.Reconciled != 0 || len(out.Owners[churnS1]) != 0 {
				t.Fatalf("%+v", out)
			}
			if out.SocketIssues[churnS1] != tc.code {
				t.Fatalf("S1 code %q want %q (issues %v)", out.SocketIssues[churnS1], tc.code, out.Issues)
			}
			if tc.code != "time_limit" && len(out.Owners[churnS2]) != 0 {
				t.Fatalf("group-atomic: S2 still owned %+v", out.Owners[churnS2])
			}
			if out.retryTopology != tc.retry {
				t.Fatalf("retryTopology %v want %v", out.retryTopology, tc.retry)
			}
		})
	}
}

func TestHolderChurnOtherGroupGainingSocketStaysAppeared(t *testing.T) {
	m := newChurnModel()
	_, out := m.run(func() {
		addThread(m, 10, 13, "1003", 1)
		// Group 70 (/other) receives the descriptor in a new thread's table: a
		// visible topology change the recheck must report as a new holder.
		m.f.tables[12] = map[int]string{4: churnS1}
		addThread(m, 70, 71, "7001", 12)
	}, defaultHolderLimits)
	if out.Complete || out.SocketIssues[churnS1] != "holder_appeared" {
		t.Fatalf("%+v", out)
	}
	for _, p := range out.Owners[churnS1] {
		if p.ThreadGroup == 70 {
			t.Fatal("a group never inspected must not become an owner")
		}
	}
}

func TestHolderChurnWithoutKcmpRefused(t *testing.T) {
	m := newChurnModel()
	m.f.kcmpErr = syscall.EPERM
	_, out := m.run(func() { addThread(m, 10, 13, "1003", 1) }, defaultHolderLimits)
	if out.Complete || out.Reconciled != 0 || len(out.Owners[churnS1]) != 0 {
		t.Fatalf("%+v", out)
	}
}

func TestHolderChurnExitedLeaderRefused(t *testing.T) {
	m := newChurnModel()
	_, out := m.run(func() { addThread(m, 20, 23, "2003", 3) }, defaultHolderLimits)
	if code := out.SocketIssues[churnS3]; out.Complete || out.Reconciled != 0 || len(out.Owners[churnS3]) != 0 || (code != "membership_changed" && code != "holder_appeared") {
		t.Fatalf("%+v", out)
	}
	if !slices.Equal(churnOwnerPIDs(out, churnS1), []int{10}) {
		t.Fatal("unrelated group lost its owner")
	}
}

func TestHolderChurnCensusIncompleteRefused(t *testing.T) {
	m := newChurnModel()
	m.f.fdErr[60] = syscall.EACCES
	_, out := m.run(func() { addThread(m, 10, 13, "1003", 1) }, defaultHolderLimits)
	if out.Complete || out.Reconciled != 0 || len(out.Owners[churnS1]) != 0 || out.SocketIssues[churnS1] != "membership_changed" {
		t.Fatalf("%+v", out)
	}
}

// Cumulative budget: the census fits exactly, the fresh rescan does not. The
// recheck fails as a whole and nothing is reconciled.
func TestHolderChurnBudgetExhaustionIsTerminal(t *testing.T) {
	m := newChurnModel()
	lim := defaultHolderLimits
	// The census reads exactly five descriptors (tables 1:2, 2:1, 3:1, 8:1, 9:0);
	// the fresh rescan of group 10 needs two more and exhausts the shared budget.
	lim.FDs = 5
	_, out := m.run(func() { addThread(m, 10, 13, "1003", 1) }, lim)
	if out.Complete || out.Reconciled != 0 || !slices.Contains(out.Issues, "holder_census_incomplete") || out.SocketIssues[churnS1] != "holder_census_incomplete" {
		t.Fatalf("%+v", out)
	}
	for _, p := range out.Owners[churnS1] {
		// Existing incomplete-recheck semantics: the census member set is kept
		// only as flagged metadata; no reconciled member may appear.
		if p.HolderWitness != "" {
			t.Fatal("budget exhaustion must not derive a witness from unverified members")
		}
	}
}

func TestHolderChurnRecheckErrorFormStaysClosed(t *testing.T) {
	m := newChurnModel()
	p := m.f.proc()
	c := p.census(churnWanted, defaultHolderLimits)
	addThread(m, 10, 13, "1003", 1)
	d := c.RecheckDetail()
	if d.Err != nil || len(d.Groups) != 0 || len(d.Appeared) != 0 || len(d.Reconcilable) != 1 {
		t.Fatalf("%+v", d)
	}
	hs := d.Reconcilable[10]
	if len(hs) != 3 || holderMembers(hs[0]) != "10@1000,11@1001,13@1003" || hs[0].Socket != churnS1 || holderMembers(hs[1]) != "10@1000,11@1001,13@1003" || hs[1].Socket != churnS4 || holderMembers(hs[2]) != "12@1002" || hs[2].Socket != churnS2 {
		t.Fatalf("%v", holderSummary(HolderCensus{Holders: hs}))
	}
	if err := c.Recheck(); err == nil || err.Error() != "membership_changed" {
		t.Fatalf("error form must stay closed: %v", err)
	}
}

// After a failed re-verification caused by a plain topology change, the
// existing single retry re-censuses and succeeds when the group has settled.
func TestHolderChurnRetryAfterFailedReconciliation(t *testing.T) {
	m := newChurnModel()
	attempts := 0
	lim := defaultHolderLimits
	c, out := retryHolderIdentities(m.f.proc().now, lim, nil, func(b *holderBudget) (HolderCensus, holderIdentities) {
		attempts++
		p := m.f.proc()
		c := p.censusBudget(churnWanted, lim, b)
		if attempts == 1 {
			addThread(m, 10, 13, "1003", 1)
			m.onFacts = func(m *churnModel, tid int) {
				if tid == 13 {
					addThread(m, 10, 14, "1004", 1)
					m.onFacts = nil
				}
			}
		}
		descriptor := func(path, socket string) bool {
			target, err := p.readlink(path)
			return err == nil && target == socket
		}
		return c, inspectHolderIdentitiesWith(c, m.inspect, m.facts, descriptor, c.RecheckDetail)
	})
	if attempts != 2 || !c.Complete || !out.Complete || out.Reconciled != 0 || !slices.Equal(churnOwnerPIDs(out, churnS1), []int{10}) {
		t.Fatalf("attempts %d census %v out %+v", attempts, c.Issues, out)
	}
}

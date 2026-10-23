package identity

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

type holderIdentityFixture struct {
	c         HolderCensus
	processes map[int]Process
	facts     map[int]holderTaskFacts
	inspect   func(int) (Process, error)
	read      func(Holder, HolderMember) (holderTaskFacts, error)
	fd        func(string, string) bool
	check     func() HolderRecheck
}

func newHolderIdentityFixture(groups ...[]int) *holderIdentityFixture {
	f := &holderIdentityFixture{c: HolderCensus{Complete: true}, processes: map[int]Process{}, facts: map[int]holderTaskFacts{}}
	for _, members := range groups {
		h := Holder{TGID: 100, GroupStart: "g1", Proven: true, Socket: "socket:[1]", FDPath: fmt.Sprint(members)}
		for _, tid := range members {
			start := fmt.Sprint(tid)
			h.Members = append(h.Members, HolderMember{tid, start})
			f.facts[tid] = holderTaskFacts{Group: 100, Start: start, Exe: "/native", Revision: "r1", NetNS: "net", MountNS: "mnt", PIDNS: "pid", Credentials: "1:1:1:1/1:1:1:1/groups:1", UID: 1}
			f.processes[tid] = Process{PID: tid, ThreadGroup: 100, Start: start, UID: 1, BootID: "boot", Executable: "/native", ExecutableRevision: "r1", NetNS: "net", MountNS: "mnt", PIDNS: "pid", Application: Application{Kind: "native", Key: "app", Revision: "r1", Executable: "/native"}}
		}
		f.c.Holders = append(f.c.Holders, h)
	}
	f.inspect = func(tid int) (Process, error) { return f.processes[tid], nil }
	f.read = func(_ Holder, m HolderMember) (holderTaskFacts, error) { return f.facts[m.TID], nil }
	f.fd = func(string, string) bool { return true }
	f.check = func() HolderRecheck { return HolderRecheck{} }
	return f
}
func (f *holderIdentityFixture) run() holderIdentities {
	return inspectHolderIdentitiesWith(f.c, f.inspect, f.read, f.fd, f.check)
}
func TestHolderIdentityRepresentatives(t *testing.T) {
	for _, tc := range []struct {
		name    string
		groups  [][]int
		pid     int
		witness bool
	}{
		{"leader", [][]int{{100, 101}}, 100, false},
		{"worker", [][]int{{101, 102}}, 101, true},
		{"private", [][]int{{101}}, 101, true},
		{"split", [][]int{{101}, {100, 102}}, 100, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newHolderIdentityFixture(tc.groups...)
			out := f.run()
			ps := out.Owners["socket:[1]"]
			if !out.Complete || len(ps) != 1 || ps[0].PID != tc.pid || (ps[0].HolderWitness != "") != tc.witness {
				t.Fatalf("%+v", out)
			}
			if !tc.witness && fingerprint(ps, nil) != fingerprint([]Process{f.processes[tc.pid]}, nil) {
				t.Fatal("leader fingerprint changed")
			}
		})
	}
}
func TestHolderIdentityChecksEveryMember(t *testing.T) {
	for _, field := range []string{"uid", "credentials", "net", "mount", "pidns", "exe", "revision", "group", "start"} {
		t.Run(field, func(t *testing.T) {
			f := newHolderIdentityFixture([]int{100, 101})
			g := f.facts[101]
			switch field {
			case "uid":
				g.UID++
			case "credentials":
				g.Credentials = "other"
			case "net":
				g.NetNS = "other"
			case "mount":
				g.MountNS = "other"
			case "pidns":
				g.PIDNS = "other"
			case "exe":
				g.Exe = "other"
			case "revision":
				g.Revision = "other"
			case "group":
				g.Group++
			case "start":
				g.Start = "other"
			}
			f.facts[101] = g
			out := f.run()
			if out.Complete || len(out.Owners["socket:[1]"]) != 0 || out.SocketIssues["socket:[1]"] == "" {
				t.Fatalf("%+v", out)
			}
		})
	}
}
func TestHolderIdentityRefusesUnsupportedWorkerAndTableMerge(t *testing.T) {
	for _, kind := range []string{"hosted", "wine", "redirected", "revision"} {
		for _, groups := range [][][]int{{{101}}, {{100}, {101}}} {
			t.Run(fmt.Sprint(kind, groups), func(t *testing.T) {
				f := newHolderIdentityFixture(groups...)
				for tid, p := range f.processes {
					switch kind {
					case "hosted":
						p.Application.Hosted = &Hosted{State: "unverified"}
					case "wine":
						p.Application.Kind = "wine"
					case "redirected":
						p.Application.Executable = "/payload"
					case "revision":
						p.Application.Revision = "payload"
					}
					f.processes[tid] = p
				}
				out := f.run()
				if out.Complete {
					t.Fatalf("unsupported worker accepted: %+v", out)
				}
				for _, p := range out.Owners["socket:[1]"] {
					if p.PID != 100 {
						t.Fatal("worker accepted")
					}
				}
			})
		}
	}
	// Existing runtime association retains a proven live-leader class, not a new worker identity.
	f := newHolderIdentityFixture([]int{100, 101})
	p := f.processes[100]
	p.Application.Kind = "wine-unresolved"
	f.processes[100] = p
	if out := f.run(); !out.Complete || len(out.Owners["socket:[1]"]) != 1 {
		t.Fatalf("live leader runtime: %+v", out)
	}
}
func TestHolderIdentityKeepsAmbiguity(t *testing.T) {
	for _, unproven := range []bool{true, false} {
		t.Run(fmt.Sprint(unproven), func(t *testing.T) {
			f := newHolderIdentityFixture([]int{100}, []int{101})
			if unproven {
				for i := range f.c.Holders {
					f.c.Holders[i].Proven = false
				}
			} else {
				f.c.Holders[1].TGID = 101
				p := f.processes[101]
				p.ThreadGroup = 101
				f.processes[101] = p
				g := f.facts[101]
				g.Group = 101
				f.facts[101] = g
			}
			out := f.run()
			if !out.Complete || len(out.Owners["socket:[1]"]) != 2 {
				t.Fatalf("%+v", out)
			}
		})
	}
}
func TestHolderIdentityRacesAndPartialEvidence(t *testing.T) {
	for _, mode := range []string{"inspect", "after", "descriptor", "recheck", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			f := newHolderIdentityFixture([]int{100, 101})
			switch mode {
			case "inspect":
				p := f.processes[100]
				p.ExecutableRevision = "changed"
				f.processes[100] = p
			case "after":
				n := 0
				f.read = func(_ Holder, m HolderMember) (holderTaskFacts, error) {
					n++
					v := f.facts[m.TID]
					if n > 2 {
						v.Credentials = "changed"
					}
					return v, nil
				}
			case "descriptor":
				f.fd = func(string, string) bool { return false }
			case "recheck":
				f.check = func() HolderRecheck { return HolderRecheck{Groups: map[int]string{100: "changed"}} }
			case "timeout":
				now := time.Now()
				f.c.src.deadline = now.Add(time.Second)
				f.c.src.now = func() time.Time { return now }
				f.inspect = func(tid int) (Process, error) { now = now.Add(time.Second * 2); return f.processes[tid], nil }
			}
			out := f.run()
			if out.Complete || len(out.Owners) != 0 {
				t.Fatalf("%+v", out)
			}
		})
	}
	f := newHolderIdentityFixture([]int{100}, []int{101})
	f.inspect = func(tid int) (Process, error) {
		if tid == 101 {
			return Process{}, errors.New("unreadable")
		}
		return f.processes[tid], nil
	}
	out := f.run()
	if out.Complete || len(out.Owners["socket:[1]"]) != 1 || out.SocketIssues["socket:[1]"] == "" || out.Unavailable != 1 {
		t.Fatalf("partial socket: %+v", out)
	}
	row := ActivityRow{Owners: []string{"100"}, Ownership: "Owner metadata unavailable"}
	if activityDisplayApplication(row, map[string]ActivityProcess{"100": {Application: f.processes[100].Application}}) != nil {
		t.Fatal("partial holder set gained display association")
	}
	f = newHolderIdentityFixture([]int{100})
	f.c.Complete = false
	f.c.Issues = []string{"unrelated_unreadable"}
	f.check = func() HolderRecheck { return HolderRecheck{Err: errors.New("incomplete")} }
	out = f.run()
	if out.Complete || len(out.Owners["socket:[1]"]) != 1 || out.SocketIssues["socket:[1]"] == "" {
		t.Fatalf("unrelated partial: %+v", out)
	}
}
func TestHolderIdentityWitnessPinsWholeSet(t *testing.T) {
	f := newHolderIdentityFixture([]int{101, 102})
	a := f.run().Owners["socket:[1]"][0]
	f.c.Holders[0].Members[1].Start = "new"
	g := f.facts[102]
	g.Start = "new"
	f.facts[102] = g
	b := f.run().Owners["socket:[1]"][0]
	if a.HolderWitness == b.HolderWitness || fingerprint([]Process{a}, nil) == fingerprint([]Process{b}, nil) {
		t.Fatal("member replacement did not change witness")
	}
	f.c.Holders[0].GroupStart = "g2"
	c := f.run().Owners["socket:[1]"][0]
	if b.HolderWitness == c.HolderWitness {
		t.Fatal("group replacement did not change witness")
	}
}

func TestHolderWitnessRefusesInstanceAuthority(t *testing.T) {
	f := newHolderIdentityFixture([]int{100})
	p := f.run().Owners["socket:[1]"][0]
	b, err := BindInstance("session", p)
	if err != nil || !b.Matches(p) {
		t.Fatalf("ordinary leader control: %v", err)
	}
	for _, groups := range [][][]int{{{101}}, {{100}, {101}}} {
		q := newHolderIdentityFixture(groups...).run().Owners["socket:[1]"][0]
		if _, err := BindInstance("session", q); err == nil {
			t.Fatal("holder witness gained instance authority")
		}
		if b.Matches(q) {
			t.Fatal("existing process rule matched witnessed owner")
		}
		a := Attribution{Application: &q.Application, Owners: []Process{q}, VisibilityComplete: true}
		if target := DescribePermissionTarget(a); target == nil || !strings.HasPrefix(target.ForAWhile, "Unavailable:") {
			t.Fatalf("false scope: %+v", target)
		}
	}
}
func TestObservedNativePreservesPerSocketWitness(t *testing.T) {
	p := newHolderIdentityFixture([]int{100}).processes[100]
	p.NetNS = NetNS()
	expected := ActivityProcess{ID: "100:100", PID: p.PID, Start: p.Start, UID: p.UID, Application: p.Application, NetNS: p.NetNS, MountNS: p.MountNS, PIDNS: p.PIDNS, BootID: p.BootID}
	row := ActivityRow{ID: "row", Owners: []string{expected.ID}, OwnershipCategory: "visible-holder", Socket: Socket{NetNS: p.NetNS, Cookie: "cookie", Inode: 1}}
	for _, witness := range []string{"", "merged-witness"} {
		row.HolderWitness = witness
		s := ActivitySnapshot{Complete: true, Rows: []ActivityRow{row}, Processes: map[string]ActivityProcess{expected.ID: expected}}
		got, err := verifyObservedNativeSnapshot("row", expected, s, func(int) (Process, error) { return p, nil })
		if err != nil || got.HolderWitness != witness {
			t.Fatalf("witness lost: %+v %v", got, err)
		}
		_, err = BindInstance("session", got)
		if (err != nil) != (witness != "") {
			t.Fatalf("scope mismatch %q: %v", witness, err)
		}
	}
}

func TestHolderIdentityRecheckFailureScope(t *testing.T) {
	f := newHolderIdentityFixture([]int{100}, []int{200})
	f.c.Holders[1].TGID = 200
	f.c.Holders[1].Socket = "socket:[2]"
	p := f.processes[200]
	p.ThreadGroup = 200
	f.processes[200] = p
	facts := f.facts[200]
	facts.Group = 200
	f.facts[200] = facts
	f.check = func() HolderRecheck { return HolderRecheck{Groups: map[int]string{100: "membership_changed"}} }
	out := f.run()
	if out.Complete || len(out.Owners["socket:[1]"]) != 0 || len(out.Owners["socket:[2]"]) != 1 || out.SocketIssues["socket:[1]"] == "" || out.SocketIssues["socket:[2]"] != "" {
		t.Fatalf("group error leaked: %+v", out)
	}
	f.check = func() HolderRecheck { return HolderRecheck{Appeared: []string{"socket:[1]"}} }
	out = f.run()
	if out.Complete || len(out.Owners["socket:[1]"]) != 1 || len(out.Owners["socket:[2]"]) != 1 || out.SocketIssues["socket:[1]"] == "" || out.SocketIssues["socket:[2]"] != "" {
		t.Fatalf("new holder scope: %+v", out)
	}
	f.check = func() HolderRecheck { return HolderRecheck{Err: errors.New("global uncertainty")} }
	out = f.run()
	if out.Complete || len(out.Owners["socket:[1]"]) != 1 || len(out.Owners["socket:[2]"]) != 1 || out.SocketIssues["socket:[1]"] == "" || out.SocketIssues["socket:[2]"] == "" {
		t.Fatalf("global uncertainty missing: %+v", out)
	}
}

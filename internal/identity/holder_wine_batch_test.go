package identity

import (
	"fmt"
	"testing"
	"time"
)

func wineHolderFixture(n int) *holderIdentityFixture {
	f := newHolderIdentityFixture([]int{100, 101})
	manyHolderSockets(f, n)
	p := f.processes[100]
	p.Application = Application{Kind: "wine-unresolved", Runtime: p.Executable, Prefix: "/prefix-a"}
	f.processes[100] = p
	return f
}

func TestWineHolderCensusScopedMetadata(t *testing.T) {
	for _, n := range []int{1, 2, 256} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			f := wineHolderFixture(n)
			facts, inspections, descriptors, rechecks := 0, 0, 0, 0
			f.read = func(_ Holder, m HolderMember) (holderTaskFacts, error) { facts++; return f.facts[m.TID], nil }
			f.inspect = func(pid int) (Process, error) { inspections++; return f.processes[pid], nil }
			f.fd = func(string, string) bool { descriptors++; return true }
			f.check = func() HolderRecheck { rechecks++; return HolderRecheck{} }
			wantFacts, wantInspections := 6, 2
			if n == 1 {
				wantFacts, wantInspections = 4, 1
			}
			for run := 1; run <= 2; run++ {
				out := f.run()
				if !out.Complete || len(out.Owners) != n || facts != run*wantFacts || inspections != run*wantInspections || descriptors != run*n || rechecks != run {
					t.Fatalf("run %d: facts=%d inspections=%d descriptors=%d rechecks=%d out=%+v", run, facts, inspections, descriptors, rechecks, out)
				}
				for _, ps := range out.Owners {
					if len(ps) != 1 || ps[0].PID != 100 || ps[0].HolderWitness != "" || ps[0].Application.Kind != "wine-unresolved" || ps[0].Application.Key != "" {
						t.Fatalf("transport evidence gained application authority: %+v", ps)
					}
				}
			}
			// This callback may itself be Activity's guarded cache. These are
			// callback counts, not a promise of this many raw FullInspect calls.
		})
	}
}

func TestWineHolderMetadataChangeWithdrawsWholeClass(t *testing.T) {
	for _, field := range []string{"start", "uid", "credentials", "exe", "revision", "netns", "mountns", "pidns", "group", "unreadable", "prefix", "runtime", "kind", "app", "app-revision", "app-key", "native", "hosted", "members"} {
		t.Run(field, func(t *testing.T) {
			f := wineHolderFixture(8)
			last := false
			links := 0
			f.fd = func(string, string) bool { links++; last = links == 8; return true }
			f.read = func(_ Holder, m HolderMember) (holderTaskFacts, error) {
				v := f.facts[m.TID]
				if last && m.TID == 101 {
					switch field {
					case "start":
						v.Start = "new"
					case "uid":
						v.UID++
					case "credentials":
						v.Credentials = "other"
					case "exe":
						v.Exe = "/other"
					case "revision":
						v.Revision = "other"
					case "netns":
						v.NetNS = "other"
					case "mountns":
						v.MountNS = "other"
					case "pidns":
						v.PIDNS = "other"
					case "group":
						v.Group++
					case "unreadable":
						return v, fmt.Errorf("unreadable")
					}
				}
				return v, nil
			}
			f.inspect = func(pid int) (Process, error) {
				p := f.processes[pid]
				if last {
					switch field {
					case "prefix":
						p.Application.Prefix = "/prefix-b"
					case "runtime":
						p.Application.Runtime = "/other-runtime"
					case "kind":
						p.Application.Kind = "wine"
					case "app":
						p.Application.Executable = "/prefix-a/beta.exe"
					case "app-revision":
						p.Application.Revision = "new"
					case "app-key":
						p.Application.Key = "other"
					case "native":
						p.Application = Application{Kind: "native", Executable: p.Executable, Revision: p.ExecutableRevision, Key: "native"}
					case "hosted":
						p.Application.Hosted = &Hosted{State: "unverified"}
					}
				}
				return p, nil
			}
			if field == "members" {
				f.c.Holders[6].Members = []HolderMember{{100, "100"}}
			}
			out := f.run()
			if out.Complete || out.retryTopology {
				t.Fatalf("changed class accepted/retried: %+v", out)
			}
			for _, h := range f.c.Holders {
				if len(out.Owners[h.Socket]) != 0 || out.SocketIssues[h.Socket] == "" {
					t.Fatalf("earlier socket survived %s: %+v", field, out)
				}
			}
		})
	}
}

func TestWineHolderMetadataRetainsDescriptorAndTopologyChecks(t *testing.T) {
	for _, failure := range []string{"descriptor", "topology"} {
		t.Run(failure, func(t *testing.T) {
			f := wineHolderFixture(8)
			if failure == "descriptor" {
				f.fd = func(path, _ string) bool { return path != "/fd/3" }
			} else {
				f.check = func() HolderRecheck { return HolderRecheck{Groups: map[int]string{100: "table_changed"}} }
			}
			out := f.run()
			if out.Complete || len(out.Owners["socket:[4]"]) != 0 {
				t.Fatalf("failed evidence retained: %+v", out)
			}
			if failure == "topology" {
				for _, ps := range out.Owners {
					if len(ps) != 0 {
						t.Fatal("changed topology retained owner", ps)
					}
				}
			}
		})
	}
}

func TestWineHolderMetadataDoesNotMergeApplicationsOrPrefixes(t *testing.T) {
	// Independent transport classes of two applications in two prefixes. The
	// same socket is deliberately shared: no representative may merge them.
	f := wineHolderFixture(1)
	f.c.Holders = nil
	for prefix := 0; prefix < 2; prefix++ {
		for app := 0; app < 2; app++ {
			pid := 200 + 10*prefix + app
			p := f.processes[100]
			p.PID, p.ThreadGroup, p.Start = pid, pid, fmt.Sprint(pid)
			p.Application.Kind = "wine"
			p.Application.Prefix = fmt.Sprintf("/prefix-%d", prefix)
			p.Application.Executable = fmt.Sprintf("/program-%d.exe", app)
			p.Application.Key = digest(fmt.Sprintf("%d|%s|%s|%s", p.UID, "wine", p.Application.Prefix, p.Application.Executable))
			p.Application.Revision = "r1"
			f.processes[pid] = p
			facts := f.facts[100]
			facts.Group, facts.Start = pid, p.Start
			f.facts[pid] = facts
			for s := 0; s < 3; s++ {
				f.c.Holders = append(f.c.Holders, Holder{TGID: pid, GroupStart: p.Start, Proven: true, Members: []HolderMember{{pid, p.Start}}, Socket: fmt.Sprintf("socket:[%d]", s), FDPath: fmt.Sprintf("/%d/fd/%d", pid, s)})
			}
		}
	}
	out := f.run()
	if !out.Complete || len(out.Owners) != 3 {
		t.Fatal(out)
	}
	for _, ps := range out.Owners {
		keys := map[string]bool{}
		for _, p := range ps {
			keys[p.Application.Key] = true
		}
		if len(ps) != 4 || len(keys) != 4 {
			t.Fatal("applications or prefixes merged", ps)
		}
	}
}

func TestWineHolderMetadataKeepsUnprovenAndWorkerRestrictions(t *testing.T) {
	for _, mode := range []string{"unproven", "worker"} {
		t.Run(mode, func(t *testing.T) {
			f := wineHolderFixture(3)
			p := f.processes[100]
			if mode == "worker" {
				p.PID, p.Start = 101, "101"
				f.processes[101] = p
			}
			for i := range f.c.Holders {
				if mode == "unproven" {
					f.c.Holders[i].Proven = false
					f.c.Holders[i].Members = []HolderMember{{100, "100"}}
				} else {
					f.c.Holders[i].Members = []HolderMember{{101, "101"}}
				}
			}
			calls := 0
			f.inspect = func(pid int) (Process, error) { calls++; return f.processes[pid], nil }
			out := f.run()
			if calls != 3 {
				t.Fatal("unsupported class batched", calls)
			}
			if mode == "worker" {
				if out.Complete {
					t.Fatal("worker accepted", out)
				}
				for _, ps := range out.Owners {
					if len(ps) > 0 {
						t.Fatal("worker gained authority", ps)
					}
				}
			} else if !out.Complete || len(out.Owners) != 3 {
				t.Fatal("single-member unproven behavior changed", out)
			}
		})
	}
}

func TestWineHolderMetadataDeadlineWithdrawsObservations(t *testing.T) {
	for _, mode := range []string{"final-inspect", "final-facts"} {
		t.Run(mode, func(t *testing.T) {
			f := wineHolderFixture(8)
			now := time.Now()
			f.c.src.deadline = now.Add(time.Second)
			f.c.src.now = func() time.Time { return now }
			calls, reads := 0, 0
			f.inspect = func(pid int) (Process, error) {
				calls++
				if mode == "final-inspect" && calls == 2 {
					now = now.Add(2 * time.Second)
				}
				return f.processes[pid], nil
			}
			f.read = func(_ Holder, m HolderMember) (holderTaskFacts, error) {
				reads++
				if mode == "final-facts" && reads == 5 {
					now = now.Add(2 * time.Second)
				}
				return f.facts[m.TID], nil
			}
			out := f.run()
			if out.Complete || out.retryTopology || len(out.Owners) != 0 {
				t.Fatal("expired class retained observations", out)
			}
		})
	}
}

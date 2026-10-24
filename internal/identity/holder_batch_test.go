package identity

import (
	"fmt"
	"testing"
	"time"
)

func manyHolderSockets(f *holderIdentityFixture, n int) {
	first := f.c.Holders[0]
	f.c.Holders = nil
	for i := 0; i < n; i++ {
		h := first
		h.Socket = fmt.Sprintf("socket:[%d]", i+1)
		h.FDPath = fmt.Sprintf("/fd/%d", i)
		f.c.Holders = append(f.c.Holders, h)
	}
}

func TestNativeHolderInspectionBookendsOncePerClass(t *testing.T) {
	f := newHolderIdentityFixture([]int{100, 101})
	manyHolderSockets(f, 256)
	reads, inspects, links, rechecks := 0, 0, 0, 0
	f.read = func(_ Holder, m HolderMember) (holderTaskFacts, error) { reads++; return f.facts[m.TID], nil }
	f.inspect = func(tid int) (Process, error) { inspects++; return f.processes[tid], nil }
	f.fd = func(string, string) bool { links++; return true }
	f.check = func() HolderRecheck { rechecks++; return HolderRecheck{} }
	out := f.run()
	if !out.Complete || len(out.Owners) != 256 || reads != 6 || inspects != 2 || links != 256 || rechecks != 1 {
		t.Fatalf("reads=%d inspect=%d links=%d rechecks=%d out=%+v", reads, inspects, links, rechecks, out)
	}
	for _, owners := range out.Owners {
		if len(owners) != 1 || owners[0].PID != 100 || owners[0].HolderWitness != "" {
			t.Fatal(owners)
		}
	}
	// No evidence or inspector result survives into another census invocation.
	f.run()
	if reads != 12 || inspects != 4 || links != 512 {
		t.Fatal("cross-snapshot reuse", reads, inspects, links)
	}
}

func TestNativeHolderFinalChangeWithdrawsEveryAssociatedSocket(t *testing.T) {
	for _, field := range []string{"uid", "credentials", "exe", "revision", "net", "mount", "pidns", "start", "group", "unreadable"} {
		t.Run(field, func(t *testing.T) {
			f := newHolderIdentityFixture([]int{100, 101})
			manyHolderSockets(f, 8)
			links := 0
			changed := false
			f.fd = func(string, string) bool {
				links++
				if links == 8 {
					changed = true
				}
				return true
			}
			f.read = func(_ Holder, m HolderMember) (holderTaskFacts, error) {
				v := f.facts[m.TID]
				if changed && m.TID == 101 {
					switch field {
					case "uid":
						v.UID++
					case "credentials":
						v.Credentials = "other"
					case "exe":
						v.Exe = "/other"
					case "revision":
						v.Revision = "other"
					case "net":
						v.NetNS = "other"
					case "mount":
						v.MountNS = "other"
					case "pidns":
						v.PIDNS = "other"
					case "start":
						v.Start = "other"
					case "group":
						v.Group++
					case "unreadable":
						return v, fmt.Errorf("unavailable")
					}
				}
				return v, nil
			}
			out := f.run()
			if out.Complete || out.retryTopology {
				t.Fatal("changed identity accepted or retried", out)
			}
			for _, h := range f.c.Holders {
				if len(out.Owners[h.Socket]) != 0 || out.SocketIssues[h.Socket] == "" {
					t.Fatal("earlier socket retained changed owner", h.Socket, out)
				}
			}
		})
	}
}

func TestHolderInspectionDoesNotBatchUnsupportedOrUnprovenIdentity(t *testing.T) {
	for _, kind := range []string{"unproven", "wine", "hosted"} {
		t.Run(kind, func(t *testing.T) {
			f := newHolderIdentityFixture([]int{100})
			manyHolderSockets(f, 3)
			if kind == "unproven" {
				for i := range f.c.Holders {
					f.c.Holders[i].Proven = false
				}
			} else {
				p := f.processes[100]
				if kind == "wine" {
					p.Application.Kind = "wine-unresolved"
				} else {
					p.Application.Hosted = &Hosted{State: "unverified"}
				}
				f.processes[100] = p
			}
			inspections := 0
			f.inspect = func(tid int) (Process, error) { inspections++; return f.processes[tid], nil }
			f.run()
			if inspections != 3 {
				t.Fatal("unsupported identity shared inspection", kind, inspections)
			}
		})
	}
}

func TestNativeHolderInspectionRetainsDescriptorAndTopologyChecks(t *testing.T) {
	for _, failure := range []string{"descriptor", "topology", "members"} {
		t.Run(failure, func(t *testing.T) {
			f := newHolderIdentityFixture([]int{100, 101})
			manyHolderSockets(f, 4)
			if failure == "descriptor" {
				f.fd = func(path, _ string) bool { return path != "/fd/2" }
			}
			if failure == "topology" {
				f.check = func() HolderRecheck { return HolderRecheck{Groups: map[int]string{100: "table_changed"}} }
			}
			if failure == "members" {
				f.c.Holders[2].Members = []HolderMember{{100, "100"}}
			}
			out := f.run()
			if out.Complete {
				t.Fatal("changed evidence accepted", failure)
			}
			if failure != "descriptor" {
				for _, h := range f.c.Holders {
					if len(out.Owners[h.Socket]) != 0 {
						t.Fatal("group change left owner", h.Socket, out)
					}
				}
			} else if len(out.Owners["socket:[3]"]) != 0 {
				t.Fatal("changed FD retained owner", out)
			}
		})
	}
}

func TestNativeHolderRuntimeClassificationBookend(t *testing.T) {
	for _, changed := range []string{"wine", "hosted", "prefix"} {
		t.Run(changed, func(t *testing.T) {
			f := newHolderIdentityFixture([]int{100})
			manyHolderSockets(f, 8)
			calls := 0
			f.inspect = func(tid int) (Process, error) {
				calls++
				p := f.processes[tid]
				if calls > 1 {
					switch changed {
					case "wine":
						p.Application.Kind = "wine"
					case "hosted":
						p.Application.Hosted = &Hosted{State: "unverified"}
					case "prefix":
						p.Application.Prefix = "/other"
					}
				}
				return p, nil
			}
			out := f.run()
			if out.Complete {
				t.Fatal("runtime transition accepted", out)
			}
			for _, h := range f.c.Holders {
				if len(out.Owners[h.Socket]) != 0 || out.SocketIssues[h.Socket] == "" {
					t.Fatal("runtime change retained earlier socket", out)
				}
			}
		})
	}
}

func TestNativeHolderBatchDeadlineAndPartialClass(t *testing.T) {
	for _, mode := range []string{"final-inspect", "final-facts", "other-class"} {
		t.Run(mode, func(t *testing.T) {
			f := newHolderIdentityFixture([]int{100, 101})
			manyHolderSockets(f, 4)
			now := time.Now()
			f.c.src.deadline = now.Add(time.Second)
			f.c.src.now = func() time.Time { return now }
			inspections, reads := 0, 0
			f.inspect = func(tid int) (Process, error) {
				inspections++
				if mode == "final-inspect" && inspections == 2 {
					now = now.Add(2 * time.Second)
				}
				return f.processes[tid], nil
			}
			f.read = func(_ Holder, m HolderMember) (holderTaskFacts, error) {
				reads++
				if mode == "final-facts" && reads == 5 {
					now = now.Add(2 * time.Second)
				}
				return f.facts[m.TID], nil
			}
			if mode == "other-class" {
				other := newHolderIdentityFixture([]int{200})
				h := other.c.Holders[0]
				h.TGID = 200
				h.GroupStart = "g2"
				h.Socket = "socket:[1]"
				h.FDPath = "/other"
				f.c.Holders = append(f.c.Holders, h)
				// A known unreadable coholder keeps the socket explicitly partial.
			}
			out := f.run()
			if out.Complete || out.retryTopology {
				t.Fatal("partial/deadline accepted or retried", out)
			}
			if mode != "other-class" && len(out.Owners) != 0 {
				t.Fatal("deadline retained owners", out)
			}
			if mode == "other-class" && out.SocketIssues["socket:[1]"] == "" {
				t.Fatal("coholder failure lost", out)
			}
		})
	}
}

package identity

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Checks real per-thread proc facts and the shared caller, not packet delivery.
func TestHolderIdentityRealTopologies(t *testing.T) {
	if os.Getenv("FLOWGATE_PARENT_NETNS") == "" || os.Getenv("FLOWGATE_PARENT_NETNS") == NetNS() {
		t.Skip("private lab namespace required")
	}
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	bins := []string{filepath.Join(dir, "alpha"), filepath.Join(dir, "beta")}
	for _, bin := range bins {
		if b, err := exec.Command(cc, "-O2", "-pthread", "../../fixtures/ownership/holder-census.c", "-o", bin).CombinedOutput(); err != nil {
			t.Fatalf("%s: %v", b, err)
		}
	}
	for _, mode := range []string{"control", "exit-shared", "exit-split", "private-live"} {
		for _, family := range []string{"4", "6"} {
			for _, proto := range []string{"tcp", "udp"} {
				t.Run(mode+proto+family, func(t *testing.T) {
					var keys []string
					for _, bin := range bins {
						f := startHolderFixture(t, bin, mode, family, proto)
						c := CensusHolders(map[string]bool{f.socket: true})
						out := inspectHolderIdentities(c, Inspect)
						ps := out.Owners[f.socket]
						if !out.Complete || len(ps) != 1 {
							t.Fatalf("%+v / %+v", c.Issues, out)
						}
						p := ps[0]
						keys = append(keys, p.Application.Key)
						if p.Application.Executable != bin || p.Application.Kind != "native" || p.ThreadGroup != f.tgid {
							t.Fatalf("wrong identity %+v", p)
						}
						if mode == "control" {
							if p.PID != f.tgid || p.HolderWitness != "" {
								t.Fatal("leader changed")
							}
						} else {
							if p.PID == f.tgid || p.HolderWitness == "" {
								t.Fatal("worker evidence missing")
							}
							if _, err := BindInstance("session", p); err == nil {
								t.Fatal("worker became process instance")
							}
						}
						sockets, err := Sockets()
						if err != nil {
							t.Fatal(err)
						}
						found := false
						for _, s := range sockets {
							if fmt.Sprintf("socket:[%d]", s.Inode) != f.socket {
								continue
							}
							found = true
							flow := Flow{Protocol: proto, Direction: "incoming", Local: s.Local, Remote: s.Local, NetNS: NetNS()}
							a := Resolve(flow)
							if a.Application == nil || a.Application.Key != p.Application.Key || !a.VisibilityComplete || len(a.Owners) != 1 {
								t.Fatalf("Resolve disagreement: %+v", a)
							}
						}
						if !found {
							t.Fatal("socket not observed")
						}
					}
					if keys[0] == keys[1] {
						t.Fatal("independent executable identities merged")
					}
				})
			}
		}
	}
}

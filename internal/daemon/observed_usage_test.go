package daemon

import (
	"flowgate/internal/accounting"
	"flowgate/internal/identity"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func usageFixture(uid uint32) *accounting.Ledger {
	l := accounting.New()
	at := time.Now().Add(-time.Second)
	s := identity.ActivitySnapshot{Sequence: 1, Collected: at, Complete: true, Processes: map[string]identity.ActivityProcess{}}
	for _, owner := range []uint32{uid, uid + 1} {
		id := string(rune('a' + owner - uid))
		p := identity.ActivityProcess{ID: id, UID: owner, PID: 1, Start: "start", BootID: "boot", NetNS: "net", ExecutableRevision: "rev", Application: identity.Application{Kind: "native", Key: id, Revision: "rev", Name: id}}
		s.Processes[id] = p
		s.Rows = append(s.Rows, identity.ActivityRow{Owners: []string{id}, OwnershipCategory: "visible-holder", Socket: identity.Socket{Cookie: id, NetNS: "net", Protocol: "tcp"}, Traffic: identity.Traffic{Available: true, Definition: accounting.TCP, Since: at}})
	}
	l.Observe(s)
	s.Sequence = 2
	s.Collected = at.Add(time.Second)
	for i := range s.Rows {
		s.Rows[i].Traffic.Uploaded = 9007199254740993
	}
	l.Observe(s)
	return l
}
func TestObservedUsageReadOnlyAPIProjection(t *testing.T) {
	uid := uint32(os.Getuid())
	for _, admin := range []bool{false, true} {
		t.Run(map[bool]string{false: "user", true: "admin"}[admin], func(t *testing.T) {
			if admin && uid != 0 {
				t.Skip("administrator endpoint requires root; exercised separately in private user namespace")
			}
			dir, err := os.MkdirTemp("../../.workspace/tmp", "usage-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(dir)
			e := New(time.Second)
			e.Mode = "daemon-monitor"
			e.ObservedUsage = usageFixture(uid)
			if admin {
				e.AdministratorUID = &uid
				e.APIUID = &uid
			}
			path, _ := filepath.Abs(filepath.Join(dir, "s"))
			listener, err := Serve(path, e, true)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			for i := 0; i < 3; i++ {
				r, err := Call(path, Request{Version: 1, Operation: "observed-usage", Scope: "machine"})
				if err != nil || r.ObservedUsage == nil || !r.ReadOnly || !slices.Contains(r.Capabilities, accounting.Capability) {
					t.Fatal(r, err)
				}
				v := r.ObservedUsage
				isAdmin := admin || uid == 0
				if isAdmin {
					if v.Scope != "machine" || len(v.Entries) != 2 || v.Unattributed == nil || v.Gaps == "" {
						t.Fatal(v)
					}
				} else {
					if v.Scope != "user" || len(v.Entries) != 1 || v.Entries[0].UID != uid || v.Unattributed != nil || v.Gaps != "" {
						t.Fatal(v)
					}
				}
				if v.Sequence != "2" || v.Entries[0].Uploaded != "9007199254740993" {
					t.Fatal("read altered totals", v)
				}
			}
			if _, err := Call(path, Request{Version: 1, Operation: "observed-usage-reset"}); err == nil {
				t.Fatal("reset accidentally exposed")
			}
		})
	}
}
func TestObservedUsageUnsupportedDaemon(t *testing.T) {
	dir, err := os.MkdirTemp("../../.workspace/tmp", "usage-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	e := New(time.Second)
	path, _ := filepath.Abs(filepath.Join(dir, "s"))
	l, err := Serve(path, e, true)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	r, err := Call(path, Request{Version: 1, Operation: "observed-usage"})
	if err == nil || r.ObservedUsage != nil || slices.Contains(r.Capabilities, accounting.Capability) {
		t.Fatal(r, err)
	}
}

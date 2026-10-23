package identity

import (
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDisplayApplicationKeepsSharedOwners(t *testing.T) {
	a := Application{Kind: "native", Key: "app", Revision: "revision"}
	p := map[string]ActivityProcess{"1:10": {UID: 1000, Application: a}, "2:20": {UID: 1000, Application: a}}
	r := ActivityRow{Ownership: "Shared socket", Owners: []string{"1:10", "2:20"}}
	if activityDisplayApplication(r, p) == nil || len(r.Owners) != 2 {
		t.Fatal("same application display grouping lost owners")
	}
	for _, change := range []string{"uid", "key", "revision", "runtime", "missing"} {
		copy := p["2:20"]
		switch change {
		case "uid":
			copy.UID++
		case "key":
			copy.Application.Key = "other"
		case "revision":
			copy.Application.Revision = "new"
		case "runtime":
			copy.Application.Kind = "wine"
		case "missing":
			copy.Application.Key = ""
		}
		p["2:20"] = copy
		if activityDisplayApplication(r, p) != nil {
			t.Fatalf("grouped %s", change)
		}
		p["2:20"] = ActivityProcess{UID: 1000, Application: a}
	}
	r.Ownership = "Owner changed during inspection"
	if activityDisplayApplication(r, p) != nil {
		t.Fatal("incomplete ownership grouped")
	}
}
func TestDescriptorCloseAndNumericReuse(t *testing.T) {
	old, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err = unix.Fstat(old, &st); err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf("/proc/self/fd/%d", old)
	if !activityDescriptorMatches(path, uint32(st.Ino)) {
		t.Fatal("live FD rejected")
	}
	// Replace exactly the old numeric FD using dup3; no probabilistic reuse claim.
	other, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(other)
	if err = unix.Dup3(other, old, unix.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	defer unix.Close(old)
	if activityDescriptorMatches(path, uint32(st.Ino)) {
		t.Fatal("reused FD retained old socket association")
	}
}
func TestActivityCacheChecksUIDAndNamespaces(t *testing.T) {
	c := ActivityCollector{cache: map[int]cachedActivityProcess{}}
	now := time.Now()
	pid := os.Getpid()
	p, err := c.inspect(pid, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"uid", "netns", "mountns"} {
		bad := c.cache[pid]
		switch field {
		case "uid":
			bad.process.UID++
		case "netns":
			bad.process.NetNS = "different"
		case "mountns":
			bad.process.MountNS = "different"
		}
		c.cache[pid] = bad
		got, err := c.inspect(pid, now)
		if err != nil || got.UID != p.UID || got.NetNS != p.NetNS || got.MountNS != p.MountNS {
			t.Fatalf("stale %s cache: %v", field, err)
		}
	}
}
func TestLeaderStateAndCategory(t *testing.T) {
	// No private metadata; minimal stat input exercises a comm containing ')'.
	dir := t.TempDir()
	for _, state := range []string{"S", "Z"} {
		os.WriteFile(filepath.Join(dir, "stat"), []byte("1 (name) with parens) "+state+" 0"), 0600)
		if activityLeaderExited(dir) != (state == "Z") {
			t.Fatal(state)
		}
	}
	if activityOwnershipCategory(ActivityRow{Ownership: "Unknown owner"}) != "unknown" {
		t.Fatal("guessed unknown cause")
	}
}
func TestOwnerlessStateDoesNotInheritDisplayIdentity(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c := ActivityCollector{}
	before := c.Collect()
	var id string
	for _, r := range before.Rows {
		if r.Socket.Local.String() == l.Addr().String() && r.Socket.State == 10 {
			id = r.ID
			if len(r.Owners) == 0 {
				t.Fatal("listener unowned")
			}
		}
	}
	if id == "" {
		t.Fatal("listener absent")
	}
	l.Close()
	after := c.Collect()
	for _, r := range after.Rows {
		if r.ID == id {
			t.Fatal("closed socket retained")
		}
	}
}

func TestMappedIPv6OwnershipUsesSocketIdentity(t *testing.T) {
	l, err := net.Listen("tcp", "[::]:0")
	if err != nil {
		t.Skip(err)
	}
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port
	client, err := net.Dial("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	accepted, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()
	s := (&ActivityCollector{}).Collect()
	found := false
	for _, r := range s.Rows {
		if r.Socket.Family != unix.AF_INET6 || r.Socket.State != 1 || int(r.Socket.Local.Port()) != port {
			continue
		}
		if !r.Socket.Local.Addr().Is4() {
			t.Fatal("mapped IPv6 address not unmapped")
		}
		if len(r.Owners) != 1 || s.Processes[r.Owners[0]].PID != os.Getpid() {
			t.Fatalf("mapped socket lost FD owner: complete=%v issues=%v row=%+v processes=%+v", s.Complete, s.Issues, r, s.Processes)
		}
		found = true
	}
	if !found {
		t.Fatal("mapped accepted socket missing")
	}
}

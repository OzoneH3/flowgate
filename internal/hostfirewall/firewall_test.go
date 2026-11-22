package hostfirewall

import (
	"flowgate/internal/daemon"
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStateSaveAfterInterruptedWrite(t *testing.T) {
	if parent := os.Getenv("FLOWGATE_PARENT_NETNS"); parent == "" || parent == identity.NetNS() {
		t.Skip("private lab namespace required")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	owner, err := lock(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	check := func(want string) {
		t.Helper()
		got, err := Read(dir)
		if err != nil || got.State != want || got.Token != strings.Repeat("a", 32) {
			t.Fatalf("reopened record %+v (%v), want %s", got, err, want)
		}
		t.Logf("reopened %s (%s)", got.State, got.Token)
	}
	record := Record{Token: strings.Repeat("a", 32), NetNS: identity.NetNS(), State: "active"}
	if err := save(dir, record); err != nil {
		t.Fatal(err)
	}
	// Model remnants left by an interrupted legacy writer, an interrupted
	// unique staging write, and a file outside the writer's ownership.
	files := map[string]string{"instance.json.new": "{", ".instance-interrupted": "{", "unrelated": "keep"}
	for name, contents := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	check("active")
	for _, state := range []string{"degraded", "stopped"} {
		record.State = state
		if err := save(dir, record); err != nil {
			t.Fatal(err)
		}
		check(state)
	}
	for name, want := range files {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || string(got) != want {
			t.Fatalf("preserved file %s = %q (%v), want %q", name, got, err, want)
		}
	}
}

func TestProfileShape(t *testing.T) {
	r := profileRules(strings.Repeat("a", 32), "incoming", policy.BootstrapInterface{Name: "test0", IPv4: true, IPv6: true})
	for _, bad := range []string{"flush", "bypass", "hook forward", "ct state established,related accept"} {
		if strings.Contains(r, bad) {
			t.Fatalf("unsafe profile %s", bad)
		}
	}
	for _, required := range []string{"queue num 101", "hook input priority 11", "ct mark set ct mark | 0x10000000", "ct direction reply ct mark & 0x30000000", "tcp flags & (syn | ack) == syn jump inspect", "meta nfproto ipv4 udp sport 67 udp dport 68", "ip6 saddr fe80::/10 udp sport 547 udp dport 546"} {
		if !strings.Contains(r, required) {
			t.Fatal("missing", required)
		}
	}
	// NF_ACCEPT resumes at the next base hook, not at the next nft rule.
	if strings.Contains(r, "inspect ct mark") {
		t.Fatal("approval mark must live in a later base hook")
	}
}
func TestPrivilegedPathRejectsSymlinkAndWritableDirectory(t *testing.T) {
	dir, err := os.MkdirTemp("../../.workspace/tmp", "host-path-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	real := filepath.Join(dir, "real")
	os.Mkdir(real, 0700)
	link := filepath.Join(dir, "link")
	os.Symlink(real, link)
	if err = daemon.SecureDirectory(link); err == nil {
		t.Fatal("symlink accepted")
	}
	os.Chmod(real, 0777)
	if err = daemon.SecureDirectory(real); err == nil {
		t.Fatal("writable directory accepted")
	}
}

package hostfirewall

import (
	"flowgate/internal/daemon"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProfileShape(t *testing.T) {
	r := rules(strings.Repeat("a", 32))
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

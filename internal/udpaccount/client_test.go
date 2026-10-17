package udpaccount

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnavailableNeverBreaksBasicObservation(t *testing.T) {
	c := &Client{Path: filepath.Join(t.TempDir(), "absent")}
	u := c.Snapshot()
	if u.State != "unavailable" || u.Reason == "" {
		t.Fatal(u)
	}
	c.seen = true
	u = c.Snapshot()
	if u.State != "disconnected" {
		t.Fatal(u)
	}
	_, err := Request(c.Path, "stop")
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}
func TestRejectUnprivilegedLoader(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires unprivileged process")
	}
	// The public command is tested separately inside the namespace; package guard
	// must refuse before any helper execution or API socket creation.
	err := Run(context.Background(), filepath.Join(t.TempDir(), "api.sock"), "nonexistent", uint32(os.Getuid()))
	if err == nil || !strings.Contains(err.Error(), "requires privileged") {
		t.Fatal(err)
	}
}

func TestClientRejectsUserOwnedImpersonator(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("non-root peer required")
	}
	path := filepath.Join(t.TempDir(), "rogue.sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, e := l.Accept()
		if e == nil {
			defer c.Close()
			c.Write([]byte("{\"version\":1,\"state\":\"active\"}\n"))
		}
	}()
	if _, err = Request(path, "list"); err == nil || !strings.Contains(err.Error(), "not owned") {
		t.Fatal("untrusted source accepted", err)
	}
	<-done
}

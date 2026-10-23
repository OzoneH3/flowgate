package daemon

import (
	"flowgate/internal/readiness"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRuntimeFailureKeepsReadOnlyAPIAvailable(t *testing.T) {
	e := New(time.Second)
	e.RuntimeChecks = func() []readiness.Check {
		return []readiness.Check{{ID: "runtime.wine_unix_peers", Status: readiness.Optional, Code: "unix_peer_probe_failed"}}
	}
	dir, err := os.MkdirTemp("../../.workspace/tmp", "health-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path, err := filepath.Abs(filepath.Join(dir, "api.sock"))
	if err != nil {
		t.Fatal(err)
	}
	server, err := Serve(path, e, true)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	response, err := Call(path, Request{Version: 1, Operation: "list"})
	if err != nil || response.Error != "" || len(response.RuntimeChecks) != 1 || response.RuntimeChecks[0].Status != readiness.Optional {
		t.Fatalf("API unavailable or health omitted: %+v, %v", response, err)
	}
	if len(e.rules) != 0 {
		t.Fatal("health probe changed policy")
	}
}

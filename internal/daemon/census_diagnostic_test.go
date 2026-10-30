package daemon

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiagnosticAPIReadOnlyGenerationAndUnarmed(t *testing.T) {
	dir, err := os.MkdirTemp("../../.workspace/tmp", "diag-api-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	e, _, _, _ := fixture()

	for _, ro := range []bool{true, false} {
		path, _ := filepath.Abs(filepath.Join(dir, "s"))
		srv, err := Serve(path, e, ro)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Call(path, Request{Version: 1, Operation: "diagnostic-status", Generation: "stale"}); err == nil {
			t.Fatal("stale accepted")
		}
		r, err := Call(path, Request{Version: 1, Operation: "diagnostic-status", Generation: e.Generation})
		if os.Getuid() != 0 {
			if err == nil {
				t.Fatal("ordinary peer saw private status")
			}
			srv.Close()
			continue
		}
		if err != nil || r.Diagnostic["state"] != "disabled" {
			t.Fatal(r, err)
		}
		if _, err := Call(path, Request{Version: 1, Operation: "diagnostic-start", Generation: e.Generation}); err == nil {
			t.Fatal("unarmed/readonly accepted")
		}
		srv.Close()
	}
}

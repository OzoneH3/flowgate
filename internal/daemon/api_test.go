package daemon

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadOnlyAPI(t *testing.T) {
	dir, err := os.MkdirTemp("../../.workspace/tmp", "api-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path, _ := filepath.Abs(filepath.Join(dir, "s"))
	e, _, _, _ := fixture()
	l, err := Serve(path, e, true)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if _, err = Call(path, Request{Version: 1, Operation: "list"}); err != nil {
		t.Fatal(err)
	}
	if _, err = Call(path, Request{Version: 1, Operation: "decide", ID: "fake", Action: "allow", Scope: "once"}); err == nil {
		t.Fatal("read-only endpoint allowed mutation")
	}
	if _, err = Call(path, Request{Version: 2, Operation: "list"}); err == nil {
		t.Fatal("unsupported API accepted")
	}
}

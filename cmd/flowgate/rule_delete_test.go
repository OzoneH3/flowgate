package main

import (
	"bytes"
	"flowgate/internal/daemon"
	"flowgate/internal/policy"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type confirmReader struct {
	before func()
	done   bool
}

func (r *confirmReader) Read(b []byte) (int, error) {
	if !r.done {
		r.before()
		r.done = true
	}
	return copy(b, "y\n"), nil
}
func TestDeleteCLIUsesDisplayedVersion(t *testing.T) {
	dir, err := os.MkdirTemp("../../.workspace/tmp", "cli-delete-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	dir, _ = filepath.Abs(dir)
	e := daemon.New(time.Second)
	e.SaveRules = func([]policy.Rule) error { return nil }
	rule := policy.Rule{ID: "cli-rule", Schema: 2, Version: 1, Created: time.Now(), Action: "allow", Filter: policy.Filter{Application: "app", Revision: "rev", UID: uint32(os.Getuid()), Direction: "incoming", Protocol: "udp", LocalPort: 5555, RemoteAddress: "127.0.0.1"}}
	if err = e.SetRules([]policy.Rule{rule}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "s")
	l, err := daemon.Serve(path, e, false)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	var out bytes.Buffer
	input := &confirmReader{before: func() {
		version := rule.Version
		changed := rule
		changed.Action = "block"
		if _, _, err := e.EditRule(rule.ID, "", &version, changed, uint32(os.Getuid()), false, true); err != nil {
			t.Fatal(err)
		}
	}}
	err = deleteRuleCLI([]string{"--socket", path, "--id", rule.ID}, input, &out)
	if err == nil || !strings.Contains(err.Error(), "version_conflict") || !strings.Contains(out.String(), `"version": 1`) {
		t.Fatal(out.String(), err)
	}
	rs := e.Rules(0, true)
	if len(rs) != 1 || rs[0].Action != "block" || rs[0].Version != 2 {
		t.Fatal(rs)
	}
	out.Reset()
	if err = deleteRuleCLI([]string{"--socket", path, "--id", rule.ID}, strings.NewReader("n\n"), &out); err == nil || len(e.Rules(0, true)) != 1 {
		t.Fatal("cancel deleted rule", err)
	}
	out.Reset()
	if err = deleteRuleCLI([]string{"--socket", path, "--id", rule.ID, "--yes"}, strings.NewReader(""), &out); err != nil || len(e.Rules(0, true)) != 0 {
		t.Fatal(out.String(), err)
	}
}

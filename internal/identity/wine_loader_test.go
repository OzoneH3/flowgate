package identity

import (
	"os"
	"path/filepath"
	"testing"
)

func TestObserverRequiresDirectLoader(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	if err := os.MkdirAll(bin, 0700); err != nil {
		t.Fatal(err)
	}
	// Never silently fall back to the generic dispatcher, even if executable.
	if err := os.WriteFile(filepath.Join(bin, "wine"), []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := observerRunner(bin); err == nil {
		t.Fatal("accepted dispatcher without direct loader")
	}
	direct := filepath.Join(root, "lib/wine/x86_64-unix/wine")
	if err := os.MkdirAll(filepath.Dir(direct), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(direct, []byte("not ELF"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := observerRunner(bin); err == nil {
		t.Fatal("accepted malformed direct loader")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(direct, data, 0700); err != nil {
		t.Fatal(err)
	}
	got, err := observerRunner(bin)
	if err != nil || got != direct {
		t.Fatalf("direct loader %q: %v", got, err)
	}
}

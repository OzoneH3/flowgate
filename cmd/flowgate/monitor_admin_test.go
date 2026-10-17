package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrepareMonitorDirectoryPreservesUnsafePaths(t *testing.T) {
	// Unprivileged /home ancestors fail the privileged path validation. Neither
	// existing contents nor symlinks may be repaired by setup on refusal.
	dir := t.TempDir()
	sentinel := filepath.Join(dir, "sentinel")
	if err := os.WriteFile(sentinel, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(dir)
	if _, err := prepareMonitorDirectory(dir, 0711); err == nil {
		t.Fatal("unsafe ancestor/path accepted")
	}
	after, _ := os.Stat(dir)
	b, _ := os.ReadFile(sentinel)
	if string(b) != "preserve" || before.Mode() != after.Mode() {
		t.Fatal("setup changed existing data/permissions")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareMonitorDirectory(link, 0711); err == nil {
		t.Fatal("symlink accepted")
	}
}
func TestMonitorSetupRejectsPathsAndOrdinaryUser(t *testing.T) {
	if err := monitorSetupCommand([]string{"/tmp/elsewhere"}); err == nil {
		t.Fatal("setup accepted arbitrary path")
	}
	if os.Geteuid() != 0 {
		if err := monitorSetupCommand(nil); err == nil {
			t.Fatal("ordinary setup accepted")
		}
		if err := monitorStopCommand([]string{"--generation", "old"}); err == nil {
			t.Fatal("ordinary shutdown accepted")
		}
	}
}

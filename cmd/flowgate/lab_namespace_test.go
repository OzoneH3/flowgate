package main

import (
	"os"
	"testing"
)

func TestRootLabCannotUseCurrentNamespaces(t *testing.T) {
	if err := isolatedRootLab(-1, -1); err == nil {
		t.Fatal("missing descriptors accepted")
	}
	pid, err := os.Open("/proc/self/ns/pid")
	if err != nil {
		t.Fatal(err)
	}
	defer pid.Close()
	mnt, err := os.Open("/proc/self/ns/mnt")
	if err != nil {
		t.Fatal(err)
	}
	defer mnt.Close()
	if err = isolatedRootLab(int(pid.Fd()), int(mnt.Fd())); err == nil {
		t.Fatal("current namespaces accepted")
	}
}

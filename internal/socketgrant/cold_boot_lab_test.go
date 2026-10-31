//go:build socketprototype

package socketgrant

import (
	"errors"
	"os"
	"os/exec"
	"testing"

	"golang.org/x/sys/unix"
)

// This probe intentionally changes module state, so it runs only in the
// disposable guest whose fresh boot ID the outer runner verifies.
func TestColdBootINETMatchDependency(t *testing.T) {
	if os.Getenv("FLOWGATE_DISPOSABLE_VM") != "1" {
		t.Skip("disposable VM only; never load modules on the development host")
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || string(boot) == os.Getenv("FLOWGATE_PARENT_BOOT_ID") || os.Getenv("FLOWGATE_PARENT_BOOT_ID") == "" {
		t.Fatal("independent guest boot not established", err)
	}
	if _, err := os.Stat("/sys/module/xt_bpf"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cold-boot prerequisite: xt_bpf must be absent", err)
	}
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("%v: %v %s", args, err, out)
		}
	}
	run("ip", "link", "set", "lo", "up")
	run("nft", "add", "table", "inet", "fg_coldboot")
	t.Cleanup(func() { run("nft", "delete", "table", "inet", "fg_coldboot") })
	run("nft", "add", "chain", "inet", "fg_coldboot", "socket_output")
	k, err := OpenRoutedKernel("fg_coldboot", "socket_output")
	if err != nil {
		t.Fatal("base program load", err)
	}
	err = k.AddInterface(1)
	if !errors.Is(err, unix.ENOENT) {
		_ = k.Close()
		t.Fatalf("without xt_bpf: got %v, want ENOENT", err)
	}
	if err := k.Close(); err != nil {
		t.Fatal("partial owner cleanup", err)
	}
	t.Log("cold INET installation refused with ENOENT; partial owner cleaned")
	run("modprobe", "xt_bpf")
	k, err = OpenRoutedKernel("fg_coldboot", "socket_output")
	if err != nil {
		t.Fatal(err)
	}
	if err := k.AddInterface(1); err != nil {
		_ = k.Close()
		t.Fatal("after explicit dependency load", err)
	}
	if err := k.Close(); err != nil {
		t.Fatal("successful owner cleanup", err)
	}
	t.Log("same INET installation succeeds after explicit xt_bpf load")
	run("modprobe", "-r", "xt_bpf")
	if _, err := os.Stat("/sys/module/xt_bpf"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("GET probe requires unloaded match", err)
	}
	if err := EnsureBPFMatch(); err != nil {
		t.Fatal("standard IPv4 match query", err)
	}
	if _, err := os.Stat("/sys/module/xt_bpf"); err != nil {
		t.Fatal("GET did not load required match", err)
	}
	k, err = OpenRoutedKernel("fg_coldboot", "socket_output")
	if err != nil {
		t.Fatal(err)
	}
	if err := k.AddInterface(1); err != nil {
		_ = k.Close()
		t.Fatal("after standard GET", err)
	}
	if err := k.Close(); err != nil {
		t.Fatal(err)
	}
	t.Log("standard IPv4 compatibility GET loaded match; real INET installation and cleanup succeeded")
}

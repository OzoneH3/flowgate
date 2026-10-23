package identity

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

type holderFixtureProc struct {
	cmd                    *exec.Cmd
	stdin                  io.WriteCloser
	socket                 string
	tgid, worker0, worker1 int
}

func startHolderFixture(t *testing.T, bin, mode, family, proto string) holderFixtureProc {
	t.Helper()
	cmd := exec.Command(bin, mode, family, proto)
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	f := holderFixtureProc{cmd: cmd, stdin: stdin}
	t.Cleanup(func() { stdin.Close(); cmd.Process.Kill(); cmd.Wait() })
	line, err := bufio.NewReader(stdout).ReadString('\n')
	var inode uint64
	if err != nil {
		t.Fatal(err)
	}
	if _, err = fmt.Sscanf(line, "READY %d %d %d %d", &inode, &f.tgid, &f.worker0, &f.worker1); err != nil {
		t.Fatal(line, err)
	}
	f.socket = fmt.Sprintf("socket:[%d]", inode)
	if strings.HasPrefix(mode, "exit-") {
		// The leader's pthread_exit is asynchronous; wait for the evidenced Z state.
		deadline := time.Now().Add(5 * time.Second)
		for !activityLeaderExited(fmt.Sprintf("/proc/%d", f.tgid)) {
			if time.Now().After(deadline) {
				t.Fatal("leader did not exit")
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	return f
}

// Real processes and sockets in the disposable lab namespace only: the census
// scans every visible thread group, so it never runs against the host here.
func TestHolderCensusRealTopologies(t *testing.T) {
	if os.Getenv("FLOWGATE_PARENT_NETNS") == "" || os.Getenv("FLOWGATE_PARENT_NETNS") == NetNS() {
		t.Skip("private lab namespace required")
	}
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("C compiler unavailable")
	}
	dir := t.TempDir()
	bins := []string{filepath.Join(dir, "a", "holder-census"), filepath.Join(dir, "b", "holder-census")}
	for _, bin := range bins {
		os.MkdirAll(filepath.Dir(bin), 0700)
		if b, err := exec.Command(cc, "-Wall", "-Wextra", "-O2", "-pthread", "../../fixtures/ownership/holder-census.c", "-o", bin).CombinedOutput(); err != nil {
			t.Fatalf("%s %v", b, err)
		}
	}
	for _, mode := range []string{"control", "exit-shared", "exit-split", "private-live"} {
		for _, family := range []string{"4", "6"} {
			for _, proto := range []string{"tcp", "udp"} {
				t.Run(mode+"/"+proto+family, func(t *testing.T) {
					f := startHolderFixture(t, bins[0], mode, family, proto)
					c := CensusHolders(map[string]bool{f.socket: true})
					if !c.Complete {
						t.Fatal(c.Issues)
					}
					var got [][]int
					for _, h := range c.Holders {
						if h.TGID != f.tgid || h.Socket != f.socket || !h.Proven || h.LeaderExited != strings.HasPrefix(mode, "exit-") {
							t.Fatalf("unexpected holder %+v", h)
						}
						var tids []int
						for _, m := range h.Members {
							if m.Start == "" {
								t.Fatalf("member without start %+v", h)
							}
							tids = append(tids, m.TID)
						}
						got = append(got, tids)
					}
					want := map[string][][]int{
						"control":      {{f.tgid, f.worker0, f.worker1}},
						"exit-shared":  {{f.worker0, f.worker1}},
						"exit-split":   {{f.worker0}, {f.worker1}},
						"private-live": {{f.worker0}},
					}[mode]
					slices.SortFunc(got, func(a, b []int) int { return a[0] - b[0] })
					if !slices.EqualFunc(got, want, slices.Equal[[]int]) {
						t.Fatalf("holders %v, want %v", got, want)
					}
					if err := c.Recheck(); err != nil {
						t.Fatal(err)
					}
				})
			}
		}
	}
	// Two distinct executables, each with an exited leader: their tables and
	// sockets are reported separately; identity remains the caller's decision.
	t.Run("two executables", func(t *testing.T) {
		a := startHolderFixture(t, bins[0], "exit-shared", "4", "udp")
		b := startHolderFixture(t, bins[1], "exit-shared", "6", "tcp")
		c := CensusHolders(map[string]bool{a.socket: true, b.socket: true})
		if !c.Complete || len(c.Holders) != 2 || c.Recheck() != nil {
			t.Fatal(c.Complete, c.Issues, c.Holders)
		}
		for _, h := range c.Holders {
			want := map[string]int{a.socket: a.tgid, b.socket: b.tgid}[h.Socket]
			if h.TGID != want {
				t.Fatalf("socket %s reported under %d, want %d", h.Socket, h.TGID, want)
			}
		}
	})
	// A real topology change after the census refuses Recheck: closing stdin
	// ends the group, so the holder group is gone.
	t.Run("recheck after exit", func(t *testing.T) {
		f := startHolderFixture(t, bins[0], "exit-shared", "4", "tcp")
		c := CensusHolders(map[string]bool{f.socket: true})
		if !c.Complete || len(c.Holders) != 1 {
			t.Fatal(c.Issues, c.Holders)
		}
		f.stdin.Close()
		f.cmd.Wait()
		if err := c.Recheck(); err == nil || err.Error() != "group_changed" {
			t.Fatalf("recheck after exit: %v", err)
		}
	})
}

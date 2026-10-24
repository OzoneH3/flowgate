package identity

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Real processes, real descriptor tables, real SCM_RIGHTS transfers in the
// disposable lab namespace only. The churn fixture changes topology solely on
// command, so each change is placed deterministically between the census and
// the recheck (or, for repeated churn, inside the re-verification).
type churnFixture struct {
	cmd    *exec.Cmd
	in     io.WriteCloser
	out    *bufio.Reader
	socket string
	tgid   int
	worker int
}

// Every fixture read is bounded: a command that does not acknowledge within
// churnDeadline kills the fixture so the blocked read returns and cleanup can
// run; stderr stays attached for the failure report.
const churnDeadline = 30 * time.Second

func startChurnFixture(t *testing.T, bin string, args ...string) *churnFixture {
	t.Helper()
	cmd := exec.Command(bin, args...)
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	f := &churnFixture{cmd: cmd, in: in, out: bufio.NewReader(stdout)}
	t.Cleanup(func() { in.Close(); cmd.Process.Kill(); cmd.Wait() })
	var inode uint64
	line := f.line(t)
	if _, err := fmt.Sscanf(line, "READY %d %d %d", &inode, &f.tgid, &f.worker); err != nil {
		t.Fatal(line, err)
	}
	if inode != 0 {
		f.socket = fmt.Sprintf("socket:[%d]", inode)
	}
	return f
}

func (f *churnFixture) line(t *testing.T) string {
	t.Helper()
	type result struct {
		line string
		err  error
	}
	done := make(chan result, 1)
	go func() {
		line, err := f.out.ReadString('\n')
		done <- result{line, err}
	}()
	timer := time.NewTimer(churnDeadline)
	defer timer.Stop()
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("fixture %s (pid %d): %v", f.cmd.Path, f.tgid, r.err)
		}
		return strings.TrimSpace(r.line)
	case <-timer.C:
		f.cmd.Process.Kill()
		r := <-done
		t.Fatalf("fixture %s (pid %d) did not answer within %v (read: %q, %v)", f.cmd.Path, f.tgid, churnDeadline, strings.TrimSpace(r.line), r.err)
		return ""
	}
}

// received waits for the receiver thread's RECEIVED line and verifies that the
// transferred descriptor is exactly the holder's socket.
func (f *churnFixture) received(t *testing.T, socket string) int {
	t.Helper()
	line := f.line(t)
	var inode uint64
	var tid int
	if _, err := fmt.Sscanf(line, "RECEIVED %d %d", &inode, &tid); err != nil || fmt.Sprintf("socket:[%d]", inode) != socket {
		t.Fatalf("%q (want %s): %v", line, socket, err)
	}
	return tid
}

// command sends one line and returns the acknowledgement, which must start
// with want; the fixture has completed the change when the line arrives.
func (f *churnFixture) command(t *testing.T, cmd, want string) int {
	t.Helper()
	if _, err := io.WriteString(f.in, cmd+"\n"); err != nil {
		t.Fatal(err)
	}
	line := f.line(t)
	if !strings.HasPrefix(line, want) {
		t.Fatalf("%q: %q", cmd, line)
	}
	var tid int
	fmt.Sscanf(strings.TrimPrefix(line, want), "%d", &tid)
	return tid
}

func realDescriptor(path, socket string) bool {
	target, err := os.Readlink(path)
	return err == nil && target == socket
}

// observe runs census → inspection → recheck like resolveHolderIdentities, with
// between executed exactly after inspection and before the recheck, and facts
// optionally wrapped to inject churn during re-verification.
func observeChurn(socket string, between func(), facts func(Holder, HolderMember) (holderTaskFacts, error)) (HolderCensus, holderIdentities) {
	c := CensusHolders(map[string]bool{socket: true})
	if facts == nil {
		facts = readHolderFacts
	}
	out := inspectHolderIdentitiesWith(c, Inspect, facts, realDescriptor, func() HolderRecheck {
		if between != nil {
			between()
		}
		return c.RecheckDetail()
	})
	return c, out
}

func censusMembers(t *testing.T, socket string, tgid int) []int {
	t.Helper()
	c := CensusHolders(map[string]bool{socket: true})
	if !c.Complete || c.Recheck() != nil {
		t.Fatalf("settled census incomplete: %v", c.Issues)
	}
	var tids []int
	for _, h := range c.Holders {
		if h.TGID == tgid {
			for _, m := range h.Members {
				tids = append(tids, m.TID)
			}
		}
	}
	return tids
}

func TestHolderChurnRealTopologies(t *testing.T) {
	if os.Getenv("FLOWGATE_PARENT_NETNS") == "" || os.Getenv("FLOWGATE_PARENT_NETNS") == NetNS() {
		t.Skip("private lab namespace required")
	}
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("C compiler unavailable")
	}
	dir := t.TempDir()
	// Two distinct executables (separate directories, same source) so a
	// transfer between them is a transfer between two synthetic applications.
	alpha, beta := filepath.Join(dir, "alpha", "churn"), filepath.Join(dir, "beta", "churn")
	for _, bin := range []string{alpha, beta} {
		os.MkdirAll(filepath.Dir(bin), 0700)
		if b, err := exec.Command(cc, "-Wall", "-Wextra", "-O2", "-pthread", "../../fixtures/ownership/churn.c", "-o", bin).CombinedOutput(); err != nil {
			t.Fatalf("%s %v", b, err)
		}
	}
	expectOwner := func(t *testing.T, out holderIdentities, f *churnFixture, bin string, reconciled int) {
		t.Helper()
		ps := out.Owners[f.socket]
		if !out.Complete || len(out.Issues) != 0 || len(out.SocketIssues) != 0 || out.Reconciled != reconciled || len(ps) != 1 {
			t.Fatalf("reconciled=%d %+v", out.Reconciled, out)
		}
		if ps[0].PID != f.tgid || ps[0].ThreadGroup != f.tgid || ps[0].Application.Executable != bin || ps[0].Application.Kind != "native" || ps[0].HolderWitness != "" {
			t.Fatalf("owner %+v", ps[0])
		}
	}
	expectRefused := func(t *testing.T, out holderIdentities, socket string, codes ...string) {
		t.Helper()
		if out.Complete || out.Reconciled != 0 || len(out.Owners[socket]) != 0 {
			t.Fatalf("%+v", out)
		}
		got := out.SocketIssues[socket]
		for _, c := range codes {
			if got == c {
				return
			}
		}
		t.Fatalf("socket code %q, want one of %v (issues %v)", got, codes, out.Issues)
	}
	for _, family := range []string{"4", "6"} {
		for _, proto := range []string{"tcp", "udp"} {
			t.Run("join/"+proto+family, func(t *testing.T) {
				f := startChurnFixture(t, alpha, family, proto)
				var joined int
				_, out := observeChurn(f.socket, func() { joined = f.command(t, "join", "JOINED ") }, nil)
				expectOwner(t, out, f, alpha, 1)
				tids := censusMembers(t, f.socket, f.tgid)
				if len(tids) != 3 || !contains(tids, joined) || !contains(tids, f.worker) || !contains(tids, f.tgid) {
					t.Fatalf("settled members %v (joined %d)", tids, joined)
				}
			})
			t.Run("leave/"+proto+family, func(t *testing.T) {
				f := startChurnFixture(t, alpha, family, proto)
				joined := f.command(t, "join", "JOINED ")
				var left int
				_, out := observeChurn(f.socket, func() { left = f.command(t, "leave", "LEFT ") }, nil)
				if left != joined {
					t.Fatalf("left %d, joined %d", left, joined)
				}
				expectOwner(t, out, f, alpha, 1)
				if tids := censusMembers(t, f.socket, f.tgid); len(tids) != 2 || contains(tids, left) {
					t.Fatalf("settled members %v", tids)
				}
			})
		}
	}
	t.Run("repeated churn fails bounded, then settles", func(t *testing.T) {
		f := startChurnFixture(t, alpha, "4", "tcp")
		var first, second int
		fired := false
		facts := func(h Holder, m HolderMember) (holderTaskFacts, error) {
			// Another task joins while the fresh members are being read.
			if m.TID == first && !fired {
				fired = true
				second = f.command(t, "join", "JOINED ")
			}
			return readHolderFacts(h, m)
		}
		_, out := observeChurn(f.socket, func() { first = f.command(t, "join", "JOINED ") }, facts)
		if !fired {
			t.Fatal("re-verification did not read the joined member")
		}
		expectRefused(t, out, f.socket, "membership_changed", "holder_appeared")
		if !out.retryTopology {
			t.Fatal("a pure topology failure must remain retryable")
		}
		// A fresh attempt without churn attributes all four members.
		_, settled := observeChurn(f.socket, nil, nil)
		expectOwner(t, settled, f, alpha, 0)
		if tids := censusMembers(t, f.socket, f.tgid); len(tids) != 4 || !contains(tids, first) || !contains(tids, second) {
			t.Fatalf("settled members %v", tids)
		}
	})
	t.Run("unshared private copy refuses", func(t *testing.T) {
		f := startChurnFixture(t, alpha, "4", "udp")
		_, out := observeChurn(f.socket, func() { f.command(t, "unshare", "UNSHARED ") }, nil)
		expectRefused(t, out, f.socket, "membership_changed", "holder_appeared")
	})
	t.Run("transfer to another executable with receiver topology change refuses", func(t *testing.T) {
		path := filepath.Join(dir, "recv.sock")
		f := startChurnFixture(t, alpha, "4", "tcp")
		r := startChurnFixture(t, beta, "recv", path)
		_, out := observeChurn(f.socket, func() {
			f.command(t, "join", "JOINED ") // alpha's own churn stays reconcilable
			r.command(t, "recv", "SPAWNED ") // beta gains a thread, then the descriptor
			f.command(t, "send "+path, "SENT")
			r.received(t, f.socket)
		}, nil)
		if out.Complete || out.SocketIssues[f.socket] != "holder_appeared" {
			t.Fatalf("%+v", out)
		}
		for _, p := range out.Owners[f.socket] {
			if p.ThreadGroup == r.tgid || p.Application.Executable == beta {
				t.Fatalf("receiver became an owner: %+v", p)
			}
		}
		// Settled: both executables hold the socket with complete evidence;
		// neither is its exclusive owner. An incomplete identity must not pass.
		c := CensusHolders(map[string]bool{f.socket: true})
		settled := inspectHolderIdentities(c, Inspect)
		if !c.Complete || !settled.Complete || len(settled.SocketIssues) != 0 || len(settled.Owners[f.socket]) != 2 {
			t.Fatalf("%v %+v", c.Issues, settled)
		}
		keys := map[string]bool{}
		for _, p := range settled.Owners[f.socket] {
			keys[p.Application.Key] = true
		}
		if len(keys) != 2 {
			t.Fatal("two executables must keep independent identities")
		}
	})
	t.Run("transfer without receiver topology change is not detected (documented snapshot boundary)", func(t *testing.T) {
		// holder_census.go: a descriptor passed later without a visible
		// topology change is a snapshot boundary. This records the limitation;
		// it must never be read as universal transfer detection.
		path := filepath.Join(dir, "recv-pre.sock")
		f := startChurnFixture(t, alpha, "4", "udp")
		r := startChurnFixture(t, beta, "recv-pre", path)
		_, out := observeChurn(f.socket, func() {
			f.command(t, "send "+path, "SENT")
			r.received(t, f.socket) // the transferred descriptor is exactly this socket
		}, nil)
		if !out.Complete || len(out.SocketIssues) != 0 || len(out.Owners[f.socket]) != 1 || out.Owners[f.socket][0].ThreadGroup != f.tgid {
			t.Fatalf("snapshot boundary changed: %+v", out)
		}
		// The next census sees both holders and withdraws exclusive ownership.
		c := CensusHolders(map[string]bool{f.socket: true})
		if !c.Complete || len(c.Holders) != 2 {
			t.Fatalf("%v %+v", c.Issues, c.Holders)
		}
	})
}

func contains(tids []int, tid int) bool {
	for _, t := range tids {
		if t == tid {
			return true
		}
	}
	return false
}

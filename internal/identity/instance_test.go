package identity

import (
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestPinnedProcessLifetime(t *testing.T) {
	c := exec.Command("/bin/sleep", "30")
	if e := c.Start(); e != nil {
		t.Fatal(e)
	}
	defer c.Process.Kill()
	p, e := Inspect(c.Process.Pid)
	if e != nil {
		t.Fatal(e)
	}
	b, e := BindInstance("session", p)
	if e != nil {
		t.Fatal(e)
	}
	b.ID = "0123456789abcdef0123456789abcdef"
	h, e := PinInstance(b)
	if e != nil {
		t.Fatal(e)
	}
	defer h.Close()
	if e = h.Check(); e != nil {
		t.Fatal(e)
	}
	// Simulated generation/namespace/exec changes; this is not an actual PID reuse.
	for _, kind := range []string{"start", "exe", "namespace", "uid", "thread"} {
		q := p
		switch kind {
		case "start":
			q.Start = "0"
		case "exe":
			q.ExecutableRevision = "new"
		case "namespace":
			q.NetNS = "other"
		case "uid":
			q.UID++
		case "thread":
			q.ThreadGroup++
		}
		if b.Matches(q) {
			t.Fatal(kind)
		}
	}
	c.Process.Kill()
	c.Wait()
	if e = h.Check(); e == nil {
		t.Fatal("exited pin live")
	}
	if e = h.Check(); e == nil {
		t.Fatal("retired pin revived")
	}
}
func TestPinnedDifferentExec(t *testing.T) {
	// The shell waits on a pipe then replaces itself; PID/start remain unchanged.
	c := exec.Command("/bin/sh", "-c", "read x; exec /bin/sleep 30")
	in, e := c.StdinPipe()
	if e != nil {
		t.Fatal(e)
	}
	if e = c.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { c.Process.Kill(); c.Wait() }()
	p, e := Inspect(c.Process.Pid)
	if e != nil {
		t.Fatal(e)
	}
	b, e := BindInstance("session", p)
	if e != nil {
		t.Fatal(e)
	}
	h, e := PinInstance(b)
	if e != nil {
		t.Fatal(e)
	}
	defer h.Close()
	in.Write([]byte("go\n"))
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if e = h.Check(); e != nil {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("exec did not invalidate", os.Getpid())
}

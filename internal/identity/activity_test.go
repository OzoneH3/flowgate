package identity

import (
	"os"
	"testing"
	"time"
)

func TestActivityStatesAndBounds(t *testing.T) {
	for _, tc := range []struct {
		proto        string
		state        uint8
		remote, want string
	}{
		{"tcp", 10, "127.0.0.1:0", "Listening"}, {"tcp", 2, "127.0.0.1:9", "Connecting (SYN sent)"}, {"tcp", 1, "127.0.0.1:9", "Established"},
		{"udp", 7, "127.0.0.1:0", "Bound/unconnected UDP socket"}, {"udp", 1, "127.0.0.1:9", "Connected UDP socket"},
	} {
		f, _ := ParseFlow(tc.proto, "incoming", "127.0.0.1:1", tc.remote)
		if got := SocketState(Socket{Protocol: tc.proto, State: tc.state, Remote: f.Remote}); got != tc.want {
			t.Fatal(got)
		}
	}
	if _, err := boundedDiag(nil, 0); err == nil {
		t.Fatal("unbounded dump accepted")
	}
}
func TestActivityCacheInvalidation(t *testing.T) {
	c := ActivityCollector{cache: map[int]cachedActivityProcess{}}
	pid := os.Getpid()
	now := time.Now()
	p, err := c.inspect(pid, now)
	if err != nil {
		t.Fatal(err)
	}
	old := c.cache[pid]
	old.process.Start = "wrong"
	c.cache[pid] = old
	next, err := c.inspect(pid, now)
	if err != nil || next.Start != p.Start {
		t.Fatal("PID reuse cache", err)
	}
	old = c.cache[pid]
	old.process.ExecutableRevision = "changed"
	c.cache[pid] = old
	next, err = c.inspect(pid, now)
	if err != nil || next.ExecutableRevision != p.ExecutableRevision {
		t.Fatal("executable cache", err)
	}
}

package daemon

import (
	"flowgate/internal/queuehealth"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestQueueHealthAPIProjection(t *testing.T) {
	e := New(time.Second)
	s := e.QueueHealth.Start(101, "both")
	s.Add(queuehealth.NetlinkOverflow)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "api.sock")
	server, err := Serve(path, e, true)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	r, err := Call(path, Request{Version: 1, Operation: "list"})
	if err != nil || r.Error != "" || r.QueueHealth == nil || r.QueueHealth.State != "pressure" {
		t.Fatal(r, err)
	}
	if e.administrator(uint32(os.Getuid())) {
		if len(r.QueueHealth.Sessions) != 1 || r.QueueHealth.Sessions[0].Counters["netlink_overflow_notifications"] != "1" {
			t.Fatal(r.QueueHealth)
		}
	} else if len(r.QueueHealth.Sessions) != 0 || r.QueueHealth.CounterUnits != nil {
		t.Fatal("machine queue telemetry leaked", r.QueueHealth)
	}
	if len(e.rules) != 0 {
		t.Fatal("diagnostics changed policy")
	}
}

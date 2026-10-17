package identity

import (
	"encoding/binary"
	"testing"
	"time"
)

func TestTCPInfoLengthAndOffsets(t *testing.T) {
	if parseTCPBytes(make([]byte, 207)) != nil {
		t.Fatal("short info fabricated counters")
	}
	b := make([]byte, 208)
	binary.NativeEndian.PutUint64(b[128:], 123)
	binary.NativeEndian.PutUint64(b[200:], 456)
	got := parseTCPBytes(b)
	if got.Downloaded != 123 || got.Uploaded != 456 {
		t.Fatal(got)
	}
}
func TestTrafficLifetimes(t *testing.T) {
	c := ActivityCollector{}
	now := time.Now()
	s := ActivitySnapshot{Rows: []ActivityRow{{ID: "cookie1", Socket: Socket{Protocol: "tcp", State: 1, Cookie: "cookie1", Counters: &TCPBytes{1000, 2000}}}}, Processes: map[string]ActivityProcess{}}
	sample := func(up, down uint64, dt time.Duration) Traffic {
		now = now.Add(dt)
		s.Rows[0].Socket.Counters = &TCPBytes{up, down}
		c.measure(&s, now)
		return s.Rows[0].Traffic
	}
	a := sample(1000, 2000, 0)
	if !a.Available || a.UploadRate != nil || a.Uploaded != 0 {
		t.Fatal(a)
	}
	a = sample(2000, 4000, time.Second)
	if *a.UploadRate != 1000 || *a.DownloadRate != 2000 || a.Uploaded != 1000 {
		t.Fatal(a)
	}
	a = sample(2000, 4000, time.Second)
	if *a.UploadRate != 0 {
		t.Fatal("idle", a)
	}
	s.Rows[0].Owners = []string{"pid:start"}
	a = sample(3000, 5000, time.Second)
	if a.Uploaded != 2000 || a.UploadRate != nil {
		t.Fatal("ownership transition lost totals or mixed rate", a)
	}
	a = sample(3000, 5000, time.Second)
	if *a.UploadRate != 0 {
		t.Fatal(a)
	}
	a = sample(3, 5, time.Second)
	if a.Uploaded != 0 || a.UploadRate != nil {
		t.Fatal("counter reset spike", a)
	}
	c.measure(&ActivitySnapshot{}, now)
	if len(c.traffic) != 0 {
		t.Fatal("closed retained")
	}
	a = sample(10000, 20000, time.Second)
	if a.Uploaded != 0 || a.UploadRate != nil {
		t.Fatal("missed sample inherited total", a)
	}
	s.Rows[0].ID = "new-cookie"
	a = sample(20000, 30000, time.Second)
	if a.Uploaded != 0 || a.UploadRate != nil {
		t.Fatal("endpoint reuse", a)
	}
	s.Rows[0].Socket.Protocol = "udp"
	a = sample(20000, 30000, time.Second)
	if a.Available {
		t.Fatal("UDP invented")
	}
	// A reset/restarted collector never incorporates previous lifetime bytes.
	c = ActivityCollector{}
	s.Rows[0].Socket.Protocol = "tcp"
	a = sample(30000, 40000, time.Second)
	if a.Uploaded != 0 || a.UploadRate != nil {
		t.Fatal(a)
	}
}

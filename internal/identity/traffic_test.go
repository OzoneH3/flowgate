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

func TestOptionalUDPAndMixedSourceLifetimes(t *testing.T) {
	c := ActivityCollector{}
	now := time.Now()
	since := now
	s := ActivitySnapshot{UDP: &UDPSnapshot{State: "active", Generation: "one", Collected: now, SampleNS: 1e9, Rows: map[string]UDPCount{"cookie": {Since: since}}}, Rows: []ActivityRow{{ID: "udp-cookie", Socket: Socket{Protocol: "udp", State: 7, Cookie: "cookie"}}}, Processes: map[string]ActivityProcess{}}
	c.measure(&s, now)
	a := s.Rows[0].Traffic
	if !a.Available || a.UploadRate != nil || a.Definition != "udp-api-reported" {
		t.Fatal(a)
	}
	now = now.Add(time.Second)
	s.UDP.Collected = now
	s.UDP.SampleNS += 1e9
	s.UDP.Rows["cookie"] = UDPCount{Uploaded: 100, Downloaded: 200, Since: since}
	c.measure(&s, now)
	a = s.Rows[0].Traffic
	if a.Uploaded != 100 || a.Downloaded != 200 || *a.UploadRate != 100 || *a.DownloadRate != 200 {
		t.Fatal(a)
	}
	c.measure(&s, now.Add(100*time.Millisecond))
	if s.Rows[0].Traffic.UploadRate != nil || s.Rows[0].Traffic.Uploaded != 100 {
		t.Fatal("duplicate collector sample became zero rate or reset")
	}

	now = now.Add(time.Second)
	s.UDP.Collected = now
	s.UDP.SampleNS += 1e9
	s.Rows[0].Owners = []string{"new-owner"}
	c.measure(&s, now)
	a = s.Rows[0].Traffic
	if a.Uploaded != 100 || a.UploadRate != nil {
		t.Fatal("owner transition", a)
	}
	now = now.Add(time.Second)
	s.UDP.Collected = now
	s.UDP.SampleNS += 1e9
	s.UDP.Missed = 1
	c.measure(&s, now)
	if !s.Rows[0].Traffic.Partial {
		t.Fatal("missed operation hidden")
	}
	s.UDP.State = "unavailable"
	c.measure(&s, now)
	if s.Rows[0].Traffic.Available {
		t.Fatal("collector failure became zero")
	}
	now = now.Add(time.Second)
	s.UDP = &UDPSnapshot{State: "active", Generation: "new", Collected: now, SampleNS: 1e9, Rows: map[string]UDPCount{"cookie": {Since: now, Uploaded: 7}}}
	c.measure(&s, now)
	a = s.Rows[0].Traffic
	if a.Uploaded != 7 || a.UploadRate != nil || !a.Since.Equal(now) {
		t.Fatal("restart spike", a)
	}
	s.UDP.Collected = now.Add(-10 * time.Second)
	c.measure(&s, now)
	if s.Rows[0].Traffic.Available {
		t.Fatal("stale counter displayed")
	}
}

func TestUDPGenerationChangesSuppressRatesWithoutResettingTCP(t *testing.T) {
	c := ActivityCollector{}
	now := time.Now()
	since := now
	s := ActivitySnapshot{UDP: &UDPSnapshot{State: "active", Machine: true, Generation: "first", Collected: now, SampleNS: 1e9, Rows: map[string]UDPCount{"u": {Since: since, Uploaded: 100}}}, Rows: []ActivityRow{{ID: "udp", Socket: Socket{Protocol: "udp", UID: 1000, Cookie: "u"}}, {ID: "tcp", Socket: Socket{Protocol: "tcp", Cookie: "t", State: 1, Counters: &TCPBytes{Uploaded: 100}}}}}
	c.measure(&s, now)
	now = now.Add(time.Second)
	s.UDP.SampleNS += 1e9
	s.UDP.Generation = "replacement"
	s.UDP.Rows["u"] = UDPCount{Since: since, Uploaded: 500}
	s.Rows[1].Socket.Counters.Uploaded = 200
	c.measure(&s, now)
	if !s.Rows[0].Traffic.Available || s.Rows[0].Traffic.UploadRate != nil || s.Rows[0].Traffic.Uploaded != 500 {
		t.Fatal("UDP reset spike", s.Rows[0].Traffic)
	}
	if s.Rows[1].Traffic.UploadRate == nil || *s.Rows[1].Traffic.UploadRate != 100 {
		t.Fatal("UDP restart disturbed TCP", s.Rows[1].Traffic)
	}
}

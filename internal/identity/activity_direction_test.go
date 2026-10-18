package identity

import (
	"net/netip"
	"testing"
	"time"
)

func directionSocket(state uint8, inode uint32) Socket {
	return Socket{Protocol: "tcp", Family: 2, NetNS: "net:test", Cookie: "0100000000000000", Inode: inode, State: state, Local: netip.MustParseAddrPort("127.0.0.1:12345"), Remote: netip.MustParseAddrPort("127.0.0.1:23456"), diagObserved: true, diagFull: inode != 0}
}
func directionStep(c *ActivityCollector, s Socket, at time.Time) ActivityRow {
	out := ActivitySnapshot{Complete: true, Rows: []ActivityRow{{ID: activitySocketID(s), Socket: s}}}
	c.directions(&out, at)
	return out.Rows[0]
}
func TestInitiationObservedHandshakeAndLifetime(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		state uint8
		inode uint32
		want  string
	}{{2, 1, "outgoing"}, {3, 0, "incoming"}} {
		c := &ActivityCollector{}
		s := directionSocket(tc.state, tc.inode)
		first := directionStep(c, s, now)
		if first.Initiation.Direction != tc.want {
			t.Fatal(first)
		}
		s.State = 1
		s.Inode = 1
		next := directionStep(c, s, now.Add(time.Second))
		if next.Initiation.Direction != tc.want || !next.Initiation.ObservedAt.Equal(*first.Initiation.ObservedAt) {
			t.Fatal(next)
		}
		fresh := directionStep(&ActivityCollector{}, s, now)
		if fresh.Initiation.State != "unknown" {
			t.Fatal("preexisting socket gained direction", fresh)
		}
		s.Cookie = "0200000000000000"
		if v := directionStep(c, s, now.Add(2*time.Second)); v.Initiation.State != "unknown" {
			t.Fatal("new cookie inherited direction", v)
		}
	}
}
func TestInitiationGapsConflictsAndUnsupported(t *testing.T) {
	now := time.Now()
	s := directionSocket(2, 1)
	for _, kind := range []string{"absence", "long-gap", "namespace", "endpoint", "inode", "incomplete", "simultaneous", "disconnected"} {
		c := &ActivityCollector{}
		directionStep(c, s, now)
		next := s
		next.State = 1
		at := now.Add(time.Second)
		want := "unknown"
		switch kind {
		case "absence":
			c.directions(&ActivitySnapshot{Complete: true}, at)
		case "long-gap":
			at = now.Add(61 * time.Second)
		case "namespace":
			next.NetNS = "other"
		case "endpoint":
			next.Remote = netip.MustParseAddrPort("127.0.0.1:34567")
			want = "ambiguous"
		case "inode":
			next.Inode = 2
			want = "ambiguous"
		case "incomplete":
			c.directions(&ActivitySnapshot{}, at)
		case "disconnected":
			closed := s
			closed.State = 7
			directionStep(c, closed, at)
		case "simultaneous":
			next.State = 3
			want = "ambiguous"
		}
		if v := directionStep(c, next, at); v.Initiation.State != want {
			t.Fatal(kind, v)
		}
	}
	c := &ActivityCollector{}
	s = directionSocket(3, 0)
	s.diagFull = true // orphan full socket cannot masquerade as passive request
	if v := directionStep(c, s, now); v.Initiation.State != "ambiguous" {
		t.Fatal(v)
	}
	s = directionSocket(10, 1)
	if v := directionStep(c, s, now); v.Initiation.State != "listening" || v.Direction != "Unknown" {
		t.Fatal(v)
	}
	s.Protocol = "udp"
	s.Remote = netip.MustParseAddrPort("0.0.0.0:0")
	if v := directionStep(c, s, now); v.Initiation.State != "unconnected" {
		t.Fatal(v)
	}
	s.Remote = netip.MustParseAddrPort("127.0.0.1:23456")
	if v := directionStep(c, s, now); v.Initiation.State != "unknown" {
		t.Fatal("UDP connect inferred initiation", v)
	}
	s = directionSocket(2, 1)
	directionStep(c, s, now)
	s.State = 3
	s.Inode = 0
	s.diagFull = false
	if v := directionStep(c, s, now.Add(time.Second)); v.Initiation.State != "ambiguous" {
		t.Fatal(v)
	}
	s.State = 1
	s.Inode = 1
	if v := directionStep(c, s, now.Add(2*time.Second)); v.Initiation.State != "ambiguous" {
		t.Fatal("conflict forgotten", v)
	}
}

func TestInitiationRejectsMissingCookie(t *testing.T) {
	for _, cookie := range []string{"", "0000000000000000", "ffffffffffffffff", "bad"} {
		s := directionSocket(2, 1)
		s.Cookie = cookie
		if v := directionStep(&ActivityCollector{}, s, time.Now()); v.Initiation.State != "unknown" {
			t.Fatal(cookie, v)
		}
	}
}

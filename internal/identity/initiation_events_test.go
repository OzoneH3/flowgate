package identity

import (
	"net/netip"
	"testing"
	"time"
)

func TestEventEvidenceSameCookieNamespaceGenerationOnly(t *testing.T) {
	now := time.Now()
	at := now.Add(-time.Millisecond)
	row := ActivityRow{Socket: Socket{Protocol: "tcp", State: 1, Cookie: "0100000000000000", NetNS: "net", Local: netip.MustParseAddrPort("127.0.0.1:1000"), Remote: netip.MustParseAddrPort("127.0.0.1:2000")}, Initiation: Initiation{State: "unknown"}}
	events := InitiationEvents{State: "active", NetNS: "net", Generation: "first", Collected: now, Rows: map[string]Initiation{row.Socket.Cookie: {State: "known", Direction: "outgoing", Source: "cgroup-sockops-active-established", Generation: "first", ObservedAt: &at}}}
	s := ActivitySnapshot{Rows: []ActivityRow{row}}
	ApplyInitiationEvents(&s, events)
	if s.Rows[0].Initiation.State != "known" || s.Rows[0].Direction != "Outgoing" {
		t.Fatal(s)
	}
	for _, what := range []string{"cookie", "namespace", "generation", "failed", "stale", "listener", "closed", "udp"} {
		t.Run(what, func(t *testing.T) {
			r := row
			e := events
			switch what {
			case "cookie":
				r.Socket.Cookie = "0200000000000000"
			case "namespace":
				r.Socket.NetNS = "other"
			case "generation":
				e.Generation = "restart"
			case "failed":
				e.State = "failed"
			case "stale":
				e.Collected = now.Add(-10 * time.Second)
			case "listener":
				r.Socket.State = 10
			case "closed":
				r.Socket.State = 7
			case "udp":
				r.Socket.Protocol = "udp"
			}
			s := ActivitySnapshot{Rows: []ActivityRow{r}}
			ApplyInitiationEvents(&s, e)
			if s.Rows[0].Initiation.State != "unknown" {
				t.Fatal("event leaked", what, s.Rows[0])
			}
		})
	}
}

package identity

import (
	"fmt"
	"net/netip"
	"testing"
	"time"
)

func displayFixture() ActivitySnapshot {
	s := ActivitySnapshot{Complete: true, Processes: map[string]ActivityProcess{}}
	for prefix := 0; prefix < 2; prefix++ {
		for app := 0; app < 2; app++ {
			for _, proto := range []string{"tcp", "udp"} {
				n := len(s.Rows) + 1
				broker := 10 + prefix
				pid := 100 + prefix*2 + app
				for _, id := range []int{broker, pid} {
					key := fmt.Sprintf("%d:100", id)
					s.Processes[key] = ActivityProcess{ID: key, PID: id, Start: "100", UID: 1000, NetNS: "ns", Executable: fmt.Sprintf("/fixture/exe-%d", id), ExecutableRevision: "host-r", Application: Application{Key: fmt.Sprint(id), Kind: "wine-unresolved", Revision: "r", Prefix: fmt.Sprintf("/prefix-%d", prefix)}}
				}
				cookie := fmt.Sprintf("%016x", n)
				r := ActivityRow{ID: fmt.Sprint(n), Socket: Socket{Protocol: proto, NetNS: "ns", UID: 1000, Inode: uint32(n), Cookie: cookie, Local: netip.MustParseAddrPort("[::]:1234"), Remote: netip.MustParseAddrPort("[::]:0"), State: 1}, Owners: []string{fmt.Sprintf("%d:100", broker), fmt.Sprintf("%d:100", pid)}}
				r.RuntimeApplication = &RuntimeApplication{UID: 1000, Application: Application{Key: fmt.Sprintf("app-%d-prefix-%d", app, prefix), Kind: "wine", Revision: "rev", Prefix: fmt.Sprintf("/prefix-%d", prefix), Evidence: []string{"fresh"}}, Evidence: TableEvidence{SocketCookie: cookie, Owners: []WindowsOwner{{Image: "synthetic.exe"}}}}
				s.Rows = append(s.Rows, r)
			}
		}
	}
	return s
}
func freshDisplayRows(s ActivitySnapshot) ActivitySnapshot {
	s.Rows = append([]ActivityRow(nil), s.Rows...)
	for i := range s.Rows {
		s.Rows[i].RuntimeApplication = nil
	}
	return s
}
func TestWineActivityDisplayBusyRetainsExactTCPAndUDP(t *testing.T) {
	m := &WineObservers{}
	m.admissionDemand.Store(1)
	s := displayFixture()
	m.AnnotateActivity(&s)
	want := make([]string, len(s.Rows))
	for i, r := range s.Rows {
		want[i] = r.RuntimeApplication.Application.Key
	}
	next := freshDisplayRows(s)
	m.AnnotateActivity(&next)
	for i, r := range next.Rows {
		if r.RuntimeApplication == nil || r.RuntimeApplication.Application.Key != want[i] || r.RuntimeApplication.DisplaySource != "last-verified-snapshot" || r.RuntimeApplication.DisplayVerifiedAt == "" {
			t.Fatalf("lost or transferred row %d: %+v", i, r)
		}
	}
	next.Rows[0].RuntimeApplication.Application.Evidence[0] = "mutated"
	next.Rows[0].RuntimeApplication.Evidence.Owners[0].Image = "changed"
	again := freshDisplayRows(s)
	m.AnnotateActivity(&again)
	if again.Rows[0].RuntimeApplication.Application.Evidence[0] != "fresh" || again.Rows[0].RuntimeApplication.Evidence.Owners[0].Image != "synthetic.exe" {
		t.Fatal("cached annotation aliased response")
	}
}
func TestWineActivityDisplayChangesAndClosureDrop(t *testing.T) {
	for _, change := range []string{"cookie", "inode", "namespace", "holder-start", "holder-set", "missing-holder", "uid", "exec", "prefix", "socket-state", "incomplete", "closed"} {
		t.Run(change, func(t *testing.T) {
			m := &WineObservers{}
			s := displayFixture()
			now := time.Now()
			m.retainWineActivityAnnotations(&s, now)
			next := freshDisplayRows(s)
			r := &next.Rows[0]
			switch change {
			case "cookie":
				r.Socket.Cookie = "other"
			case "inode":
				r.Socket.Inode++
			case "namespace":
				r.Socket.NetNS = "other"
			case "holder-start":
				p := next.Processes[r.Owners[0]]
				p.Start = "101"
				next.Processes[r.Owners[0]] = p
			case "holder-set":
				r.Owners = r.Owners[:1]
			case "missing-holder":
				delete(next.Processes, r.Owners[0])
			case "uid":
				p := next.Processes[r.Owners[0]]
				p.UID++
				next.Processes[r.Owners[0]] = p
			case "exec":
				p := next.Processes[r.Owners[0]]
				p.ExecutableRevision = "other"
				next.Processes[r.Owners[0]] = p
			case "prefix":
				p := next.Processes[r.Owners[0]]
				p.Application.Prefix = "/other-prefix"
				next.Processes[r.Owners[0]] = p
			case "socket-state":
				r.Socket.State++
			case "incomplete":
				next.Complete = false
			case "closed":
				next.Rows = next.Rows[1:]
			}
			m.retainWineActivityAnnotations(&next, now.Add(time.Second))
			if change != "closed" && next.Rows[0].RuntimeApplication != nil {
				t.Fatal("changed row borrowed old identity")
			}
			// Returning the original socket after an absent/changed snapshot never
			// resurrects the discarded annotation from an older snapshot.
			original := freshDisplayRows(s)
			m.retainWineActivityAnnotations(&original, now.Add(2*time.Second))
			if original.Rows[0].RuntimeApplication != nil {
				t.Fatal("discarded row resurrected")
			}
		})
	}
}
func TestWineActivityDisplayTTLNotExtendedAndCacheBounded(t *testing.T) {
	m := &WineObservers{}
	s := displayFixture()
	now := time.Now()
	m.retainWineActivityAnnotations(&s, now)
	for _, age := range []time.Duration{time.Second, 2 * time.Second, 3 * time.Second} {
		next := freshDisplayRows(s)
		m.retainWineActivityAnnotations(&next, now.Add(age))
		if (next.Rows[0].RuntimeApplication != nil) != (age < wineActivityDisplayTTL) {
			t.Fatal("retention extended its TTL", age)
		}
	}
	s = displayFixture()
	many := s
	many.Rows = nil
	for i := 0; i < wineActivityDisplayMax+100; i++ {
		r := s.Rows[0]
		r.Socket.Inode = uint32(i + 1)
		r.Socket.Cookie = fmt.Sprintf("%016x", i+1)
		a := *r.RuntimeApplication
		a.Evidence.SocketCookie = r.Socket.Cookie
		r.RuntimeApplication = &a
		many.Rows = append(many.Rows, r)
	}
	m.retainWineActivityAnnotations(&many, now)
	if len(m.activityDisplay.rows) != wineActivityDisplayMax {
		t.Fatal("unbounded/empty cache", len(m.activityDisplay.rows))
	}
	m.Close()
	next := freshDisplayRows(s)
	m.retainWineActivityAnnotations(&next, now.Add(time.Second))
	if len(m.activityDisplay.rows) != 0 || next.Rows[0].RuntimeApplication != nil {
		t.Fatal("closed observer reused display identity")
	}
}

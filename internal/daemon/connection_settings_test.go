package daemon

import (
	"errors"
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"os"
	"testing"
	"time"
)

func TestConnectionCheckSettingsAuthorityAndFailure(t *testing.T) {
	e := New(time.Second)
	e.InitConnectionChecks(false, 1, func(bool, uint64) error { return nil })
	off := false
	o := ConnectionCheckOptions{&off, "1"}
	if !e.ConnectionChecks().Enabled {
		t.Fatal("not enabled by default")
	}
	for _, x := range []struct {
		g    string
		a, r bool
	}{{e.Generation, false, false}, {e.Generation, true, true}, {"old", true, false}} {
		if _, err := e.ConfigureConnectionChecks(x.g, o, x.a, x.r); err == nil {
			t.Fatal("authority accepted")
		}
	}
	e.saveConnectionChecks = func(bool, uint64) error { return errors.New("disk") }
	if _, err := e.ConfigureConnectionChecks(e.Generation, o, true, false); err == nil || !e.ConnectionChecks().Enabled {
		t.Fatal("failed save applied")
	}
	e.saveConnectionChecks = func(bool, uint64) error { return nil }
	s, err := e.ConfigureConnectionChecks(e.Generation, o, true, false)
	if err != nil || s.Enabled || s.Revision != "2" {
		t.Fatal(s, err)
	}
	if _, err = e.ConfigureConnectionChecks(e.Generation, o, true, false); err == nil {
		t.Fatal("stale CAS applied")
	}
}
func TestConnectionChecksOffOnlySkipsEstablishedScheduling(t *testing.T) {
	e, s, f, a, m := connectionFixture(t)
	e.InitConnectionChecks(true, 1, func(bool, uint64) error { return nil })
	if e.connectionCheckDue(f) {
		t.Fatal("established check due while off")
	}
	fresh := *f
	fresh.haveKey = false
	if !e.connectionCheckDue(&fresh) {
		t.Fatal("initial proof skipped")
	}
	if !f.haveKey || len(m.values) != 1 {
		t.Fatal("toggle revoked grant")
	}
	s.socketSnapshot = func() ([]identity.Socket, error) { return a.Sockets, nil }
	e.sweepConnectionSockets(s)
	if !f.haveKey {
		t.Fatal("idle grant removed")
	}
	if err := e.SetRules(nil); err != nil {
		t.Fatal(err)
	}
	if len(m.values) != 0 {
		t.Fatal("policy revocation disabled")
	}
}

func TestConnectionChecksOffCleanupExpiryAndResume(t *testing.T) {
	for _, expired := range []bool{false, true} {
		e, s, f, a, m := connectionFixture(t)
		e.InitConnectionChecks(true, 1, func(bool, uint64) error { return nil })
		s.socketSnapshot = func() ([]identity.Socket, error) {
			if expired {
				return a.Sockets, nil
			}
			return nil, nil
		}
		if expired {
			f.deadline = 1
		}
		e.sweepConnectionSockets(s)
		if f.haveKey || len(m.values) != 0 {
			t.Fatal("off bypassed closure/expiry")
		}
	}
	e, s, f, a, m := connectionFixture(t)
	e.InitConnectionChecks(false, 1, func(bool, uint64) error { return nil })
	ticket := s.store.Begin()
	off := false
	if _, err := e.ConfigureConnectionChecks(e.Generation, ConnectionCheckOptions{&off, "1"}, true, false); err != nil {
		t.Fatal(err)
	}
	// An in-flight check can finish; disabling never turns a check into a new grant.
	e.finishSocketAuthorizationLocked(s, f, ticket, a)
	if !f.haveKey || len(m.values) != 1 {
		t.Fatal("toggle interrupted established traffic")
	}
	on := true
	if _, err := e.ConfigureConnectionChecks(e.Generation, ConnectionCheckOptions{&on, "2"}, true, false); err != nil {
		t.Fatal(err)
	}
	if !e.connectionCheckDue(f) {
		t.Fatal("reenabling did not resume eligibility")
	}
}
func TestConnectionCheckAPIEndpointAuthority(t *testing.T) {
	for _, ro := range []bool{false, true} {
		e := New(time.Second)
		e.SaveRules = func([]policy.Rule) error { return nil }
		e.InitConnectionChecks(false, 1, func(bool, uint64) error { return nil })
		path := profileAPISocket(t, e, ro)
		off := false
		r, _ := Call(path, Request{Version: 1, Operation: "connection-check-configure", Generation: e.Generation, ConnectionChecks: &ConnectionCheckOptions{&off, "1"}})
		if ro || os.Geteuid() != 0 {
			if r.ErrorCode != "forbidden" || !e.ConnectionChecks().Enabled {
				t.Fatal(r)
			}
		} else if r.ErrorCode != "" || e.ConnectionChecks().Enabled {
			t.Fatal(r)
		}
	}
}

package daemon

import (
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"testing"
	"time"
)

func TestUDPBatchRechecksApplicationsPrefixesAndPolicy(t *testing.T) {
	e := New(time.Minute)
	e.LocalPeer = nil
	f, _ := identity.ParseFlow("udp", "outgoing", "192.0.2.1:41001", "198.51.100.1:41002")
	apps := []identity.Application{}
	for _, prefix := range []string{"/prefix-a", "/prefix-b"} {
		for _, exe := range []string{"alpha.exe", "beta.exe"} {
			apps = append(apps, identity.Application{Kind: "wine", Key: prefix + exe, Prefix: prefix, Executable: prefix + "/drive_c/" + exe, Revision: "r1"})
		}
	}
	current := apps[0]
	calls := 0
	e.Resolve = func(identity.Flow) identity.Attribution {
		calls++
		a := current
		return identity.Attribution{Application: &a, Owners: []identity.Process{{UID: 1000, Start: "1"}}, Fingerprint: a.Key}
	}
	rule := policy.Rule{ID: "only-alpha-a", Action: "allow", Filter: policy.Filter{Application: apps[0].Key, Revision: "r1", UID: 1000, Protocol: "udp", Direction: "outgoing"}}
	if err := e.SetRules([]policy.Rule{rule}); err != nil {
		t.Fatal(err)
	}
	for i, app := range apps {
		current = app
		before := calls
		events, ok := observeUDPBatch(e, f, "udp", 16, true)
		if !ok || len(events) != 16 || calls != before+1 {
			t.Fatal("not one fresh resolution", ok, len(events), calls, before)
		}
		for _, event := range events {
			if (event.State == "allowed") != (i == 0) {
				t.Fatal("cross-app/prefix permission", app, event.State)
			}
		}
	}
	current = apps[0]
	rule.Action = "block"
	rule.Version++
	if err := e.SetRules([]policy.Rule{rule}); err != nil {
		t.Fatal(err)
	}
	events, _ := observeUDPBatch(e, f, "udp", 16, true)
	for _, v := range events {
		if v.State != "blocked" {
			t.Fatal("old rule result reused", v.State)
		}
	}
	e.Resolve = func(identity.Flow) identity.Attribution {
		return identity.Attribution{Status: "unknown", Reason: "socket closed or replaced"}
	}
	events, _ = observeUDPBatch(e, f, "udp", 16, true)
	for _, v := range events {
		if v.State != "blocked" || v.Attribution.Application != nil {
			t.Fatal("missing owner inherited permission")
		}
	}
}

func TestUDPBatchBusyCensusDoesNotCreateEvents(t *testing.T) {
	e := New(time.Minute)
	e.LocalPeer = nil
	f, _ := identity.ParseFlow("udp", "outgoing", "192.0.2.1:41001", "198.51.100.1:41002")
	e.TryResolve = func(identity.Flow) (identity.Attribution, bool) { return identity.Attribution{}, false }
	if events, ok := observeUDPBatch(e, f, "udp", 16, false); ok || len(events) != 0 || len(e.events) != 0 {
		t.Fatal("busy census changed decisions")
	}
}

func observeUDPBatch(e *Engine, f identity.Flow, token string, count int, census bool) ([]Event, bool) {
	decide, ok := e.PrepareUDPBatch(f, token, count, census)
	if !ok {
		return nil, false
	}
	events := make([]Event, count)
	for i := range events {
		events[i] = decide()
	}
	return events, true
}

package daemon

import (
	"context"
	"flowgate/internal/identity"
	"flowgate/internal/socketgrant"
	"testing"
	"time"
)

func TestSocketSessionRequiresZonePublisherAndFreshState(t *testing.T) {
	e := New(time.Second)
	e.Mode = "daemon-monitor"
	e.ZoneSource = func() identity.NetworkZones { return e.Zones }
	r := SocketSessionResolvers{Fresh: func(identity.Flow) identity.Attribution { return identity.Attribution{} }, Observed: func(identity.Flow) (identity.Attribution, uint64) { return identity.Attribution{}, 0 }}
	model := &grantModel{values: map[socketgrant.Key]socketgrant.Value{}}
	b := socketgrant.RetainForSession(model)
	if e.StartSessionSocketAuthorization(context.Background(), b, r) == nil {
		t.Fatal("uninstalled publication transaction accepted")
	}
	_ = e.NetworkZonePublisher()
	if err := e.StartSessionSocketAuthorization(context.Background(), b, r); err != nil {
		t.Fatal(err)
	}
	e.mu.Lock()
	s := e.socketAuthorization
	if !s.routeBound || !s.productionSession || !s.batchCoordination || s.ordinaryObserved == nil || s.ordinaryYield {
		t.Fatal("wrong production scope/options")
	}
	e.mu.Unlock()
	if err := e.StopSocketAuthorization(); err != nil {
		t.Fatal(err)
	}
	if model.epoch != 0 || e.socketAuthorization != nil {
		t.Fatal("stop left active state")
	}
	if err := b.Release(); err != nil {
		t.Fatal(err)
	}
	next := socketgrant.RetainForSession(&grantModel{values: map[socketgrant.Key]socketgrant.Value{}})
	if err := e.StartSessionSocketAuthorization(context.Background(), next, r); err != nil {
		t.Fatal("new session refused", err)
	}
	if e.socketAuthorization == s {
		t.Fatal("old observation state reused")
	}
	if err := e.StopSocketAuthorization(); err != nil {
		t.Fatal(err)
	}
}
func TestSocketSessionStopJoinsInFlightObservation(t *testing.T) {
	e := New(time.Second)
	e.Mode = "daemon-monitor"
	e.ZoneSource = func() identity.NetworkZones { return e.Zones }
	_ = e.NetworkZonePublisher()
	entered, release := make(chan struct{}), make(chan struct{})
	r := SocketSessionResolvers{Fresh: func(identity.Flow) identity.Attribution { close(entered); <-release; return identity.Attribution{} }, Observed: func(identity.Flow) (identity.Attribution, uint64) { return identity.Attribution{}, 0 }}
	b := socketgrant.RetainForSession(&grantModel{values: map[socketgrant.Key]socketgrant.Value{}})
	if err := e.StartSessionSocketAuthorization(context.Background(), b, r); err != nil {
		t.Fatal(err)
	}
	e.mu.Lock()
	s := e.socketAuthorization
	s.flows["test"] = &socketFlow{lastPacket: socketgrant.BootNow()}
	s.wakeScheduler()
	e.mu.Unlock()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("observation did not start")
	}
	stopped := make(chan error, 1)
	go func() { stopped <- e.StopSocketAuthorization() }()
	select {
	case <-stopped:
		t.Fatal("stop discarded in-flight ownership")
	case <-time.After(10 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("stop failed to join")
	}
}

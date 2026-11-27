package uploadshape

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"flowgate/internal/identity"
	"golang.org/x/sys/unix"
)

func TestDefaultInterface(t *testing.T) {
	links := []identity.NetworkLink{
		{Index: 2, Name: "lan", Flags: unix.IFF_UP | unix.IFF_LOWER_UP},
		{Index: 3, Name: "other", Flags: unix.IFF_UP | unix.IFF_LOWER_UP},
	}
	route := identity.NetworkRoute{Prefix: "0.0.0.0/0", Table: unix.RT_TABLE_MAIN, Type: unix.RTN_UNICAST, Interface: 2, Priority: 10}
	for _, tc := range []struct {
		name   string
		routes []identity.NetworkRoute
		want   string
	}{
		{"no default", nil, "Waiting for a usable default route"},
		{"one", []identity.NetworkRoute{route}, "lan"},
		{"metric", []identity.NetworkRoute{route, {Prefix: route.Prefix, Table: route.Table, Type: route.Type, Interface: 3, Priority: 20}}, "lan"},
		{"ambiguous metric", []identity.NetworkRoute{route, {Prefix: route.Prefix, Table: route.Table, Type: route.Type, Interface: 3, Priority: 10}}, "multiple interfaces"},
		{"split families", []identity.NetworkRoute{route, {Prefix: "::/0", Table: route.Table, Type: route.Type, Interface: 3}}, "multiple interfaces"},
		{"carrier missing", []identity.NetworkRoute{{Prefix: route.Prefix, Table: route.Table, Type: route.Type, Interface: 4}}, "Waiting for carrier"},
		{"multipath", []identity.NetworkRoute{{Prefix: route.Prefix, Table: route.Table, Type: route.Type}}, "multipath"},
		{"policy routing", []identity.NetworkRoute{{Prefix: route.Prefix, Table: 101, Type: route.Type, Interface: 2}}, "policy routing tables"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			device, err := defaultInterface(identity.NetworkSnapshot{State: "ready", Links: links, Routes: tc.routes})
			if err != nil {
				device = err.Error()
			}
			if !strings.Contains(device, tc.want) {
				t.Fatalf("selection %q, want %q", device, tc.want)
			}
		})
	}
}

func TestDiscoveredShapingWaitsAndStartsEmpty(t *testing.T) {
	d := NewDiscovered(context.Background(), Options{}, Preferences{}, nil)
	defer d.Close()
	calls := 0
	approved := make(chan struct{})
	d.prepare = func(ctx context.Context) (string, *Manager, error) {
		calls++
		if calls == 1 {
			return "lan", nil, errors.New("foreign classes or filters present")
		}
		select {
		case <-approved:
			return "lan", newManager(Options{Interface: "lan", HostTrial: true}), nil
		case <-ctx.Done():
			return "", nil, ctx.Err()
		}
	}
	d.Resume()
	deadline := time.Now().Add(5 * time.Second)
	for d.Snapshot().Interface != "lan" && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	s := d.Snapshot()
	if !s.InterfacePending || !strings.Contains(s.LastError, "foreign classes") || s.Enabled || len(s.Caps) != 0 {
		t.Fatalf("unsupported snapshot: %+v", s)
	}
	if _, err := d.Configure(s.Version, Config{}); !errors.Is(err, ErrInterfaceUnavailable) {
		t.Fatalf("pending write: %v", err)
	}
	close(approved)
	select {
	case <-d.done:
	case <-time.After(5 * time.Second):
		t.Fatal("discovery did not retry")
	}
	s = d.Snapshot()
	if s.InterfacePending || s.Status != "Disabled" || s.Interface != "lan" || s.Enabled || len(s.Caps) != 0 || d.manager.Load().running {
		t.Fatalf("fresh manager: %+v", s)
	}
}

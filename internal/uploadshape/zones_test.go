package uploadshape

import (
	"encoding/json"
	"flowgate/internal/identity"
	"sync"
	"testing"
)

func TestZoneSchemaCASAndExplicitNormal(t *testing.T) {
	m := newManager(Options{Interface: "test"})
	defer m.Close()
	m.start = func() (transport, error) { return &model{}, nil }
	c := Config{Enabled: true, Schema: 3, Caps: []Cap{{Application: "a", BitsPerSecond: 12_000_000, TrafficPriority: "high"}, {Application: "a", Scope: "local", BitsPerSecond: 4_000_000}, {Application: "a", Scope: "internet", TrafficPriority: "normal"}}}
	s, err := m.Configure(1, c)
	if err != nil {
		t.Fatal(err)
	}
	if s.Caps[2].TrafficPriority != "normal" {
		t.Fatal("lost explicit zone Normal")
	}
	for _, schema := range []int{0, 2} {
		_, err = m.Configure(s.Version, Config{Schema: schema})
		if err == nil || err.Error() != "schema_upgrade_required" {
			t.Fatal(schema, err)
		}
	}
	if m.Snapshot().Version != s.Version {
		t.Fatal("rejected legacy overwrite mutated")
	}
	if _, err = m.Configure(1, c); err == nil || err.Error() != "stale_version" {
		t.Fatal(err)
	}
	// Lost receipt is reconciled by version and complete desired state, never replay.
	reconciled := m.Snapshot()
	if len(reconciled.Caps) != 3 {
		t.Fatal(reconciled.Caps)
	}
	c.Caps = c.Caps[:2]
	s, err = m.Configure(reconciled.Version, c)
	if err != nil || len(s.Caps) != 2 || s.Caps[0].BitsPerSecond != 12_000_000 || s.Caps[1].Scope != "local" {
		t.Fatal(s, err)
	}
}
func TestZoneCapacityAndIndependentDirections(t *testing.T) {
	c := Config{Enabled: true, Schema: 3, Caps: []Cap{{Application: "a", DownloadBitsPerSecond: 1_000_000, TrafficPriority: "low"}, {Application: "a", Scope: "internet", BitsPerSecond: 4_000_000}}}
	if err := validateConfig(c); err != nil {
		t.Fatal("upload scope must not split unchanged download allocation", err)
	}
	for i := 0; i < 4; i++ {
		c.Caps = append(c.Caps, Cap{Application: string(rune('b' + i)), Scope: "local", BitsPerSecond: 4_000_000})
	}
	if validateConfig(c) == nil {
		t.Fatal("overcapacity accepted")
	}
	c.Caps = []Cap{{Application: "a", BitsPerSecond: 1_000_000}, {Application: "a", Scope: "local", TrafficPriority: "low"}, {Application: "a", Scope: "internet", TrafficPriority: "high"}}
	c.UploadBudget = 16_000_000
	if err := validateConfig(c); err == nil || err.Error() != "allocation_below_minimum" {
		t.Fatal(err)
	}
	c.UploadBudget = 0
	if err := validateConfig(c); err != nil {
		t.Fatal("priority must be dormant without budget", err)
	}
}
func TestAuthoritativeZoneUnknownAndPolicyGrouping(t *testing.T) {
	for _, state := range []string{"unavailable", "ambiguous", ""} {
		if knownZone(identity.NetworkScope{State: state, Zone: "local"}) != "" {
			t.Fatal("unknown became local")
		}
	}
	if knownZone(identity.NetworkScope{State: "known", Zone: "internet"}) != "internet" {
		t.Fatal("lost known zone")
	}
	caps := []Cap{{Application: "a", BitsPerSecond: 12_000_000}, {Application: "a", Scope: "local", BitsPerSecond: 4_000_000}, {Application: "a", Scope: "internet", TrafficPriority: "normal"}}
	p := zonePolicy(caps)
	if len(p) != 1 {
		t.Fatal(p)
	}
	e := p["0:a"].(map[string]any)
	if e["rate"] != uint64(12_000_000) || len(e["zones"].(map[string]any)) != 2 {
		t.Fatal(p)
	}
	for _, scope := range []string{"private", "unknown"} {
		c := caps[1]
		c.Scope = scope
		if validateConfig(Config{Enabled: true, Caps: []Cap{c}}) == nil {
			t.Fatal(scope)
		}
	}
}

// Synthetic classifier revisions exercise the actual manager reconciliation
// loop. Transport is a map model: this does not prove kernel reclassification.
type zoneTransport struct {
	mu      sync.Mutex
	zone    string
	changes int
}

func (z *zoneTransport) Close() error { return nil }
func (z *zoneTransport) Call(q map[string]any) (json.RawMessage, error) {
	z.mu.Lock()
	defer z.mu.Unlock()
	if q["op"] == "rezone" {
		for _, scope := range q["bindings"].(map[string]string) {
			z.zone = scope
			z.changes++
		}
	}
	return json.Marshal(map[string]any{"status": "Partial", "next_minor": 5, "bindings": []any{map[string]any{"app": "0:a", "cookie": "0000000000000001", "zone": z.zone, "descriptor": map[string]any{"local": "10.0.0.1:1000", "remote": "10.0.0.2:2000", "netns": "net:[1]"}}}})
}
func TestManagerReclassificationUsesAuthoritativeRevision(t *testing.T) {
	var sourceMu sync.Mutex
	zones, _ := identity.NewNetworkZones([]string{"10.0.0.2/32"}, nil)
	m := newManager(Options{Interface: "test", Zones: func() identity.NetworkZones { sourceMu.Lock(); defer sourceMu.Unlock(); return zones }})
	tr := &zoneTransport{zone: "local"}
	m.start = func() (transport, error) { return tr, nil }
	m.sockets = func() ([]identity.Socket, error) { return nil, nil }
	defer m.Close()
	_, err := m.Configure(1, Config{Enabled: true, Schema: 3, Caps: []Cap{{Application: "a", Scope: "local", BitsPerSecond: 4_000_000}, {Application: "a", Scope: "internet", BitsPerSecond: 8_000_000}}})
	if err != nil {
		t.Fatal(err)
	}
	until(t, func() bool { return m.Snapshot().Kernel != nil })
	for _, zone := range []string{"internet", "", "local"} {
		sourceMu.Lock()
		switch zone {
		case "internet":
			zones, _ = identity.NewNetworkZones(nil, []string{"10.0.0.2/32"})
		case "local":
			zones, _ = identity.NewNetworkZones([]string{"10.0.0.2/32"}, nil)
		default:
			zones, _ = identity.NewNetworkZones(nil, nil)
		}
		sourceMu.Unlock()
		select {
		case m.wake <- struct{}{}:
		default:
		}
		until(t, func() bool {
			s := m.Snapshot()
			return s.Kernel != nil && len(s.Kernel.Bindings) == 1 && s.Kernel.Bindings[0].Zone == zone
		})
	}
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if tr.changes != 3 {
		t.Fatal("missing/duplicate reclassifications", tr.changes)
	}
}

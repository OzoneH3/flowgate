package uploadshape

import (
	"encoding/json"
	"testing"
)

func TestTrafficPriorityValidationAndSchema(t *testing.T) {
	ok := Config{Enabled: true, Schema: 2, UploadBudget: 40_000_000, Caps: []Cap{{Application: "a", TrafficPriority: "high"}}}
	if err := validateConfig(ok); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]Config{
		"priority normal without cap": {Enabled: true, Caps: []Cap{{Application: "a"}}},
		"unknown priority":            {Enabled: true, Caps: []Cap{{Application: "a", TrafficPriority: "critical"}}},
		"budget too small":            {Enabled: true, UploadBudget: 15_999_999},
		"disabled with budget":        {Enabled: false, DownloadBudget: 40_000_000},
		"floor below minimum":         {Enabled: true, UploadBudget: 16_000_000, Caps: lowCapped()},
	} {
		if validateConfig(c) == nil {
			t.Fatal(name)
		}
	}
	// Review counterexample is admitted: 16 High apps capped at 1 Mbit/s, budget 16.
	var many []Cap
	for i := 0; i < 16; i++ {
		many = append(many, Cap{Application: string(rune('a' + i)), BitsPerSecond: 1_000_000, TrafficPriority: "high"})
	}
	if err := validateConfig(Config{Enabled: true, UploadBudget: 16_000_000, Caps: many}); err != nil {
		t.Fatal(err)
	}
	m := newManager(Options{Interface: "test"})
	defer m.Close()
	m.start = func() (transport, error) { return &model{}, nil }
	if _, err := m.Configure(1, Config{Enabled: true, Caps: []Cap{{Application: "a", TrafficPriority: "low"}}}); err == nil || err.Error() != "schema_upgrade_required" {
		t.Fatal("schema-1 request carrying traffic priority accepted", err)
	}
	if _, err := m.Configure(1, Config{Enabled: true, Schema: 2, DownloadBudget: 40_000_000, Caps: []Cap{{Application: "a", TrafficPriority: "normal", BitsPerSecond: 4_000_000}}}); err != nil {
		t.Fatal(err)
	}
	s := m.Snapshot()
	if s.Caps[0].TrafficPriority != "" || s.DownloadBudget != 40_000_000 {
		t.Fatal("explicit Normal must normalise to default; budget must be published", s.Caps, s.DownloadBudget)
	}
	// An old full-replacement client must not erase the stored budget by omission.
	if _, err := m.Configure(2, Config{Enabled: true, Caps: []Cap{{Application: "a", BitsPerSecond: 4_000_000}}}); err == nil || err.Error() != "schema_upgrade_required" {
		t.Fatal("schema-1 replacement of advanced stored config accepted", err)
	}
	if m.Snapshot().Version != 2 {
		t.Fatal("refused replacement changed version")
	}
}

func lowCapped() []Cap {
	caps := []Cap{{Application: "l", BitsPerSecond: 1_000_000, TrafficPriority: "low"}}
	for i := 0; i < 15; i++ {
		caps = append(caps, Cap{Application: string(rune('b' + i)), TrafficPriority: "high"})
	}
	return caps
}

type policyTransport struct{ calls []map[string]any }

func (p *policyTransport) Call(q map[string]any) (json.RawMessage, error) {
	p.calls = append(p.calls, q)
	return json.RawMessage(`{"status":"Partial","apps":{},"bindings":[],"next_minor":1}`), nil
}
func (p *policyTransport) Close() error { return nil }

func TestPolicyOperationCarriesBudgetsAndPriorityOnlyBind(t *testing.T) {
	m := newManager(Options{Interface: "test"})
	f := &policyTransport{}
	m.start = func() (transport, error) { return f, nil }
	defer m.Close()
	if _, err := m.Configure(1, Config{Enabled: true, Schema: 2, UploadBudget: 40_000_000, Caps: []Cap{{UID: 0, Application: "a", TrafficPriority: "high"}}}); err != nil {
		t.Fatal(err)
	}
	until(t, func() bool { return m.Snapshot().AppliedVersion == 2 })
	m.mu.Lock()
	var policy map[string]any
	for _, q := range f.calls {
		if q["op"] == "policy" {
			policy = q
		}
	}
	m.mu.Unlock()
	if policy == nil || policy["upload_budget"] != uint64(40_000_000) || policy["download_budget"] != uint64(0) {
		t.Fatal("policy op missing budgets", policy)
	}
	app := policy["apps"].(map[string]any)["0:a"].(map[string]any)
	if app["priority"] != "high" || app["rate"] != uint64(0) {
		t.Fatal(app)
	}
}

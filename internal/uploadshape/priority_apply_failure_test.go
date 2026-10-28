package uploadshape

import (
	"encoding/json"
	"errors"
	"sync"
	"testing"
)

type gatedPolicy struct {
	mu       sync.Mutex
	policies int
	calls    []string
	entered  chan int
	release  chan error
	closed   bool
}

func (p *gatedPolicy) Call(q map[string]any) (json.RawMessage, error) {
	op := q["op"].(string)
	p.mu.Lock()
	p.calls = append(p.calls, op)
	n := 0
	if op == "policy" {
		p.policies++
		n = p.policies
	}
	p.mu.Unlock()
	if n > 0 {
		p.entered <- n
		if err := <-p.release; err != nil {
			return nil, err
		}
	}
	return json.RawMessage(`{"status":"Partial","apps":{},"bindings":[],"next_minor":1}`), nil
}
func (p *gatedPolicy) Close() error { p.mu.Lock(); defer p.mu.Unlock(); p.closed = true; return nil }
func TestPolicyFailureDoesNotAdvanceAppliedVersion(t *testing.T) {
	m := newManager(Options{})
	p := &gatedPolicy{entered: make(chan int, 2), release: make(chan error, 2)}
	m.start = func() (transport, error) { return p, nil }
	defer m.Close()
	if _, err := m.Configure(1, Config{Enabled: true}); err != nil {
		t.Fatal(err)
	}
	<-p.entered
	p.release <- nil
	until(t, func() bool { return m.Snapshot().AppliedVersion == 2 })
	if _, err := m.Configure(2, Config{Enabled: true, Schema: 2, UploadBudget: 40_000_000}); err != nil {
		t.Fatal(err)
	}
	<-p.entered
	if s := m.Snapshot(); s.Status != "Applying" || s.AppliedVersion != 2 {
		t.Fatal(s)
	}
	p.release <- errors.New("partial policy mutation")
	until(t, func() bool { return m.Snapshot().Status == "Unsupported" })
	until(t, func() bool { p.mu.Lock(); defer p.mu.Unlock(); return p.closed })
	if s := m.Snapshot(); s.AppliedVersion != 2 {
		t.Fatal(s)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.calls[len(p.calls)-1] != "policy" {
		t.Fatal(p.calls)
	}
}
func TestSupersededPolicyRemainsApplying(t *testing.T) {
	m := newManager(Options{})
	p := &gatedPolicy{entered: make(chan int, 2), release: make(chan error, 2)}
	m.start = func() (transport, error) { return p, nil }
	defer m.Close()
	if _, err := m.Configure(1, Config{Enabled: true}); err != nil {
		t.Fatal(err)
	}
	<-p.entered
	if _, err := m.Configure(2, Config{Enabled: true, Schema: 2, UploadBudget: 40_000_000}); err != nil {
		t.Fatal(err)
	}
	p.release <- nil
	<-p.entered
	if s := m.Snapshot(); s.Version != 3 || s.AppliedVersion != 2 || s.Status != "Applying" {
		t.Fatal(s)
	}
	p.release <- nil
	until(t, func() bool { return m.Snapshot().AppliedVersion == 3 })
}

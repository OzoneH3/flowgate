package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"flowgate/internal/store"
)

func TestDecisionTimeoutRetainsExistingDeadlineAndPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.db")
	db, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	e, flow, _, now := fixture()
	e.Timeout = 30 * time.Second
	seconds, revision, err := db.DecisionTimeout()
	if err != nil || seconds != 0 || revision != 1 {
		t.Fatalf("initial settings = %d seconds, revision %d, error %v", seconds, revision, err)
	}
	e.InitDecisionTimeout(seconds, revision, db.SaveDecisionTimeout)
	existing := e.Observe(flow, "existing")
	if existing.State != "awaiting-decision" || existing.Deadline.Sub(existing.FirstSeen) != 30*time.Second {
		t.Fatalf("startup request = %+v", existing)
	}
	opts := DecisionTimeoutOptions{Seconds: 7, ExpectedRevision: "1"}
	got, err := e.ConfigureDecisionTimeout(e.Generation, opts, true, false)
	if err != nil || got.Seconds != 7 || got.Revision != "2" {
		t.Fatalf("saved settings = %+v, error %v", got, err)
	}
	again := e.Observe(flow, "existing")
	if again.ID != existing.ID || !again.Deadline.Equal(existing.Deadline) {
		t.Fatalf("existing request changed: %+v", again)
	}
	next := e.Observe(flow, "new")
	if next.State != "awaiting-decision" || next.Deadline.Sub(next.FirstSeen) != 7*time.Second {
		t.Fatalf("new request = %+v", next)
	}
	*now = next.Deadline
	states := map[string]string{}
	for _, event := range e.List(1000, true) {
		states[event.ID] = event.State
	}
	if states[next.ID] != "expired" || states[existing.ID] != "awaiting-decision" {
		t.Fatalf("states at new deadline = %+v", states)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	seconds, revision, err = reopened.DecisionTimeout()
	if err != nil || seconds != 7 || revision != 2 {
		t.Fatalf("reopened settings = %d seconds, revision %d, error %v", seconds, revision, err)
	}
	restarted := New(40 * time.Second)
	restarted.InitDecisionTimeout(seconds, revision, reopened.SaveDecisionTimeout)
	if settings := restarted.DecisionTimeoutSettings(); settings != got {
		t.Fatalf("restarted settings = %+v", settings)
	}
}

func TestDecisionTimeoutRefusesInvalidAndUnpersistedChanges(t *testing.T) {
	e := New(30 * time.Second)
	saveErr := errors.New("disk full")
	e.InitDecisionTimeout(0, 1, func(int, uint64) error { return saveErr })
	for _, tc := range []struct {
		generation      string
		opts            DecisionTimeoutOptions
		admin, readonly bool
		code            string
	}{
		{e.Generation, DecisionTimeoutOptions{7, "1"}, false, false, "forbidden"},
		{e.Generation, DecisionTimeoutOptions{7, "1"}, true, true, "forbidden"},
		{"previous", DecisionTimeoutOptions{7, "1"}, true, false, "stale_generation"},
		{e.Generation, DecisionTimeoutOptions{1, "1"}, true, false, "invalid_request"},
		{e.Generation, DecisionTimeoutOptions{61, "1"}, true, false, "invalid_request"},
		{e.Generation, DecisionTimeoutOptions{7, "2"}, true, false, "revision_conflict"},
		{e.Generation, DecisionTimeoutOptions{7, "1"}, true, false, "persistence_failed"},
	} {
		_, err := e.ConfigureDecisionTimeout(tc.generation, tc.opts, tc.admin, tc.readonly)
		var failure *RuleMutationError
		if !errors.As(err, &failure) || failure.Code != tc.code {
			t.Errorf("wanted %s, received %v", tc.code, err)
		}
	}
	if settings := e.DecisionTimeoutSettings(); settings.Seconds != 30 || settings.Revision != "1" {
		t.Fatalf("failed changes mutated settings: %+v", settings)
	}
}

func TestDecisionTimeoutReadOnlyAPI(t *testing.T) {
	e := New(30 * time.Second)
	e.InitDecisionTimeout(16, 1, func(int, uint64) error { return nil })
	dir := filepath.Join(t.TempDir(), "api")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "s")
	listener, err := Serve(path, e, true)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	r, err := Call(path, Request{Version: 1, Operation: "decision-timeout-status"})
	if err != nil || r.DecisionTimeout == nil || r.DecisionTimeout.Seconds != 16 || !slices.Contains(r.Capabilities, DecisionTimeoutCapability) {
		t.Fatalf("read-only status = %+v, error %v", r, err)
	}
	r = callResponse(path, Request{Version: 1, Operation: "decision-timeout-configure", Generation: e.Generation,
		DecisionTimeout: &DecisionTimeoutOptions{Seconds: 4, ExpectedRevision: "1"}})
	if r.ErrorCode != "forbidden" || r.DecisionTimeout != nil {
		t.Fatalf("read-only mutation = %+v", r)
	}
}

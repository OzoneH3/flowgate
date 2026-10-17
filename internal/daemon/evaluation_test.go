package daemon

import (
	"flowgate/internal/store"
	"os"
	"path/filepath"
	"testing"
)

type fakeEvaluation struct {
	starts, stops int
	s             EvaluationStatus
}

func (f *fakeEvaluation) Status() EvaluationStatus                    { return f.s }
func (f *fakeEvaluation) Readiness() EvaluationStatus                 { return f.s }
func (f *fakeEvaluation) Start(a, b string) (EvaluationStatus, error) { f.starts++; return f.s, nil }
func (f *fakeEvaluation) Stop(a string) (EvaluationStatus, error)     { f.stops++; return f.s, nil }
func TestEvaluationPermissionNotImpliedByRules(t *testing.T) {
	f := &fakeEvaluation{s: EvaluationStatus{State: "active", Profile: "incoming", DurationSeconds: 300}}
	a := newDeleteAPI(t, func(e *Engine, _ *store.Store) { e.Mode = "daemon-monitor"; e.Evaluation = f })
	ro := filepath.Join(filepath.Dir(a.path), "readonly")
	l, err := Serve(ro, a.e, true)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	q := Request{Version: 1, Operation: "evaluation-start", Generation: a.e.Generation, Profile: "incoming", RequestID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	assertCode(t, callResponse(ro, q), "forbidden")
	if os.Getuid() != 0 {
		r := callResponse(a.path, Request{Version: 1, Operation: "list"})
		if !r.Permissions.CanManageRules || r.Permissions.CanControlEvaluation {
			t.Fatal(r.Permissions)
		}
		assertCode(t, callResponse(a.path, q), "forbidden")
	}
	if f.starts != 0 || f.stops != 0 {
		t.Fatal("forbidden request reached manager")
	}
	r := callResponse(ro, Request{Version: 1, Operation: "evaluation-readiness", Generation: a.e.Generation, Profile: "incoming"})
	if r.Error != "" || r.Evaluation == nil {
		t.Fatal(r)
	}
	if r.Permissions.CanDecide {
		t.Fatal("companion got decision authority")
	}
	if c, d := coverage("daemon-monitor", "incoming", &EnforcementStatus{State: "active", Profile: "incoming"}); !c.Covered || !d.Known {
		t.Fatal(c, d)
	}
	a.e.ResetAdmission()
	if len(a.e.Rules(uint32(os.Getuid()), true)) != 1 {
		t.Fatal("Stop reset stored rules")
	}
}

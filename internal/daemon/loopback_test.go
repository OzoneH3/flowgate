package daemon

import (
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"net"
	"testing"
)

func TestDefaultLocalhostDoesNotRequireRuntimeCensus(t *testing.T) {
	e, f, a, _ := fixture()
	is, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range is {
		if i.Flags&net.FlagLoopback != 0 {
			f.Interface = uint32(i.Index)
		}
	}
	calls := 0
	e.Resolve = func(identity.Flow) identity.Attribution { calls++; return *a }
	e.TryResolve = func(identity.Flow) (identity.Attribution, bool) {
		t.Fatal("localhost waited for runtime census")
		return identity.Attribution{}, false
	}
	for _, proto := range []string{"tcp", "udp"} {
		f.Protocol = proto
		v, ok := e.TryObserve(f, "local")
		if !ok || v.State != "allowed" || v.Rule != policy.DefaultLoopback || calls != 0 {
			t.Fatal(v, ok, calls)
		}
	}
	r := policy.Rule{Schema: 2, ID: "explicit", Action: "block", Filter: policy.Filter{Application: "app", Revision: "rev", UID: 1000, Direction: f.Direction, Protocol: f.Protocol, RemoteAddress: "127.0.0.1"}}
	if err = e.SetRules([]policy.Rule{r}); err != nil {
		t.Fatal(err)
	}
	v := e.Observe(f, "explicit")
	if v.State != "blocked" || v.Rule != "explicit" || calls == 0 {
		t.Fatal(v, calls)
	}
}

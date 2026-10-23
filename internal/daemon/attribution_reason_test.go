package daemon

import (
	"encoding/json"
	"flowgate/internal/identity"
	"testing"
)

func TestAttributionReasonDoesNotGrantAuthorityAndReachesRecords(t *testing.T) {
	for _, status := range []string{"unidentified", "directly-associated", "corroborated"} {
		for _, code := range []string{"", identity.ReasonNoSocketObserved, identity.ReasonNativeOwnerObserved, identity.ReasonRuntimeBrokerUnavailable, "future_reason"} {
			e, f, a, _ := fixture()
			*a = identity.Attribution{Status: status, Reason: "no visible matching socket", ReasonCode: code}
			v := e.Observe(f, "udp")
			if v.Attribution.Application != nil || v.State != "blocked" {
				t.Fatalf("code granted authority %q: %+v", code, v)
			}
			r := e.baseRecord(&v, "final")
			if r.Attribution.ReasonCode != code || r.Attribution.Reason != a.Reason || r.PrincipalUID != nil {
				t.Fatalf("log evidence/projection changed: %+v", r)
			}
			b, err := json.Marshal(v)
			if err != nil {
				t.Fatal(err)
			}
			var round Event
			if err = json.Unmarshal(b, &round); err != nil {
				t.Fatal(err)
			}
			if round.Attribution.ReasonCode != code {
				t.Fatal("event code lost")
			}
		}
	}
}

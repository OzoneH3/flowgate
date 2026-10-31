package daemon

import (
	"flowgate/internal/policy"
	"testing"
	"time"
)

func TestQueueSchedulingHintExpiresAndInvalidatesWithoutPermission(t *testing.T) {
	e, f, a, now := fixture()
	e.LocalPeer = nil
	r := policy.Rule{ID: "temporary", Action: "block", Expires: now.Add(time.Second), Filter: policy.Remembered(f, *a)}
	e.rules = []policy.Rule{r}
	v := e.Observe(f, "udp")
	epoch, until := v.QueueSchedulingHint()
	if v.State != "blocked" || !until.Equal(r.Expires) {
		t.Fatal("scheduling hint outlived policy", v.State, until, r.Expires)
	}
	e.mu.Lock()
	e.resetCachedLocked("edited policy")
	e.mu.Unlock()
	if e.QueuePolicyEpoch() == epoch {
		t.Fatal("old policy scheduling mark retained")
	}
	old, _ := v.QueueSchedulingHint()
	if old != epoch {
		t.Fatal("event metadata changed retrospectively")
	}
}

func TestQueueAllowedSchedulingHintDoesNotExpireAtPacketDeadline(t *testing.T) {
	v := Event{State: "allowed", Deadline: time.Now().Add(time.Millisecond)}
	_, until := v.QueueSchedulingHint()
	if !until.IsZero() {
		t.Fatal("packet deadline became completed-allow scheduling expiry")
	}
	expires := time.Now().Add(time.Minute)
	v.decided = &policy.Rule{Expires: expires}
	_, until = v.QueueSchedulingHint()
	if !until.Equal(expires) {
		t.Fatal("temporary rule horizon lost")
	}
}

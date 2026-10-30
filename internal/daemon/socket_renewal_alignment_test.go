package daemon

import (
	"flowgate/internal/identity"
	"testing"
	"time"
)

func alignmentFixture() (*socketAuthorization, *socketFlow, *socketFlow, time.Time, uint64) {
	now := time.Now()
	boot := uint64(time.Second)
	a := &socketFlow{runtime: true, haveKey: true, application: "verified-app-uid-prefix", deadline: boot + uint64(150*time.Millisecond), next: now}
	a.noteRenewalDuration(100 * time.Millisecond)
	b := *a
	b.busy = true
	b.verificationStarted = now.Add(-80 * time.Millisecond)
	s := &socketAuthorization{flows: map[string]*socketFlow{"a": a, "b": &b}, resolveGroup: func([]identity.Flow, func(int, *identity.Attribution)) {}}
	return s, a, &b, now, boot
}
func TestSocketAuthorizationAlignmentCompletionAndBound(t *testing.T) {
	s, a, b, now, boot := alignmentFixture()
	if !s.alignRenewal(a, now, boot) {
		t.Fatal("eligible alignment refused")
	}
	if s.nextRenewal(now, boot) != nil || s.nextRenewalWake(now) != 22*time.Millisecond {
		t.Fatal("wait not bounded/scheduled")
	}
	if s.nextRenewal(now.Add(25*time.Millisecond), boot) != a {
		t.Fatal("busy peer exceeded bound")
	}
	b.busy = false
	if s.nextRenewal(now.Add(time.Millisecond), boot) == nil {
		t.Fatal("completion did not release wait")
	}
	group := s.renewalGroup(a, now.Add(time.Millisecond))
	s.finishAlignment(group, now.Add(time.Millisecond))
	if len(group) != 2 || s.alignmentSuccesses != 1 || s.alignmentWaitNS != uint64(time.Millisecond) {
		t.Fatal("alignment not recorded")
	}
	if a.deadline != boot+uint64(150*time.Millisecond) {
		t.Fatal("expiry changed")
	}
	b.busy = true
	if s.alignRenewal(a, now, boot) {
		t.Fatal("repeated attempt")
	}
}
func TestSocketAuthorizationAlignmentRefusals(t *testing.T) {
	for _, kind := range []string{"slack", "no-timing", "application", "prefix", "uid", "namespace", "direction", "native", "unverified", "attempted"} {
		t.Run(kind, func(t *testing.T) {
			s, a, b, now, boot := alignmentFixture()
			switch kind {
			case "slack":
				a.deadline = boot + uint64(141*time.Millisecond)
			case "no-timing":
				a.renewalDurations = [16]time.Duration{}
				b.renewalDurations = [16]time.Duration{}
			case "application", "prefix", "uid":
				b.application = "other-verified-" + kind
			case "namespace":
				b.flow.NetNS = "other"
			case "direction":
				b.flow.Direction = "incoming"
			case "native":
				b.runtime = false
			case "unverified":
				b.haveKey = false
			case "attempted":
				b.alignmentAttempted = true
			}
			if s.alignRenewal(a, now, boot) || s.alignmentDeferrals != 0 {
				t.Fatal("ineligible deferral")
			}
		})
	}
}
func TestSocketAuthorizationAlignmentFailedAttemptNotRepeated(t *testing.T) {
	s, a, b, now, boot := alignmentFixture()
	if !s.alignRenewal(a, now, boot) {
		t.Fatal("no first attempt")
	}
	s.finishAlignment([]*socketFlow{a}, now.Add(25*time.Millisecond))
	if s.alignmentSuccesses != 0 || s.alignRenewal(a, now.Add(time.Second), boot) {
		t.Fatal("failed pairing repeated")
	}
	b.busy = false
	a.busy = true
	if s.alignRenewal(b, now.Add(time.Second), boot) {
		t.Fatal("reverse pairing repeated")
	}
}

func TestSocketAuthorizationAlignmentLeavesOtherWorkRunnable(t *testing.T) {
	s, a, _, now, boot := alignmentFixture()
	other := &socketFlow{haveKey: true, deadline: boot + uint64(200*time.Millisecond), next: now}
	s.flows["native"] = other
	if !s.alignRenewal(a, now, boot) {
		t.Fatal("no deferral")
	}
	if s.nextRenewal(now, boot) != other {
		t.Fatal("unrelated due work blocked")
	}
}
func TestSocketAuthorizationAlignmentDoesNotSpendAttemptOnDistantPeer(t *testing.T) {
	s, a, b, now, boot := alignmentFixture()
	b.verificationStarted = now.Add(-50 * time.Millisecond)
	if s.alignRenewal(a, now, boot) || a.alignmentAttempted || b.alignmentAttempted {
		t.Fatal("distant prediction consumed attempt")
	}
	b.verificationStarted = now.Add(-80 * time.Millisecond)
	if !s.alignRenewal(a, now, boot) {
		t.Fatal("feasible later attempt unavailable")
	}
}

func TestSocketAuthorizationAlignmentRetryRequiresTimeAndPublications(t *testing.T) {
	s, a, b, now, boot := alignmentFixture()
	if !s.alignRenewal(a, now, boot) {
		t.Fatal("first attempt refused")
	}
	s.finishAlignment([]*socketFlow{a}, now.Add(25*time.Millisecond))
	later := now.Add(5 * time.Second)
	b.verificationStarted = later.Add(-80 * time.Millisecond)
	if s.alignRenewal(a, later, boot) {
		t.Fatal("time alone retried")
	}
	a.alignmentPublications = 10
	b.alignmentPublications = 9
	if s.alignRenewal(a, later, boot) {
		t.Fatal("peer without ten clean cycles retried")
	}
	b.alignmentPublications = 10
	if s.alignRenewal(a, now.Add(4*time.Second), boot) {
		t.Fatal("cycles alone retried")
	}
	if !s.alignRenewal(a, later, boot) {
		t.Fatal("bounded retry unavailable")
	}
	if a.alignmentPublications != 0 || b.alignmentPublications != 0 {
		t.Fatal("retry did not reset evidence")
	}
}

func TestSocketAuthorizationAlignmentPublicationsPermitRecoveryAfterLapse(t *testing.T) {
	e, s, f, a, _ := wineGrantFixture(t)
	e.finishSocketAuthorizationLocked(s, f, s.store.Begin(), a)
	for i := 0; i < 10; i++ {
		e.finishSocketAuthorizationLocked(s, f, s.store.Begin(), a)
	}
	if f.alignmentPublications != 11 {
		t.Fatal("successful cycles not counted", f.alignmentPublications)
	}
	f.deadline = 1
	e.finishSocketAuthorizationLocked(s, f, s.store.Begin(), a)
	if f.alignmentPublications != 12 {
		t.Fatal("fresh publication after lapse did not count toward recovery")
	}
}

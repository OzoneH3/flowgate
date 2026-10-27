package uploadshape

import (
	"testing"
	"time"
)

func ms(v int64) *int64 { return &v }

// The reader-side view ages the controller observation by the snapshot's held
// time, crosses the 1 s / 2 s boundaries exactly, never upgrades the
// controller's own label, and keeps the unknown sentinel for missing data.
func TestVerificationViewAgesAndNeverUpgrades(t *testing.T) {
	anchor := time.Now()
	k := &KernelStatus{VerifiedAgeMillis: ms(300), Verification: "fresh"}
	for _, tc := range []struct {
		held  time.Duration
		label string
	}{{0, "fresh"}, {700 * time.Millisecond, "fresh"}, {701 * time.Millisecond, "stale"}, {1700 * time.Millisecond, "stale"}, {1701 * time.Millisecond, "unknown"}, {10 * time.Second, "unknown"}} {
		age, label := verificationView(k, anchor, anchor.Add(tc.held))
		if label != tc.label || *age != 300+tc.held.Milliseconds() {
			t.Fatalf("held %v: got %s/%d want %s", tc.held, label, *age, tc.label)
		}
	}
	if _, label := verificationView(&KernelStatus{VerifiedAgeMillis: ms(100), Verification: "stale"}, anchor, anchor); label != "stale" {
		t.Fatalf("controller 'stale' must not be upgraded to fresh, got %s", label)
	}
	if age, label := verificationView(&KernelStatus{VerifiedAgeMillis: ms(100), Verification: "unknown"}, anchor, anchor); label != "unknown" || age == nil {
		t.Fatalf("controller 'unknown' stays unknown with its age, got %s", label)
	}
	if age, label := verificationView(&KernelStatus{}, anchor, anchor); age != nil || label != "unknown" {
		t.Fatalf("missing observation must be unknown without age, got %v/%s", age, label)
	}
	if age, label := verificationView(nil, anchor, anchor); age != nil || label != "unknown" {
		t.Fatalf("nil kernel status: %v/%s", age, label)
	}
}

// A cached snapshot ages with no new RPC: the published state degrades from
// Active to Partial as the held time crosses the thresholds, while Applying
// and Unsupported are preserved exactly.
func TestSnapshotAgesCachedVerificationWithoutRPC(t *testing.T) {
	m := newManager(Options{})
	m.snap.Kernel = &KernelStatus{VerifiedAgeMillis: ms(200), Verification: "fresh", Covered: 2}
	m.snap.VerifiedUntil = time.Now().Add(time.Hour)
	for _, tc := range []struct {
		held    time.Duration
		status  string
		want    string
		label   string
		covered int
	}{{0, "Active", "Active", "fresh", 2}, {900 * time.Millisecond, "Active", "Partial", "stale", 2}, {3 * time.Second, "Active", "Partial", "unknown", 2}, {3 * time.Second, "Applying", "Applying", "unknown", 2}, {3 * time.Second, "Unsupported", "Unsupported", "unknown", 2}} {
		m.sampleStart = time.Now().Add(-tc.held)
		m.sampleReceived = m.sampleStart
		m.snap.Status = tc.status
		s := m.Snapshot()
		if s.Status != tc.want || s.Verification != tc.label || s.VerificationAgeMillis == nil || *s.VerificationAgeMillis < 200+tc.held.Milliseconds() {
			t.Fatalf("held %v from %s: got %s/%s/%v", tc.held, tc.status, s.Status, s.Verification, s.VerificationAgeMillis)
		}
		if m.snap.Status != tc.status {
			t.Fatal("reading a snapshot must not change the published state")
		}
	}
}

// The age already includes time spent inside the RPC before it was sampled.
// Report the uncertainty, rather than claiming request-anchored age is exact.
func TestVerificationIntervalTransportAndHeldTime(t *testing.T) {
	start := time.Now()
	received := start.Add(400 * time.Millisecond)
	k := &KernelStatus{VerifiedAgeMillis: ms(700), Verification: "fresh"}
	for _, held := range []time.Duration{0, 250 * time.Millisecond, 2 * time.Second} {
		lo, hi, h, r := verificationInterval(k, start, received, received.Add(held))
		if *lo != 700+held.Milliseconds() || *hi != 1101+held.Milliseconds() || *h != held.Milliseconds() || *r != 400 || *lo > *hi {
			t.Fatalf("held=%v bounds=%v,%v held/rpc=%v/%v", held, *lo, *hi, *h, *r)
		}
	}
	// Millisecond flooring at both clocks must not hide fractional uncertainty.
	lo, hi, _, _ := verificationInterval(k, start, start.Add(1500*time.Microsecond), start.Add(2750*time.Microsecond))
	if *lo != 701 || *hi != 704 {
		t.Fatalf("fractional bounds %d/%d", *lo, *hi)
	}
	for _, tc := range []struct {
		k                   *KernelStatus
		start, receipt, now time.Time
	}{
		{nil, start, received, received}, {&KernelStatus{}, start, received, received},
		{&KernelStatus{VerifiedAgeMillis: ms(-1)}, start, received, received},
		{k, time.Time{}, received, received}, {k, start, time.Time{}, received},
		{k, received, start, received}, {k, start, received, start},
	} {
		lo, hi, _, _ := verificationInterval(tc.k, tc.start, tc.receipt, tc.now)
		if lo != nil || hi != nil {
			t.Fatal("invalid observation must stay unknown")
		}
	}
}

func TestSnapshotIntervalPreservesPublishedObservation(t *testing.T) {
	m := newManager(Options{})
	m.sampleReceived = time.Now().Add(-2 * time.Second)
	m.sampleStart = m.sampleReceived.Add(-400 * time.Millisecond)
	m.snap.Kernel = &KernelStatus{VerifiedAgeMillis: ms(700), Verification: "fresh", Covered: 1}
	m.snap.VerifiedUntil = time.Now().Add(time.Second)
	m.snap.Status = "Applying"
	s := m.Snapshot()
	if s.Verification != "unknown" || s.Status != "Applying" || *s.VerificationAgeMinMillis < 2700 || *s.VerificationAgeMillis < 3101 {
		t.Fatalf("bad interval/state %+v", s)
	}
	if *s.Kernel.VerifiedAgeMillis != 700 || s.Kernel.Verification != "fresh" || *m.snap.Kernel.VerifiedAgeMillis != 700 {
		t.Fatal("controller observation must remain immutable")
	}
	if s.CoverageExpired || s.Kernel.Covered != 1 {
		t.Fatal("observation recency must not substitute for lease validity")
	}
}

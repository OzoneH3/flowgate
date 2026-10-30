package daemon

import "time"

const renewalAlignmentLimit = 25 * time.Millisecond
const renewalAlignmentMargin = 20 * time.Millisecond

// ApplicationKey includes executable, UID and Wine prefix. This is scheduling
// eligibility only: every selected flow still obtains a fresh independent proof.
func renewalPeers(a, b *socketFlow) bool {
	return a != b && a.runtime && b.runtime && a.haveKey && b.haveKey &&
		a.application != "" && a.application == b.application &&
		a.flow.NetNS == b.flow.NetNS && a.flow.Direction == b.flow.Direction && a.flow.Protocol == b.flow.Protocol
}

func (f *socketFlow) noteRenewalDuration(d time.Duration) {
	f.renewalDurations[f.renewalDurationIndex%len(f.renewalDurations)] = d
	f.renewalDurationIndex++
}
func (f *socketFlow) maxRenewalDuration() time.Duration {
	var d time.Duration
	for _, v := range f.renewalDurations {
		if v > d {
			d = v
		}
	}
	return d
}
func (f *socketFlow) renewalEligibleAt() time.Time {
	if f.batchPending != nil {
		return f.batchPending.frozen
	}
	if f.alignmentPeer != nil && f.alignmentPeer.busy && f.alignmentUntil.After(f.next) {
		return f.alignmentUntil
	}
	return f.next
}

// Retry only after five seconds and ten successful publications on both peers.
// Never waits for
// arrivals or starts observations while waiting. The current grant is unchanged.
// Measured slack is a scheduling heuristic, not a worst-case latency guarantee;
// the kernel's hard deadline remains authoritative even if the estimate fails.
func (s *socketAuthorization) alignRenewal(f *socketFlow, now time.Time, boot uint64) bool {
	if s.resolveGroup == nil || !f.canAlign(now) || !f.runtime || !f.haveKey {
		return false
	}
	for _, peer := range s.flows {
		if !peer.busy || !peer.canAlign(now) || !renewalPeers(f, peer) {
			continue
		}
		peerCost := peer.maxRenewalDuration()
		if peer.verificationStarted.IsZero() || peerCost <= 0 {
			continue
		}
		remaining := peer.verificationStarted.Add(peerCost).Sub(now)
		if remaining <= 0 || remaining > renewalAlignmentLimit {
			continue
		}
		// Small completion-wake allowance, still inside the fixed cap.
		wait := remaining + 2*time.Millisecond
		if wait > renewalAlignmentLimit {
			wait = renewalAlignmentLimit
		}
		cost := f.maxRenewalDuration()
		if p := peer.maxRenewalDuration(); p > cost {
			cost = p
		}
		if cost <= 0 || f.deadline <= boot {
			continue
		}
		// Reserve the predicted remaining wait, measured rolling maximum and margin.
		if time.Duration(f.deadline-boot) < wait+cost+renewalAlignmentMargin {
			continue
		}
		f.alignmentAttempted = true
		peer.alignmentAttempted = true
		f.alignmentLastAttempt = now
		peer.alignmentLastAttempt = now
		f.alignmentPublications = 0
		peer.alignmentPublications = 0
		f.alignmentPeer = peer
		f.alignmentStarted = now
		f.alignmentUntil = now.Add(wait)
		s.alignmentDeferrals++
		return true
	}
	return false
}
func (s *socketAuthorization) finishAlignment(group []*socketFlow, now time.Time) {
	for _, f := range group {
		if f.alignmentPeer == nil {
			continue
		}
		waited := now.Sub(f.alignmentStarted)
		if waited > 0 {
			s.alignmentWaitNS += uint64(waited)
			if uint64(waited) > s.alignmentMaxWaitNS {
				s.alignmentMaxWaitNS = uint64(waited)
			}
		}
		for _, peer := range group {
			if peer == f.alignmentPeer {
				s.alignmentSuccesses++
				break
			}
		}
		f.alignmentPeer = nil
	}
}

// Only completed fresh publications count; packet hits do not. A lapse does
// not prevent recovery once the time, publication count and slack checks pass.
func (f *socketFlow) canAlign(now time.Time) bool {
	return !f.alignmentAttempted || (!f.alignmentLastAttempt.IsZero() && now.Sub(f.alignmentLastAttempt) >= 5*time.Second && f.alignmentPublications >= 10)
}

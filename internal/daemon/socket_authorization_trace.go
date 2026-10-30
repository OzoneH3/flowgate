package daemon

import "flowgate/internal/socketgrant"

// Fixed-size lab-only ring. Timing evidence never renews a grant. The sequence
// and overwritten count make truncation explicit instead of hiding gaps.
const socketRenewalTraceLimit = 4096

type socketRenewalTrace struct {
	Due              uint64 `json:"due_boot_ns"`
	Sequence         uint64 `json:"sequence"`
	Flow             string `json:"flow"`
	Start            uint64 `json:"start_boot_ns"`
	Resolved         uint64 `json:"resolved_boot_ns"`
	Finished         uint64 `json:"finished_boot_ns"`
	PreviousDeadline uint64 `json:"previous_deadline_boot_ns"`
	Deadline         uint64 `json:"deadline_boot_ns"`
	Published        bool   `json:"published"`
	HasGrant         bool   `json:"has_grant"`
	Reason           string `json:"reason"`
}

func (s *socketAuthorization) recordRenewal(row socketRenewalTrace) {
	if s.trace == nil {
		s.trace = make([]socketRenewalTrace, socketRenewalTraceLimit)
	}
	row.Sequence = s.traceCount
	s.trace[s.traceCount%socketRenewalTraceLimit] = row
	s.traceCount++
}
func (s *socketAuthorization) renewalTrace() ([]socketRenewalTrace, uint64) {
	start := uint64(0)
	if s.traceCount > socketRenewalTraceLimit {
		start = s.traceCount - socketRenewalTraceLimit
	}
	rows := make([]socketRenewalTrace, 0, s.traceCount-start)
	for i := start; i < s.traceCount; i++ {
		rows = append(rows, s.trace[i%socketRenewalTraceLimit])
	}
	return rows, start
}

func (s *socketAuthorization) traceCompletion(f *socketFlow, ticket socketgrant.Ticket, resolved uint64, reason string, finish func()) {
	before := s.published
	previous := f.deadline
	finish()
	s.recordRenewal(socketRenewalTrace{Due: f.scheduledDue, Flow: f.flow.Key(), Start: ticket.Deadline() - uint64(socketgrant.Window), Resolved: resolved, Finished: socketgrant.BootNow(), PreviousDeadline: previous, Deadline: f.deadline, Published: s.published != before, HasGrant: f.haveKey, Reason: reason})
}

package daemon

import (
	"flowgate/internal/readiness"
	"time"
)

const EvaluationCapability = "daemon-evaluation-v1"

type EvaluationReadiness struct {
	State     string            `json:"state"`
	CheckedAt time.Time         `json:"checked_at"`
	Checks    []readiness.Check `json:"checks"`
}
type EvaluationStatus struct {
	Review              string              `json:"review"`
	UnsupportedOutgoing string              `json:"unsupported_outgoing"`
	ID                  string              `json:"id"`
	RequestID           string              `json:"request_id"`
	State               string              `json:"state"`
	Profile             string              `json:"profile"`
	StopsAt             time.Time           `json:"stops_at"`
	DurationSeconds     int                 `json:"duration_seconds"`
	Cleanup             string              `json:"cleanup"`
	ReasonCode          string              `json:"reason_code"`
	Reason              string              `json:"reason"`
	Readiness           EvaluationReadiness `json:"readiness"`
}
type EvaluationManager interface {
	Status() EvaluationStatus
	Readiness() EvaluationStatus
	Start(expected, request string) (EvaluationStatus, error)
	Stop(expected string) (EvaluationStatus, error)
}

// ResetAdmission keeps stored policy, observation and collector ownership intact.
// Called only after the queue has drained/dropped retained packets.
func (e *Engine) ResetAdmission() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.flushCapacity(e.Now(), true)
	e.discardPendingLocked("evaluation stopped; retained packets drop")
	e.events = map[string]*Event{}
}

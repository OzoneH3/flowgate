package identity

import (
	"fmt"
	"time"
)

// Optional socket-level UDP accounting; no per-peer totals are manufactured.
type UDPCount struct {
	Uploaded   uint64    `json:"uploaded"`
	Downloaded uint64    `json:"downloaded"`
	Since      time.Time `json:"since"`
}
type UDPSnapshot struct {
	// Nil means this older helper cannot report tracing skips.
	TracingSkipped *uint64 `json:"tracing_skipped_runs,omitempty"`
	// Private observation feed. Never serialized or projected to an API client.
	AccountingRows map[string]UDPCount `json:"-"`
	Retired        map[string]UDPCount `json:"-"`
	FinalsLost     uint64              `json:"final_snapshots_lost,omitempty"`

	Machine    bool                `json:"machine_scope,omitempty"`
	SampleNS   int64               `json:"sample_ns"`
	Version    int                 `json:"version"`
	UID        uint32              `json:"uid"`
	NetNS      string              `json:"netns"`
	State      string              `json:"state"`
	Reason     string              `json:"reason"`
	Generation string              `json:"generation"`
	Collected  time.Time           `json:"collected"`
	Missed     uint64              `json:"missed_operations"`
	Rows       map[string]UDPCount `json:"rows"`
}

// TracingGapReason describes missing invocations, never estimated byte loss.
func (s UDPSnapshot) TracingGapReason() string {
	if s.TracingSkipped == nil {
		return "Tracing-skip diagnostics unavailable; possible undercount is unquantified"
	}
	if *s.TracingSkipped > 0 {
		return fmt.Sprintf("Possible undercount: %d skipped tracing runs across all socket families; UDP operations and missing bytes are unknown", *s.TracingSkipped)
	}
	return ""
}

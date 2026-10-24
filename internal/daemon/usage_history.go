package daemon

import (
	"errors"
	"flowgate/internal/accounting"
	"fmt"
)

// Shared by the primary and read-only companion; peer identity comes only from
// authenticated SO_PEERCRED. Queries never accept a UID or permission target.
func (e *Engine) UsageHistoryRead(generation string, q accounting.HistoryQuery, uid uint32, admin bool) (accounting.HistorySnapshot, error) {
	if generation != e.Generation {
		return accounting.HistorySnapshot{}, mutationError("stale_generation", "Daemon changed; refresh history")
	}
	if e.UsageHistory == nil {
		return accounting.HistorySnapshot{}, fmt.Errorf("usage history unavailable")
	}
	if q.Unattributed && !admin {
		return accounting.HistorySnapshot{}, mutationError("forbidden", "Unattributed history requires administrator")
	}
	return e.UsageHistory.Query(q, uid, admin)
}
func (e *Engine) UsageHistoryConfigure(generation string, o accounting.HistoryOptions, admin, readonly bool) (accounting.HistorySettings, error) {
	if !admin || readonly {
		return accounting.HistorySettings{}, mutationError("forbidden", "History settings require administrator on the primary endpoint")
	}
	if generation != e.Generation {
		return accounting.HistorySettings{}, mutationError("stale_generation", "Daemon changed; refresh history settings")
	}
	if e.UsageHistory == nil {
		return accounting.HistorySettings{}, fmt.Errorf("usage history unavailable")
	}
	return e.UsageHistory.Configure(o)
}

func usageHistoryError(r *Response, err error) {
	if err == nil {
		return
	}
	r.ErrorCode, r.Error = "invalid_request", err.Error()
	var v *RuleMutationError
	if errors.As(err, &v) {
		r.ErrorCode = v.Code
	}
}

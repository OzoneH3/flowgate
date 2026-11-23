package daemon

import (
	"errors"

	"flowgate/internal/uploadshape"
)

// Authenticated machine administrator only. Companion status is allowed but
// never mutation. No request can select helper paths or expand interface scope.
func (e *Engine) uploadRequest(q Request, admin, readonly bool) (uploadshape.Snapshot, error) {
	if !admin || (readonly && q.Operation == "upload-configure") {
		return uploadshape.Snapshot{}, mutationError("forbidden", "Upload shaping requires administrator; read-only endpoints cannot configure")
	}
	if q.Generation == "" || q.Generation != e.Generation {
		return uploadshape.Snapshot{}, mutationError("stale_generation", "Daemon changed; refresh")
	}
	if e.UploadShaping == nil {
		return uploadshape.Snapshot{}, mutationError("unavailable", "Experimental native upload was not enabled at daemon startup")
	}
	if q.Operation == "upload-status" {
		return e.UploadShaping.Snapshot(), nil
	}
	if q.UploadConfig == nil || q.ExpectedVersion == nil {
		return uploadshape.Snapshot{}, mutationError("invalid_request", "Explicit desired configuration and expected_version required")
	}
	s, err := e.UploadShaping.Configure(*q.ExpectedVersion, *q.UploadConfig)
	if err != nil {
		code := "invalid_request"
		if errors.Is(err, uploadshape.ErrSavePreferences) {
			code = "persistence_failed"
		} else if err.Error() == "stale_version" || err.Error() == "schema_upgrade_required" || err.Error() == "allocation_below_minimum" {
			code = err.Error()
		}
		return s, mutationError(code, err.Error())
	}
	return s, nil
}

package daemon

const ProtectionCapability = "continuous-firewall-v1"

// ProtectionStatus deliberately has no deadline. Desired mode is durable, state
// describes the current consumer, never a promise derived from configuration.
type ProtectionStatus struct {
	ID                  string              `json:"id"`
	RequestID           string              `json:"request_id"`
	DesiredMode         string              `json:"desired_mode"`
	State               string              `json:"state"`
	Profile             string              `json:"profile"`
	Cleanup             string              `json:"cleanup"`
	ReasonCode          string              `json:"reason_code"`
	Reason              string              `json:"reason"`
	Readiness           EvaluationReadiness `json:"readiness"`
	ExistingConnections string              `json:"existing_connections"`
	FailurePolicy       string              `json:"failure_policy"`
	GUIRequired         bool                `json:"gui_required"`
}
type ProtectionManager interface {
	ProtectionStatus() ProtectionStatus
	ProtectionReadiness(profile string) (ProtectionStatus, error)
	ProtectionStart(expected, request, profile string) (ProtectionStatus, error)
	ProtectionStop(expected string) (ProtectionStatus, error)
}

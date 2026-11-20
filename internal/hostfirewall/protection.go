package hostfirewall

import (
	"encoding/json"
	"flowgate/internal/daemon"
	"flowgate/internal/decisionlog"
	"fmt"
	"os"
	"path/filepath"
)

type desiredProtection struct {
	Schema int    `json:"schema"`
	Mode   string `json:"mode"`
}

func validProfile(p string) bool { return p == "incoming" || p == "both" }

// ConfigureProtection does not activate or mutate firewall state. Only explicit
// configuration installs this API; administrator authority is still required.
func (m *Evaluation) ConfigureProtection(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("desired protection path must be absolute")
	}
	if err := daemon.SecureDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	m.desiredPath = path
	m.desiredMode = "monitoring"
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var d desiredProtection
	if len(b) > 4096 || json.Unmarshal(b, &d) != nil || d.Schema != 1 || (!validProfile(d.Mode) && d.Mode != "monitoring") {
		return fmt.Errorf("invalid desired protection state; refusing implicit monitoring fallback")
	}
	m.desiredMode = d.Mode
	return nil
}

// Caller holds lifecycle mutex. Durability must precede a mode transition.
func (m *Evaluation) saveDesired(mode string) error {
	if m.desiredPath == "" {
		return lifecycleError("unavailable", "Continuous protection not configured")
	}
	b, _ := json.Marshal(desiredProtection{1, mode})
	f, err := os.CreateTemp(filepath.Dir(m.desiredPath), ".desired-*")
	if err != nil {
		return lifecycleError("persistence_failed", err.Error())
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(f.Name(), m.desiredPath)
	}
	if err == nil {
		var d *os.File
		d, err = os.Open(filepath.Dir(m.desiredPath))
		if err == nil {
			err = d.Sync()
			d.Close()
		}
	}
	if err != nil {
		return lifecycleError("persistence_failed", err.Error())
	}
	m.desiredMode = mode
	return nil
}
func (m *Evaluation) ProtectionStatus() daemon.ProtectionStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.status
	if !m.continuous {
		s.State = "stopped"

		s.Reason = "Monitoring only; continuous interception not active"
		s.ReasonCode = "monitoring"
		if m.cancel != nil {
			s.ReasonCode = "evaluation_active"
			s.Reason = "Bounded evaluation owns interception; stop it before continuous Start"
		}
	}
	return daemon.ProtectionStatus{ID: s.ID, RequestID: s.RequestID, DesiredMode: m.desiredMode, State: s.State, Profile: s.Profile, Cleanup: s.Cleanup, ReasonCode: s.ReasonCode, Reason: s.Reason, Readiness: s.Readiness, ExistingConnections: "Existing connections are preserved at activation. During active protection, creating or enabling a newly winning Block can disconnect verified established TCP sockets.", FailurePolicy: "New TCP/UDP fail closed on consumer loss; pre-existing admitted connections may continue. Explicit Stop returns to monitoring.", GUIRequired: false}
}
func (m *Evaluation) ProtectionReadiness(profile string) (daemon.ProtectionStatus, error) {
	if !validProfile(profile) {
		return m.ProtectionStatus(), lifecycleError("invalid_request", "profile must be incoming or both")
	}
	m.mu.Lock()
	if m.cancel != nil || m.probing {
		m.mu.Unlock()
		return m.ProtectionStatus(), lifecycleError("busy", "Lifecycle operation in progress")
	}
	m.status.Profile = profile
	m.mu.Unlock()
	m.Readiness()
	return m.ProtectionStatus(), nil
}
func (m *Evaluation) ProtectionStart(expected, request, profile string) (daemon.ProtectionStatus, error) {
	if !validProfile(profile) {
		return m.ProtectionStatus(), lifecycleError("invalid_request", "profile must be incoming or both")
	}
	_, err := m.start(expected, request, profile, true)
	return m.ProtectionStatus(), err
}
func (m *Evaluation) ProtectionStop(expected string) (daemon.ProtectionStatus, error) {
	_, err := m.stop(expected, true)
	return m.ProtectionStatus(), err
}

// Restore is called after policy loading and before API creation. It uses the same
// readiness/activation path as Start, never a privileged bypass.
func (m *Evaluation) Restore() error {
	m.mu.Lock()
	mode := m.desiredMode
	id := m.status.ID
	m.mu.Unlock()
	if mode == "monitoring" {
		// A crash after saving Stop but before cleanup must finish that exact owned
		// cleanup before a new API reports monitoring. No application policy changes.
		if err := RecoverContinuous(m.dir); err != nil {
			return err
		}
		if err := RemoveGuard(m.dir); err != nil {
			return err
		}
		m.mu.Lock()
		m.status.Cleanup = "confirmed"
		m.mu.Unlock()
		return nil
	}
	_, err := m.ProtectionStart(id, decisionlog.NewRecordID(), mode)
	return err
}

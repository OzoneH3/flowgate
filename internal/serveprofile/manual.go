package serveprofile

import (
	"fmt"
	"sync"
)

// Root service configuration must arm this once-per-process capture. The API
// can trigger/status it but cannot choose paths, durations or rearm it.
var manual struct {
	sync.Mutex
	trigger chan struct{}
	state   string
	detail  string
}

func ManualStatus() map[string]string {
	manual.Lock()
	defer manual.Unlock()
	state := manual.state
	if state == "" {
		state = "disabled"
	}
	return map[string]string{"state": state, "detail": manual.detail}
}
func StartManual() error {
	manual.Lock()
	defer manual.Unlock()
	if manual.state != "armed" || manual.trigger == nil {
		return fmt.Errorf("diagnostics not armed or already requested")
	}
	manual.state = "requested"
	manual.trigger <- struct{}{}
	return nil
}
func manualState(state string, err error) {
	manual.Lock()
	defer manual.Unlock()
	manual.state = state
	if err != nil {
		manual.detail = err.Error()
	}
}

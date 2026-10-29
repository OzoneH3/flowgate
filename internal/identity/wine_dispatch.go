package identity

import (
	"encoding/hex"
	"time"
)

const wineDispatchTTL = 250 * time.Millisecond
const wineDispatchMax = 128

// This is a bounded routing hint, NOT reusable attribution or permission.
// The table resolver must still perform its complete fresh kernel/holder census,
// two runtime snapshots, cookie/inode, broker generation and image validation.
// No hit extends the age of the initial snapshot. Mismatch gets one fresh
// discovery attempt; policy is evaluated separately for every queued packet.
type wineDispatchHint struct {
	initial  Attribution
	observed time.Time
}

func positiveWineDispatch(a Attribution) bool {
	return a.Application != nil && a.Application.Kind == "wine" && a.Application.Key != "" && a.VisibilityComplete && a.Status == "corroborated-runtime-table" && a.Table != nil
}

func copyWineInitial(a Attribution) Attribution {
	a.Owners = append([]Process(nil), a.Owners...)
	a.Sockets = append([]Socket(nil), a.Sockets...)
	// Even an unexpected routing fallback must never donate an application.
	a.Application, a.Association, a.Table = nil, nil, nil
	a.presentationTarget = nil
	return a
}

func (m *WineObservers) dispatchHint(f Flow, now time.Time) *wineDispatchHint {
	if !reuseEligible(f) {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	h := m.dispatch[f.Key()]
	if h != nil && (now.Before(h.observed) || now.Sub(h.observed) >= wineDispatchTTL) {
		delete(m.dispatch, f.Key())
		return nil
	}
	if m.closed {
		return nil
	}
	return h
}

func (m *WineObservers) forgetDispatch(f Flow, hint *wineDispatchHint) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.dispatch[f.Key()] == hint {
		delete(m.dispatch, f.Key())
	}
}

func (m *WineObservers) rememberDispatch(f Flow, initial, result Attribution, observed, now time.Time) {
	if !reuseEligible(f) || !positiveWineDispatch(result) || !initial.VisibilityComplete || len(initial.Sockets) != 1 || len(initial.Owners) == 0 || len(initial.Owners) > 16 || now.Before(observed) || now.Sub(observed) >= wineDispatchTTL {
		return
	}
	for _, p := range initial.Owners {
		if p.Application.Kind != "wine" && p.Application.Kind != "wine-unresolved" {
			return
		}
	}
	s := initial.Sockets[0]
	cookie, err := hex.DecodeString(s.Cookie)
	if s.Inode == 0 || err != nil || len(cookie) != 8 || s.Cookie == "0000000000000000" || s.Cookie == "ffffffffffffffff" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}
	if m.dispatch == nil {
		m.dispatch = make(map[string]*wineDispatchHint)
	}
	for key, h := range m.dispatch {
		if now.Before(h.observed) || now.Sub(h.observed) >= wineDispatchTTL {
			delete(m.dispatch, key)
		}
	}
	key := f.Key()
	if m.dispatch[key] == nil && len(m.dispatch) >= wineDispatchMax {
		return
	}
	m.dispatch[key] = &wineDispatchHint{initial: copyWineInitial(initial), observed: observed}
}

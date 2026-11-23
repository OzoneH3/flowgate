package uploadshape

import (
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"flowgate/internal/identity"
	"golang.org/x/sys/unix"
)

// Wine shaping uses only live, connected TCP sockets. A Windows handle census
// can disambiguate a wineserver and a client holding the same Linux socket.
// A Wine display name or a Linux holder list alone cannot do so.
func wineOwner(f identity.Flow, a identity.Attribution) (string, identity.Socket, bool) {
	if f.Protocol != "tcp" || f.Direction != "outgoing" || !a.FreshConnectionProof() ||
		!a.VisibilityComplete || a.Status != "corroborated-runtime-table" || len(a.Sockets) != 1 ||
		a.Application == nil || a.Table == nil || len(a.Table.Owners) != 1 || a.Fingerprint == "" {
		return "", identity.Socket{}, false
	}
	app, table, s := a.Application, a.Table, a.Sockets[0]
	if app.Kind != "wine" || app.Hosted != nil || app.Revision == "" || !filepath.IsAbs(app.Executable) ||
		!filepath.IsAbs(app.Prefix) || strings.ContainsAny(app.Prefix+app.Executable, "|") ||
		app.Prefix != table.Prefix || s.UID != table.UID || app.Key != identity.ApplicationKey(s.UID, *app) ||
		table.SocketCookie != s.Cookie || s.Cookie == "" || s.Inode == 0 || s.Protocol != f.Protocol ||
		s.State != 1 || s.NetNS == "" || s.NetNS != f.NetNS || s.Local != f.Local || s.Remote != f.Remote {
		return "", identity.Socket{}, false
	}
	return strconv.FormatUint(uint64(s.UID), 10) + ":" + app.Key, s, true
}

// Runtime-adjacent holders are an inexpensive discovery hint only.
func maybeWine(a identity.Attribution) bool {
	for _, owner := range a.Owners {
		if owner.Application.Kind == "wine" || owner.Application.Kind == "wine-unresolved" {
			return true
		}
	}
	return false
}

type wineProof struct {
	App         string          `json:"app"`
	Socket      identity.Socket `json:"socket"`
	Fingerprint string          `json:"fingerprint"`
	Until       int64           `json:"until_ns"`
}

func monotonicNS() int64 {
	var ts unix.Timespec
	if unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts) != nil {
		return 0
	}
	return ts.Nano()
}

func (m *Manager) proveWine(f identity.Flow) (string, *wineProof) {
	before := monotonicNS()
	if before == 0 || m.opts.WineResolve == nil {
		return "", nil
	}
	a := m.opts.WineResolve(f)
	app, s, ok := wineOwner(f, a)
	until := before + int64(5*time.Second)
	now := monotonicNS()
	if !ok || now == 0 || now >= until {
		return "", nil
	}
	// Counters are irrelevant and must not be carried to the controller.
	s.Counters = nil
	return app, &wineProof{App: app, Socket: s, Fingerprint: a.Fingerprint, Until: until}
}

// Controller maintenance never extends these deadlines. A slow or unavailable
// resolver can leave the socket uncovered, but cannot lengthen a stale lease.
func (m *Manager) renewWine(t transport, bindings []Binding, version uint64) error {
	for _, b := range bindings {
		if !b.Wine {
			continue
		}
		f, ok := bindingFlow(b)
		var proof *wineProof
		if ok {
			f.Protocol, f.Direction = "tcp", "outgoing"
			app, verified := m.proveWine(f)
			if app == b.App && verified != nil && verified.Socket.Cookie == b.Cookie {
				proof = verified
			}
		}
		if _, v, closed := m.current(); closed || v != version {
			break
		}
		if proof == nil {
			m.gap("wine_ownership_lost")
		}
		if _, err := call(t, map[string]any{"op": "renew_wine", "cookie": b.Cookie, "proof": proof}); err != nil {
			return err
		}
	}
	return nil
}

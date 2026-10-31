package identity

// Only AnnotateActivity reads this cache. Copied labels can appear in configured-
// policy presentation, but resolvers, packet-policy decisions and socket grants
// never read the cache. Rule creation still verifies the runtime owner afresh.
import (
	"fmt"
	"sync"
	"time"
)

const wineActivityDisplayTTL = 3 * time.Second
const wineActivityDisplayMax = 2048

type retainedWineActivity struct {
	verified time.Time
	runtime  RuntimeApplication
	holders  map[string]string
}
type wineActivityDisplay struct {
	mu     sync.Mutex
	closed bool
	rows   map[string]retainedWineActivity
}

// Socket identity is independent of the observation's holder completeness.
// Protocol/endpoints/state changes still invalidate the retained label.
func wineActivityDisplaySocketKey(row ActivityRow) string {
	s := row.Socket
	if s.Inode == 0 || s.Cookie == "" || s.NetNS == "" {
		return ""
	}
	return digest(fmt.Sprintf("%q|%d|%q|%d|%q|%d|%s|%s|%d", s.NetNS, s.Inode, s.Cookie, s.UID, s.Protocol, s.Family, s.Local, s.Remote, s.State))
}
func wineActivityDisplayHolders(row ActivityRow, processes map[string]ActivityProcess) map[string]string {
	if len(row.Owners) == 0 || len(row.Owners) > 32 {
		return nil
	}
	holders := make(map[string]string, len(row.Owners))
	for _, id := range row.Owners {
		p, ok := processes[id]
		if !ok || p.PID <= 0 || p.Start == "" || p.UID != row.Socket.UID || id != fmt.Sprintf("%d:%s", p.PID, p.Start) {
			return nil
		}
		if _, duplicate := holders[id]; duplicate {
			return nil
		}
		holders[id] = digest(fmt.Sprintf("%q|%d|%q|%q|%q|%q|%q|%q|%q|%q|%q", id, p.UID, p.NetNS, p.MountNS, p.PIDNS, p.Executable, p.ExecutableRevision, p.Application.Key, p.Application.Revision, p.Application.Prefix, p.Application.Kind))
	}
	return holders
}
func retainedWineHoldersMatch(old, current map[string]string, complete bool) bool {
	if len(current) == 0 || complete && len(old) != len(current) {
		return false
	}
	for id, stamp := range current {
		if old[id] != stamp {
			return false
		}
	}
	return true
}
func copyActivityRuntime(a RuntimeApplication) RuntimeApplication {
	a.Application.Evidence = append([]string(nil), a.Application.Evidence...)
	if a.Application.Hosted != nil {
		h := *a.Application.Hosted
		h.Chain = append([]HostedStep(nil), h.Chain...)
		a.Application.Hosted = &h
	}
	a.Evidence.Owners = append([]WindowsOwner(nil), a.Evidence.Owners...)
	return a
}
func (m *WineObservers) retainWineActivityAnnotations(s *ActivitySnapshot, now time.Time) {
	d := &m.activityDisplay
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		d.rows = nil
		return
	}
	// Rebuild from CURRENT rows, so closed/changed sockets and holders disappear
	// immediately. Reused annotations never renew their original three-second TTL.
	next := make(map[string]retainedWineActivity)
	for i := range s.Rows {
		row := &s.Rows[i]
		key := wineActivityDisplaySocketKey(*row)
		holders := wineActivityDisplayHolders(*row, s.Processes)
		if key == "" || len(holders) == 0 {
			continue
		}
		a := row.RuntimeApplication
		if a != nil {
			if !s.Complete || a.DisplaySource != "" || a.Application.Kind != "wine" || a.Application.Key == "" || a.Application.Revision == "" || a.Application.Prefix == "" || a.UID != row.Socket.UID || a.Evidence.SocketCookie != row.Socket.Cookie {
				continue
			}
			if len(next) < wineActivityDisplayMax {
				next[key] = retainedWineActivity{verified: now, runtime: copyActivityRuntime(*a), holders: holders}
			}
			continue
		}
		old, ok := d.rows[key]
		if !ok || !retainedWineHoldersMatch(old.holders, holders, s.Complete) || now.Before(old.verified) || now.Sub(old.verified) >= wineActivityDisplayTTL {
			continue
		}
		copy := copyActivityRuntime(old.runtime)
		copy.DisplaySource = "last-verified-snapshot"
		if !s.Complete {
			copy.DisplaySource = "last-verified-partial-snapshot"
		}
		copy.DisplayVerifiedAt = old.verified.UTC().Format(time.RFC3339Nano)
		row.RuntimeApplication = &copy
		if len(next) < wineActivityDisplayMax {
			next[key] = old
		}
	}
	d.rows = next
}

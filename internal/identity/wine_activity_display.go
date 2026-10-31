package identity

// Only AnnotateActivity reads this cache. Resolve/TryResolve, policy and socket
// grants cannot use its contents; it never avoids an authorization census.
import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

const wineActivityDisplayTTL = 3 * time.Second
const wineActivityDisplayMax = 2048

type retainedWineActivity struct {
	verified time.Time
	runtime  RuntimeApplication
}
type wineActivityDisplay struct {
	mu     sync.Mutex
	closed bool
	rows   map[string]retainedWineActivity
}

// Bind presentation to the exact current socket and complete visible holder set.
// PID/start, executable revision and namespace changes all invalidate retention.
// Protocol/endpoints/state are included so a changed TCP lifecycle isn't hidden.
func wineActivityDisplayKey(row ActivityRow, processes map[string]ActivityProcess) string {
	s := row.Socket
	if s.Inode == 0 || s.Cookie == "" || s.NetNS == "" || len(row.Owners) == 0 || len(row.Owners) > 32 {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%q|%d|%q|%d|%q|%d|%s|%s|%d", s.NetNS, s.Inode, s.Cookie, s.UID, s.Protocol, s.Family, s.Local, s.Remote, s.State)
	ids := append([]string(nil), row.Owners...)
	sort.Strings(ids)
	for i, id := range ids {
		p, ok := processes[id]
		if !ok || p.PID <= 0 || p.Start == "" || p.UID != s.UID || id != fmt.Sprintf("%d:%s", p.PID, p.Start) || i > 0 && ids[i-1] == id {
			return ""
		}
		fmt.Fprintf(&b, "|%q|%d|%q|%q|%q|%q|%q|%q|%q|%q|%q", id, p.UID, p.NetNS, p.MountNS, p.PIDNS, p.Executable, p.ExecutableRevision, p.Application.Key, p.Application.Revision, p.Application.Prefix, p.Application.Kind)
	}
	return digest(b.String())
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
	if d.closed || !s.Complete {
		d.rows = nil
		return
	}
	// Rebuild from CURRENT rows, so closed/changed sockets and holders disappear
	// immediately. Reused annotations never renew their original three-second TTL.
	next := make(map[string]retainedWineActivity)
	for i := range s.Rows {
		row := &s.Rows[i]
		key := wineActivityDisplayKey(*row, s.Processes)
		if key == "" {
			continue
		}
		a := row.RuntimeApplication
		if a != nil {
			if a.DisplaySource != "" || a.Application.Kind != "wine" || a.Application.Key == "" || a.Application.Revision == "" || a.Application.Prefix == "" || a.UID != row.Socket.UID || a.Evidence.SocketCookie != row.Socket.Cookie {
				continue
			}
			if len(next) < wineActivityDisplayMax {
				next[key] = retainedWineActivity{verified: now, runtime: copyActivityRuntime(*a)}
			}
			continue
		}
		old, ok := d.rows[key]
		if !ok || now.Before(old.verified) || now.Sub(old.verified) >= wineActivityDisplayTTL {
			continue
		}
		copy := copyActivityRuntime(old.runtime)
		copy.DisplaySource = "last-verified-snapshot"
		copy.DisplayVerifiedAt = old.verified.UTC().Format(time.RFC3339Nano)
		row.RuntimeApplication = &copy
		if len(next) < wineActivityDisplayMax {
			next[key] = old
		}
	}
	d.rows = next
}

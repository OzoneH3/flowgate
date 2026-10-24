package identity

import (
	"fmt"
	"sync"
	"time"
)

// Every queued UDP datagram requires fresh ownership evidence. The queue may
// share a fresh observation across a frozen batch that predates the check;
// subsequent arrivals require another check. Full attribution scans every process
// and, for Wine sockets, takes two runtime owner-table censuses.
//
// A complete positive attribution is therefore reused for one kernel socket.
// Each ownership observation still needs a fresh UDP census showing exactly that one
// matching socket (netns, inode, cookie) on the same local endpoint and
// direction, and every recorded owner must still be the same process instance.
// Full attribution re-runs in the background after Refresh and is required
// again after Window. Partial, ambiguous or failed results are never reused,
// and the remote endpoint is never part of the evidence: policy still decides
// every flow separately.
type UDPAttributionReuse struct {
	resolve func(Flow) Attribution
	// Try, when set, is the non-waiting form of resolve used by TryResolve.
	Try         func(Flow) (Attribution, bool)
	Sockets     func() ([]Socket, error)
	PortSockets func(uint16) ([]Socket, error)
	Running     func(pid int, start string) bool
	Now         func() time.Time
	Async       func(func())
	Refresh     time.Duration
	Window      time.Duration
	Max         int

	mu      sync.Mutex
	entries map[string]*reusedAttribution
}
type reusedAttribution struct {
	attribution Attribution
	verified    time.Time
	refreshing  bool
}

func NewUDPAttributionReuse(resolve func(Flow) Attribution) *UDPAttributionReuse {
	return &UDPAttributionReuse{resolve: resolve, PortSockets: UDPPortSockets, Running: InstanceRunning, Now: time.Now, Async: func(fn func()) { go fn() }, Refresh: 10 * time.Second, Window: 30 * time.Second, Max: 256, entries: map[string]*reusedAttribution{}}
}

func reuseKey(f Flow, s Socket) string {
	return fmt.Sprintf("%s|%s|%s|%d|%s", f.Direction, f.Local, s.NetNS, s.Inode, s.Cookie)
}

// Link-local endpoints keep per-datagram attribution: their interface mapping
// is part of the evidence and differs by remote.
func reuseEligible(f Flow) bool {
	if f.Protocol != "udp" || (f.Direction != "incoming" && f.Direction != "outgoing") || f.NetNS != NetNS() {
		return false
	}
	l, r := f.Local.Addr().Unmap(), f.Remote.Addr().Unmap()
	return !l.IsLinkLocalUnicast() && !r.IsLinkLocalUnicast() && !l.IsLinkLocalMulticast() && !r.IsLinkLocalMulticast()
}

func reusable(a Attribution) bool {
	if a.Application == nil || a.Application.Key == "" || !a.VisibilityComplete || len(a.Sockets) != 1 || len(a.Owners) == 0 {
		return false
	}
	switch a.Status {
	case "directly-associated", "corroborated", "corroborated-runtime-table", "corroborated-broker-client":
	default:
		return false
	}
	for _, p := range a.Owners {
		if p.PID <= 0 || p.Start == "" {
			return false
		}
	}
	return true
}

func (r *UDPAttributionReuse) Resolve(f Flow) Attribution {
	a, _ := r.resolveWith(f, func(f Flow) (Attribution, bool) { return r.resolve(f), true })
	return a
}

// TryResolve answers from verified reuse, else defers to Try without waiting.
// false carries no evidence and is never stored.
func (r *UDPAttributionReuse) TryResolve(f Flow) (Attribution, bool) {
	if r.Try == nil {
		return r.Resolve(f), true
	}
	return r.resolveWith(f, r.Try)
}

func (r *UDPAttributionReuse) resolveWith(f Flow, resolve func(Flow) (Attribution, bool)) (Attribution, bool) {
	if !reuseEligible(f) {
		return resolve(f)
	}
	var sockets []Socket
	var err error
	if r.Sockets != nil { // explicit injected full-census provider
		sockets, err = r.Sockets()
	} else {
		sockets, err = r.PortSockets(f.Local.Port())
	}
	if err == nil {
		if current := receivers(sockets, f); len(current) == 1 {
			if a, ok := r.reuse(f, reuseKey(f, current[0])); ok {
				return a, true
			}
		}
	}
	a, ok := resolve(f)
	if ok {
		r.store(f, a)
	}
	return a, ok
}

func (r *UDPAttributionReuse) reuse(f Flow, key string) (Attribution, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry := r.entries[key]
	if entry == nil {
		return Attribution{}, false
	}
	age := r.Now().Sub(entry.verified)
	if age < 0 || age >= r.Window {
		delete(r.entries, key)
		return Attribution{}, false
	}
	for _, p := range entry.attribution.Owners {
		if !r.Running(p.PID, p.Start) {
			delete(r.entries, key)
			return Attribution{}, false
		}
	}
	if age >= r.Refresh && !entry.refreshing {
		entry.refreshing = true
		r.Async(func() { r.refresh(f, key, entry) })
	}
	a := entry.attribution
	a.Owners = append([]Process(nil), a.Owners...)
	a.Sockets = append([]Socket(nil), a.Sockets...)
	return a, true
}

// A refresh replaces evidence only with a new complete attribution; any other
// outcome withdraws reuse so the next datagram takes the full path.
func (r *UDPAttributionReuse) refresh(f Flow, key string, old *reusedAttribution) {
	a := r.resolve(f)
	r.mu.Lock()
	if r.entries[key] == old {
		delete(r.entries, key)
	}
	r.mu.Unlock()
	r.store(f, a)
}

func (r *UDPAttributionReuse) store(f Flow, a Attribution) {
	if !reusable(a) {
		return
	}
	key := reuseKey(f, a.Sockets[0])
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.Now()
	var oldestKey string
	var oldest *reusedAttribution
	for k, v := range r.entries {
		if now.Sub(v.verified) >= r.Window {
			delete(r.entries, k)
		} else if oldest == nil || v.verified.Before(oldest.verified) {
			oldestKey, oldest = k, v
		}
	}
	if _, replacing := r.entries[key]; !replacing && len(r.entries) >= r.Max && oldest != nil {
		delete(r.entries, oldestKey)
	}
	r.entries[key] = &reusedAttribution{attribution: a, verified: now}
}

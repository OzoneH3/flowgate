package identity

import (
	"fmt"
	"sync"
	"time"
)

// A complete positive attribution of one exact native application run by its
// thread-group leader may be reused for one kernel socket. Every frozen group
// still needs a fresh UDP census showing exactly that socket (netns, inode,
// cookie), followed by two matching reads of the owner's generation, executable,
// revision, credentials and namespaces. Facts are captured at store time after
// full resolution, and the reuse window starts after that capture.
//
// Runtime classification is re-derived by the full resolver initially and on
// refresh, not by scanning mappings on each hit. A native process that loads a
// Wine runtime without exec can retain its native classification until that
// refresh. Full attribution is scheduled after at least Refresh and required
// again after Window; verification never extends the window. Partial, ambiguous
// or failed results, workers, witnesses and Wine/runtime/hosted applications are
// never reused. Every packet still receives a current policy decision.
//
// These checks re-verify the recorded owner, not descriptors passed to or
// inherited by other processes since the last census (SEMANTICS snapshot
// boundary). PID/start equality alone is never treated as permission authority.
type UDPAttributionReuse struct {
	resolve func(Flow) Attribution
	// Try, when set, is the non-waiting form of resolve used by TryResolve.
	Try         func(Flow) (Attribution, bool)
	Sockets     func() ([]Socket, error)
	PortSockets func(uint16) ([]Socket, error)
	Running     func(pid int, start string) bool
	// Facts reads the recorded owner's raw task facts. Tests substitute models;
	// production reads /proc. Runtime classification belongs to the full resolver.
	Facts   func(pid int, start string) (holderTaskFacts, error)
	Now     func() time.Time
	Async   func(func())
	Refresh time.Duration
	Window  time.Duration
	Max     int

	mu      sync.Mutex
	entries map[string]*reusedAttribution
}
type reusedAttribution struct {
	attribution Attribution
	facts       holderTaskFacts // leader facts captured after the full resolution
	verified    time.Time
	refreshing  bool
}

// ownerFacts reads the thread-group leader's raw facts at its recorded generation.
func ownerFacts(pid int, start string) (holderTaskFacts, error) {
	return readHolderFacts(Holder{TGID: pid}, HolderMember{TID: pid, Start: start})
}

// factsMatchProcess ties raw task facts to the fully resolved process they claim
// to describe: same generation, executable, revision, user and namespaces.
func factsMatchProcess(f holderTaskFacts, p Process) bool {
	return f.Group == p.PID && f.Start == p.Start && f.Exe == p.Executable && f.Revision == p.ExecutableRevision && f.UID == p.UID && f.NetNS == p.NetNS && f.MountNS == p.MountNS && f.PIDNS == p.PIDNS
}

func NewUDPAttributionReuse(resolve func(Flow) Attribution) *UDPAttributionReuse {
	return &UDPAttributionReuse{resolve: resolve, PortSockets: UDPPortSockets, Running: InstanceRunning, Facts: ownerFacts, Now: time.Now, Async: func(fn func()) { go fn() }, Refresh: 10 * time.Second, Window: 30 * time.Second, Max: 256, entries: map[string]*reusedAttribution{}}
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

// reusable admits only a complete, directly associated attribution whose single
// owner is an exact native application observed in its live thread-group leader
// without a holder witness. Wine, runtime-table, broker, hosted/Electron and
// worker-held sockets are never cached.
func reusable(a Attribution) bool {
	if a.Application == nil || a.Application.Key == "" || !a.VisibilityComplete || len(a.Sockets) != 1 || len(a.Owners) != 1 || a.Status != "directly-associated" {
		return false
	}
	p := a.Owners[0]
	if p.PID <= 0 || p.Start == "" || p.ThreadGroup != p.PID || p.HolderWitness != "" || p.Application.Kind != "native" || p.Application.Hosted != nil || !exactNativeHolder(p) || p.Application.Key != a.Application.Key {
		return false
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
	entry := r.entries[key]
	if entry == nil {
		r.mu.Unlock()
		return Attribution{}, false
	}
	age := r.Now().Sub(entry.verified)
	if age < 0 || age >= r.Window {
		delete(r.entries, key)
		r.mu.Unlock()
		return Attribution{}, false
	}
	a := entry.attribution
	a.Owners = append([]Process(nil), a.Owners...)
	a.Sockets = append([]Socket(nil), a.Sockets...)
	stored := entry.facts
	r.mu.Unlock()
	// Fresh recorded-owner verification outside the lock. Both raw reads must
	// match the stored identity; runtime classification is refreshed separately.
	if !r.verifyOwner(a.Owners[0], stored) {
		r.mu.Lock()
		if r.entries[key] == entry {
			delete(r.entries, key)
		}
		r.mu.Unlock()
		return Attribution{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.entries[key] != entry {
		return Attribution{}, false
	}
	// Verification took time: the window is judged again now, not when the
	// entry was first looked up.
	age = r.Now().Sub(entry.verified)
	if age < 0 || age >= r.Window {
		delete(r.entries, key)
		return Attribution{}, false
	}
	if age >= r.Refresh && !entry.refreshing {
		entry.refreshing = true
		r.Async(func() { r.refresh(f, key, entry) })
	}
	return a, true
}

// verifyOwner re-establishes the recorded native owner's process generation,
// executable revision, credentials and namespaces. It does not reclassify
// runtime mappings or observe other holders of the socket.
func (r *UDPAttributionReuse) verifyOwner(p Process, stored holderTaskFacts) bool {
	if r.Running != nil && !r.Running(p.PID, p.Start) {
		return false
	}
	first, err := r.Facts(p.PID, p.Start)
	if err != nil || first != stored || !factsMatchProcess(first, p) {
		return false
	}
	second, err := r.Facts(p.PID, p.Start)
	return err == nil && second == first
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
	// Facts are captured after the full resolution and must describe exactly the
	// resolved process; otherwise nothing is stored. The window starts now.
	owner := a.Owners[0]
	facts, err := r.Facts(owner.PID, owner.Start)
	if err != nil || !factsMatchProcess(facts, owner) {
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
	r.entries[key] = &reusedAttribution{attribution: a, facts: facts, verified: now}
}

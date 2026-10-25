package identity

import (
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"
)

// Pure model of the full resolver and raw task facts.
// No /proc, no sockets. Native owners are thread-group leaders of distinct
// executables; Wine owners model the runtime-table path that must never cache.
type reuseFixture struct {
	sockets       []Socket
	owners        map[string]Application // socket cookie -> verified application
	running       map[int]bool
	factsOverride map[int]func(*holderTaskFacts)
	factsErr      map[int]error
	resolveHook   func(*Attribution)
	onFacts       func(pid int) // runs after a facts read (store or verification)
	calls         int
	factsCalls    int
	fail          bool
	now           time.Time
	async         []func()
}

func syntheticWine(name, prefix string) Application {
	app := Application{Kind: "wine", Name: name, Executable: prefix + "/drive_c/" + name, Revision: "rev-" + name, Prefix: prefix}
	app.Key = digest("1000|wine|" + prefix + "|" + app.Executable)
	return app
}

func syntheticNative(name string) Application {
	app := Application{Kind: "native", Name: name, Executable: "/opt/" + name, Revision: "rev-" + name}
	app.Key = digest("1000|native||" + app.Executable)
	return app
}

func (x *reuseFixture) socket(port uint16, inode uint32, cookie string) Socket {
	return Socket{Protocol: "udp", Family: 2, Local: netip.MustParseAddrPort(fmt.Sprintf("0.0.0.0:%d", port)), Remote: netip.MustParseAddrPort("0.0.0.0:0"), Inode: inode, Cookie: cookie, NetNS: NetNS()}
}

func (x *reuseFixture) process(pid int, app Application) Process {
	p := Process{PID: pid, ThreadGroup: pid, Start: "start", UID: 1000, BootID: "boot", NetNS: "net", MountNS: "mnt", PIDNS: "pid", Executable: app.Executable, ExecutableRevision: app.Revision, Application: app}
	if app.Kind == "wine" {
		p.Executable, p.ExecutableRevision = "/usr/bin/wine64-preloader", "rev-wine"
	}
	return p
}

// The full resolver stands in for the expensive census: it answers from the
// current socket list and the verified owner of each cookie.
func (x *reuseFixture) resolve(f Flow) Attribution {
	x.calls++
	a := Attribution{Status: "unidentified", Reason: "no visible matching socket"}
	for _, s := range x.sockets {
		if matches(s, f) {
			a.Sockets = append(a.Sockets, s)
		}
	}
	if x.fail || len(a.Sockets) != 1 {
		return a
	}
	app, ok := x.owners[a.Sockets[0].Cookie]
	if !ok {
		return a
	}
	pid := int(a.Sockets[0].Inode)
	a.Owners = []Process{x.process(pid, app)}
	a.VisibilityComplete = true
	a.Status = "directly-associated"
	if app.Kind == "wine" {
		a.Status = "corroborated-runtime-table"
	}
	a.Reason = "synthetic census"
	a.Fingerprint = a.Sockets[0].Cookie + app.Key
	a.Application = &app
	if x.resolveHook != nil {
		x.resolveHook(&a)
	}
	return a
}

func (x *reuseFixture) appOfPID(pid int) (Application, bool) {
	for _, s := range x.sockets {
		if int(s.Inode) == pid {
			app, ok := x.owners[s.Cookie]
			return app, ok
		}
	}
	return Application{}, false
}

func (x *reuseFixture) facts(pid int, start string) (holderTaskFacts, error) {
	x.factsCalls++
	defer func() {
		if x.onFacts != nil {
			x.onFacts(pid)
		}
	}()
	if err := x.factsErr[pid]; err != nil {
		return holderTaskFacts{}, err
	}
	app, ok := x.appOfPID(pid)
	if !ok || !x.running[pid] || start != "start" {
		return holderTaskFacts{}, errors.New("holder generation changed")
	}
	p := x.process(pid, app)
	f := holderTaskFacts{Group: pid, Start: p.Start, Exe: p.Executable, Revision: p.ExecutableRevision, NetNS: p.NetNS, MountNS: p.MountNS, PIDNS: p.PIDNS, Credentials: "1000:1000:1000:1000/1000:1000:1000:1000/groups:1000", UID: 1000}
	if o := x.factsOverride[pid]; o != nil {
		o(&f)
	}
	return f, nil
}

func newReuseFixture() (*reuseFixture, *UDPAttributionReuse) {
	x := &reuseFixture{owners: map[string]Application{}, running: map[int]bool{}, factsOverride: map[int]func(*holderTaskFacts){}, factsErr: map[int]error{}, now: time.Unix(1000, 0)}
	r := NewUDPAttributionReuse(x.resolve)
	r.Sockets = func() ([]Socket, error) { return append([]Socket(nil), x.sockets...), nil }
	r.Running = func(pid int, start string) bool { return x.running[pid] && start == "start" }
	r.Facts = x.facts
	r.Now = func() time.Time { return x.now }
	r.Async = func(fn func()) { x.async = append(x.async, fn) }
	return x, r
}

func udpFlow(direction, local, remote string) Flow {
	f, err := ParseFlow("udp", direction, local, remote)
	if err != nil {
		panic(err)
	}
	return f
}

func appOf(a Attribution) string {
	if a.Application == nil {
		return ""
	}
	return a.Application.Name
}

func (x *reuseFixture) nativeAlpha() Application {
	alpha := syntheticNative("alpha")
	x.sockets = []Socket{x.socket(34429, 11, "c-alpha")}
	x.owners["c-alpha"] = alpha
	x.running[11] = true
	return alpha
}

func TestUDPReuseServesBurstToManyRemotesFromOneVerifiedSocket(t *testing.T) {
	x, r := newReuseFixture()
	x.nativeAlpha()
	for i := 0; i < 15; i++ {
		a := r.Resolve(udpFlow("outgoing", "172.30.42.123:34429", fmt.Sprintf("198.51.100.%d:7770", i+1)))
		if appOf(a) != "alpha" || a.Status != "directly-associated" {
			t.Fatalf("probe %d: %+v", i, a)
		}
	}
	if x.calls != 1 {
		t.Fatalf("burst from one verified socket ran %d full censuses, want 1", x.calls)
	}
	// Every hit re-verifies raw identity twice; full runtime inspection stays
	// in the initial/refresh resolver rather than the burst path.
	if x.factsCalls != 1+2*14 {
		t.Fatalf("verification per hit missing: facts=%d", x.factsCalls)
	}
}

// Wine/runtime applications are never cached: two synthetic Windows
// applications in separate prefixes take the full resolver for every batch and
// never see each other's evidence.
func TestUDPReuseNeverCachesWineRuntimeApplications(t *testing.T) {
	x, r := newReuseFixture()
	alpha := syntheticWine("alpha.exe", "/prefixes/alpha")
	beta := syntheticWine("beta.exe", "/prefixes/beta")
	x.sockets = []Socket{x.socket(34429, 11, "c-alpha"), x.socket(40001, 22, "c-beta")}
	x.owners["c-alpha"], x.owners["c-beta"] = alpha, beta
	x.running[11], x.running[22] = true, true
	for i := 0; i < 5; i++ {
		a := r.Resolve(udpFlow("outgoing", "172.30.42.123:34429", fmt.Sprintf("198.51.100.%d:7770", i+1)))
		b := r.Resolve(udpFlow("outgoing", "172.30.42.123:40001", fmt.Sprintf("198.51.100.%d:7770", i+1)))
		if appOf(a) != "alpha.exe" || a.Application.Prefix != "/prefixes/alpha" || appOf(b) != "beta.exe" || b.Application.Prefix != "/prefixes/beta" {
			t.Fatalf("round %d: %+v / %+v", i, a, b)
		}
	}
	if x.calls != 10 || len(r.entries) != 0 || x.factsCalls != 0 {
		t.Fatalf("runtime applications must run the full resolver every batch: calls=%d entries=%d facts=%d", x.calls, len(r.entries), x.factsCalls)
	}
}

func TestUDPReuseStoresOnlyVerifiedNativeLeaders(t *testing.T) {
	alpha := syntheticNative("alpha")
	base := func() Attribution {
		x := &reuseFixture{owners: map[string]Application{}}
		s := x.socket(34429, 11, "c-alpha")
		return Attribution{Status: "directly-associated", VisibilityComplete: true, Sockets: []Socket{s}, Owners: []Process{x.process(11, alpha)}, Application: &alpha, Fingerprint: "fp"}
	}
	for name, mutate := range map[string]func(*Attribution){
		"worker owner":            func(a *Attribution) { a.Owners[0].PID = 12 },
		"holder witness":          func(a *Attribution) { a.Owners[0].HolderWitness = "w" },
		"two owners":              func(a *Attribution) { a.Owners = append(a.Owners, a.Owners[0]) },
		"wine status":             func(a *Attribution) { a.Status = "corroborated" },
		"broker status":           func(a *Attribution) { a.Status = "corroborated-broker-client" },
		"incomplete visibility":   func(a *Attribution) { a.VisibilityComplete = false },
		"hosted runtime":          func(a *Attribution) { a.Owners[0].Application.Hosted = &Hosted{Runtime: "/usr/bin/electron"} },
		"application key differs": func(a *Attribution) { k := *a.Application; k.Key = "other"; a.Application = &k },
		"revision missing":        func(a *Attribution) { a.Owners[0].Application.Revision = "" },
	} {
		a := base()
		mutate(&a)
		if reusable(a) {
			t.Fatalf("%s must not be reusable", name)
		}
	}
	if !reusable(base()) {
		t.Fatal("native leader must be reusable")
	}
	// Store-time facts must describe the resolved process; otherwise skip, and
	// the window starts after the facts read, never before.
	x, r := newReuseFixture()
	x.nativeAlpha()
	f := udpFlow("outgoing", "172.30.42.123:34429", "198.51.100.1:7770")
	x.factsOverride[11] = func(f *holderTaskFacts) { f.Revision = "rev-replaced" }
	r.Resolve(f)
	if len(r.entries) != 0 {
		t.Fatal("stored despite facts not matching the resolved process")
	}
	delete(x.factsOverride, 11)
	x.onFacts = func(int) { x.now = x.now.Add(3 * time.Second) } // the read itself takes time
	r.Resolve(f)
	x.onFacts = nil
	for _, e := range r.entries {
		if !e.verified.Equal(x.now) {
			t.Fatalf("window must start after verification: verified=%v now=%v", e.verified, x.now)
		}
	}
}

func TestUDPReuseHitRequiresUnchangedOwnerIdentity(t *testing.T) {
	for name, tc := range map[string]struct {
		change func(x *reuseFixture)
	}{
		"exec replaced the image": {func(x *reuseFixture) {
			x.factsOverride[11] = func(f *holderTaskFacts) { f.Exe, f.Revision = "/opt/beta", "rev-beta" }
		}},
		"credentials changed": {func(x *reuseFixture) {
			x.factsOverride[11] = func(f *holderTaskFacts) { f.Credentials = "0:0:0:0/0:0:0:0/groups:0" }
		}},
		"namespace changed": {func(x *reuseFixture) {
			x.factsOverride[11] = func(f *holderTaskFacts) { f.MountNS = "other" }
		}},
		"facts unreadable":            {func(x *reuseFixture) { x.factsErr[11] = errors.New("EACCES") }},
		"thread group changed":        {func(x *reuseFixture) { x.factsOverride[11] = func(f *holderTaskFacts) { f.Group = 99 } }},
		"UID changed":                 {func(x *reuseFixture) { x.factsOverride[11] = func(f *holderTaskFacts) { f.UID = 0 } }},
		"process generation changed":  {func(x *reuseFixture) { x.factsOverride[11] = func(f *holderTaskFacts) { f.Start = "new-generation" } }},
		"executable revision changed": {func(x *reuseFixture) { x.factsOverride[11] = func(f *holderTaskFacts) { f.Revision = "new-revision" } }},
		"network namespace changed":   {func(x *reuseFixture) { x.factsOverride[11] = func(f *holderTaskFacts) { f.NetNS = "new-net" } }},
		"PID namespace changed":       {func(x *reuseFixture) { x.factsOverride[11] = func(f *holderTaskFacts) { f.PIDNS = "new-pid" } }},
		"second read differs": {func(x *reuseFixture) {
			reads := 0
			x.onFacts = func(pid int) {
				if reads++; reads == 1 {
					x.factsOverride[11] = func(f *holderTaskFacts) { f.Revision = "rev-after-exec" }
				}
			}
		}},
	} {
		t.Run(name, func(t *testing.T) {
			x, r := newReuseFixture()
			x.nativeAlpha()
			f := udpFlow("outgoing", "172.30.42.123:34429", "198.51.100.1:7770")
			if a := r.Resolve(f); appOf(a) != "alpha" || x.calls != 1 || len(r.entries) != 1 {
				t.Fatalf("setup: %+v", a)
			}
			tc.change(x)
			// The next datagram must not be served from the cached attribution.
			x.fail = true
			a := r.Resolve(f)
			if a.Application != nil || x.calls != 2 || len(r.entries) != 0 {
				t.Fatalf("stale identity reused: %+v calls=%d entries=%d", a, x.calls, len(r.entries))
			}
		})
	}
}

// A verification that itself crosses the window must not serve the entry.
func TestUDPReuseSlowVerificationCrossingWindowIsAMiss(t *testing.T) {
	x, r := newReuseFixture()
	x.nativeAlpha()
	f := udpFlow("outgoing", "172.30.42.123:34429", "198.51.100.1:7770")
	r.Resolve(f)
	x.now = x.now.Add(r.Window - time.Second)
	x.onFacts = func(int) { x.now = x.now.Add(2 * time.Second) } // the facts read outlives the window
	x.fail = true
	if a := r.Resolve(f); a.Application != nil || x.calls != 2 || len(r.entries) != 0 {
		t.Fatalf("expired during verification yet served: %+v calls=%d entries=%d", a, x.calls, len(r.entries))
	}
	// Within the window a slow verification still serves and schedules refresh by the final age.
	x.onFacts, x.fail = nil, false
	r.Resolve(f)
	x.now = x.now.Add(r.Refresh - time.Second)
	x.onFacts = func(int) { x.now = x.now.Add(2 * time.Second) }
	if a := r.Resolve(f); appOf(a) != "alpha" || len(x.async) != 1 {
		t.Fatalf("refresh must follow the recomputed age: %+v async=%d", a, len(x.async))
	}
}

func TestUDPReuseNeverTransfersBetweenApplicationsOrSockets(t *testing.T) {
	x, r := newReuseFixture()
	alpha, beta := syntheticNative("alpha"), syntheticNative("beta")
	x.sockets = []Socket{x.socket(34429, 11, "c-alpha"), x.socket(40001, 22, "c-beta")}
	x.owners["c-alpha"], x.owners["c-beta"] = alpha, beta
	x.running[11], x.running[22] = true, true
	if a := r.Resolve(udpFlow("outgoing", "172.30.42.123:34429", "198.51.100.1:7770")); appOf(a) != "alpha" {
		t.Fatalf("alpha: %+v", a)
	}
	if a := r.Resolve(udpFlow("outgoing", "172.30.42.123:40001", "198.51.100.1:7770")); appOf(a) != "beta" {
		t.Fatalf("beta must be attributed on its own socket: %+v", a)
	}
	// Alpha closes; Beta binds the same port. New cookie: no reuse.
	x.sockets = []Socket{x.socket(34429, 33, "c-beta-2"), x.socket(40001, 22, "c-beta")}
	x.owners["c-beta-2"] = beta
	x.running[33] = true
	calls := x.calls
	a := r.Resolve(udpFlow("outgoing", "172.30.42.123:34429", "198.51.100.2:7770"))
	if appOf(a) != "beta" || x.calls != calls+1 {
		t.Fatalf("replaced socket reused Alpha evidence: %+v calls=%d", a, x.calls-calls)
	}
	// Same port, unverified replacement: stays unidentified, never Alpha.
	x.sockets = []Socket{x.socket(34429, 44, "c-unknown")}
	if a := r.Resolve(udpFlow("outgoing", "172.30.42.123:34429", "198.51.100.3:7770")); a.Application != nil {
		t.Fatalf("unverified replacement inherited an application: %+v", a)
	}
}

func TestUDPReuseRequiresSameDirectionAndLocalEndpoint(t *testing.T) {
	x, r := newReuseFixture()
	x.nativeAlpha()
	r.Resolve(udpFlow("outgoing", "172.30.42.123:34429", "198.51.100.1:7770"))
	r.Resolve(udpFlow("incoming", "172.30.42.123:34429", "198.51.100.1:7770"))
	r.Resolve(udpFlow("outgoing", "100.87.58.72:34429", "198.51.100.1:7770"))
	if x.calls != 3 {
		t.Fatalf("direction/local endpoint must be verified separately, censuses=%d", x.calls)
	}
}

func TestUDPReuseWithdrawsOnOwnerExitAmbiguityFailureAndExpiry(t *testing.T) {
	x, r := newReuseFixture()
	x.nativeAlpha()
	f := udpFlow("outgoing", "172.30.42.123:34429", "198.51.100.1:7770")
	r.Resolve(f)

	x.running[11] = false // recorded owner instance is gone
	x.fail = true
	if a := r.Resolve(f); a.Application != nil || x.calls != 2 {
		t.Fatalf("exited owner must force full census: %+v calls=%d", a, x.calls)
	}
	if r.Resolve(f); x.calls != 3 {
		t.Fatalf("failed attribution must not be reused, calls=%d", x.calls)
	}

	x.fail, x.running[11] = false, true
	r.Resolve(f)
	x.sockets = append(x.sockets, x.socket(34429, 12, "c-second"))
	if a := r.Resolve(f); a.Application != nil {
		t.Fatalf("two matching sockets must not reuse one: %+v", a)
	}

	x.sockets = x.sockets[:1]
	r.Resolve(f)
	calls := x.calls
	x.now = x.now.Add(r.Window)
	if r.Resolve(f); x.calls != calls+1 {
		t.Fatalf("evidence older than the window must be re-established")
	}
}

func TestUDPReuseRefreshesInBackgroundAndFailedRefreshWithdraws(t *testing.T) {
	x, r := newReuseFixture()
	x.nativeAlpha()
	f := udpFlow("outgoing", "172.30.42.123:34429", "198.51.100.1:7770")
	r.Resolve(f)
	x.now = x.now.Add(r.Refresh)
	if a := r.Resolve(f); appOf(a) != "alpha" || x.calls != 1 || len(x.async) != 1 {
		t.Fatalf("refresh must not stall the datagram: calls=%d async=%d", x.calls, len(x.async))
	}
	r.Resolve(f)
	if len(x.async) != 1 {
		t.Fatalf("one refresh at a time, got %d", len(x.async))
	}
	x.fail = true
	x.async[0]()
	if a := r.Resolve(f); a.Application != nil || x.calls != 3 {
		t.Fatalf("failed refresh must withdraw reuse: %+v calls=%d", a, x.calls)
	}
}

func TestUDPReusePassesThroughTCPAndLinkLocal(t *testing.T) {
	x, r := newReuseFixture()
	x.sockets = []Socket{x.socket(5355, 11, "c-alpha")}
	x.owners["c-alpha"] = syntheticNative("alpha")
	x.running[11] = true
	for i := 0; i < 2; i++ {
		r.Resolve(udpFlow("outgoing", "172.30.42.123:5355", "[fe80::1]:5355"))
		r.Resolve(udpFlow("outgoing", "172.30.42.123:5355", "224.0.0.252:5355"))
	}
	tcp, _ := ParseFlow("tcp", "outgoing", "172.30.42.123:5355", "198.51.100.1:443")
	r.Resolve(tcp)
	r.Resolve(tcp)
	if x.calls != 6 {
		t.Fatalf("TCP and link-local UDP must keep full attribution, censuses=%d", x.calls)
	}
}

func TestUDPReuseTryBusyStoresNothingAndLaterResolveSucceeds(t *testing.T) {
	x, r := newReuseFixture()
	x.nativeAlpha()
	busy, tries := true, 0
	r.Try = func(f Flow) (Attribution, bool) {
		tries++
		if busy {
			return Attribution{}, false
		}
		return x.resolve(f), true
	}
	f := udpFlow("outgoing", "172.30.42.123:34429", "198.51.100.1:7770")
	for i := 0; i < 3; i++ {
		if a, ok := r.TryResolve(f); ok || a.Application != nil {
			t.Fatalf("busy try: %+v %v", a, ok)
		}
	}
	if len(r.entries) != 0 || x.calls != 0 {
		t.Fatalf("busy try stored evidence or ran a census: entries=%d calls=%d", len(r.entries), x.calls)
	}
	busy = false
	if a, ok := r.TryResolve(f); !ok || appOf(a) != "alpha" {
		t.Fatalf("later try must resolve: %+v %v", a, ok)
	}
	// Now verified: the next datagram is a re-verified reuse hit and needs no census.
	busy = true
	if a, ok := r.TryResolve(f); !ok || appOf(a) != "alpha" || tries != 4 {
		t.Fatalf("reuse hit must not call Try: %+v %v tries=%d", a, ok, tries)
	}
	// Beta's socket on another port never inherits Alpha's entry while busy.
	x.sockets = append(x.sockets, x.socket(40001, 22, "c-beta"))
	x.owners["c-beta"] = syntheticNative("beta")
	x.running[22] = true
	if a, ok := r.TryResolve(udpFlow("outgoing", "172.30.42.123:40001", "198.51.100.1:7770")); ok || a.Application != nil {
		t.Fatalf("beta must not reuse alpha evidence: %+v %v", a, ok)
	}
}

// The optimized query narrows only retained socket rows, never the policy
// endpoint or remote. Errors must use full fresh attribution, not old evidence.
func TestUDPReuseUsesFreshPortCensusAndRefusesItsErrors(t *testing.T) {
	x, r := newReuseFixture()
	x.sockets = []Socket{x.socket(41001, 11, "c-alpha")}
	x.owners["c-alpha"] = syntheticNative("alpha")
	x.running[11] = true
	r.Sockets = nil
	queries := 0
	fail := false
	r.PortSockets = func(port uint16) ([]Socket, error) {
		queries++
		if port != 41001 {
			t.Fatal(port)
		}
		if fail {
			return nil, fmt.Errorf("incomplete")
		}
		return append([]Socket(nil), x.sockets...), nil
	}
	f := udpFlow("outgoing", "192.0.2.1:41001", "198.51.100.1:443")
	r.Resolve(f)
	r.Resolve(f)
	if queries != 2 || x.calls != 1 {
		t.Fatal("census must remain fresh", queries, x.calls)
	}
	fail, x.fail = true, true
	if a := r.Resolve(f); a.Application != nil || x.calls != 2 {
		t.Fatal("query failure reused old evidence", a, x.calls)
	}
}

// The practical policy deliberately reclassifies an unchanged native executable
// at full refresh, not on every hit. Model an in-process runtime mapping change
// without changing any raw process facts; this is the chosen residual.
func TestUDPReuseRuntimeClassificationChangesAtFullRefresh(t *testing.T) {
	for _, completeRefresh := range []bool{true, false} {
		t.Run(fmt.Sprintf("refresh-completes-%v", completeRefresh), func(t *testing.T) {
			x, r := newReuseFixture()
			x.nativeAlpha()
			f := udpFlow("outgoing", "192.0.2.1:34429", "198.51.100.1:443")
			if appOf(r.Resolve(f)) != "alpha" || len(r.entries) != 1 {
				t.Fatal("setup did not cache native identity")
			}
			x.resolveHook = func(a *Attribution) {
				a.Application = nil
				a.Status = "unidentified"
				a.Reason = "runtime classification now unresolved"
			}
			x.now = x.now.Add(r.Refresh / 2)
			if appOf(r.Resolve(f)) != "alpha" || x.calls != 1 {
				t.Fatal("native classification was not reused under practical contract")
			}
			x.now = x.now.Add(r.Refresh / 2)
			if appOf(r.Resolve(f)) != "alpha" || len(x.async) != 1 || x.calls != 1 {
				t.Fatal("full refresh not scheduled at refresh age")
			}
			if completeRefresh {
				x.async[0]()
				if len(r.entries) != 0 {
					t.Fatal("unresolved refresh retained native classification")
				}
			} else {
				// A delayed asynchronous refresh never renews the hard window.
				x.now = x.now.Add(r.Window - r.Refresh)
			}
			if a := r.Resolve(f); a.Application != nil || len(r.entries) != 0 {
				t.Fatalf("stale runtime classification survived full re-resolution: %+v", a)
			}
		})
	}
}

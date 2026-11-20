package daemon

import (
	"context"
	"log"
	"maps"
	"time"

	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"flowgate/internal/socketcontrol"
)

// EstablishedTCP binds the current diagnostic socket to its observed TCP
// initiation direction. It is supplied by the privileged enforcement backend.
type EstablishedTCP struct {
	Socket identity.Socket
	Flow   identity.Flow
}

// ConfigureTCPDisconnect installs the privileged census and the uncached owner
// resolver before the API starts. Monitoring alone never invokes the census.
func (e *Engine) ConfigureTCPDisconnect(census func(context.Context) ([]EstablishedTCP, error), resolve func(identity.Flow) identity.Attribution) {
	e.tcpDisconnect = &tcpDisconnect{census: census, resolve: resolve, abort: socketcontrol.Abort}
}

type tcpDisconnect struct {
	census  func(context.Context) ([]EstablishedTCP, error)
	resolve func(identity.Flow) identity.Attribution
	abort   func(context.Context, identity.Socket) (socketcontrol.Result, error)
}

type tcpBlockEdit struct {
	before, after []policy.Rule
	blocks        map[string]uint64
	at            time.Time
	leases        map[string]*processLease
}

func (e *Engine) publishRuleStateLocked(next []policy.Rule) {
	before := e.rules
	e.rules = next
	if e.tcpDisconnect == nil {
		return
	}
	now := e.Now()
	old := make(map[string]policy.Rule, len(before))
	for _, r := range before {
		old[r.ID] = r
	}
	var blocks map[string]uint64
	for _, r := range next {
		if !activeTCPBlock(r, now) || activeTCPBlock(old[r.ID], now) {
			continue
		}
		if blocks == nil {
			blocks = make(map[string]uint64)
		}
		blocks[r.ID] = r.Version
	}
	if len(blocks) != 0 {
		// Leases are immutable after insertion. Capture the set at publication
		// since another decision can replace a lease during the socket census.
		e.tcpBlockEdit = &tcpBlockEdit{before: before, after: next, blocks: blocks, at: now, leases: maps.Clone(e.processLeases)}
	}
}

func activeTCPBlock(r policy.Rule, now time.Time) bool {
	return r.Action == "block" && !r.Disabled && policy.ProtocolMatches(r.Filter.Protocol, "tcp") &&
		(r.Expires.IsZero() || now.Before(r.Expires))
}

func (e *Engine) disconnectBlockedTCP(edit *tcpBlockEdit) {
	if edit == nil || e.Enforcement == nil {
		return
	}
	status := e.Enforcement()
	if status.State != "active" {
		return
	}
	d := e.tcpDisconnect
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	sockets, err := d.census(ctx)
	if err != nil {
		log.Printf("established TCP Block: socket census unavailable: %v", err)
		return
	}
	for _, candidate := range sockets {
		if ctx.Err() != nil {
			break
		}
		f := candidate.Flow
		if !protectsTCPDirection(status, f.Direction) || !edit.mayMatch(f, e.Now()) {
			continue
		}
		// This is a current diagnostic and holder census, outside the policy
		// lock. The kernel abort independently rechecks the diagnostic identity.
		a := d.resolve(f)
		if !verifiedEstablishedOwner(candidate.Socket, a) {
			continue
		}
		e.abortNewlyBlockedTCP(ctx, edit, candidate, a, status)
	}
}

func protectsTCPDirection(s EnforcementStatus, direction string) bool {
	return (direction == "incoming" && (s.Profile == "incoming" || s.Profile == "both")) ||
		(direction == "outgoing" && s.Profile == "both")
}

func (edit *tcpBlockEdit) mayMatch(f identity.Flow, now time.Time) bool {
	for _, r := range policy.FlowCandidates(edit.after, f) {
		if _, ok := edit.blocks[r.ID]; ok && activeTCPBlock(r, now) {
			return true
		}
	}
	return false
}

func verifiedEstablishedOwner(expected identity.Socket, a identity.Attribution) bool {
	if !a.FreshConnectionProof() || !a.VisibilityComplete || a.Application == nil || len(a.Sockets) != 1 {
		return false
	}
	p, app, s := a.Principal(), a.Application, a.Sockets[0]
	return p != nil && app.Key != "" && app.Revision != "" && identity.RuntimeRuleBlocked(app) == "" &&
		app.Key == identity.ApplicationKey(p.UID, *app) &&
		(app.Kind == "native" || (app.Kind == "wine" && app.Prefix != "")) &&
		s.Protocol == "tcp" && s.State == 1 && s.Cookie != "" && s.Cookie == expected.Cookie &&
		s.NetNS == expected.NetNS && s.Family == expected.Family && s.Inode == expected.Inode &&
		s.Local == expected.Local && s.Remote == expected.Remote && s.Interface == expected.Interface && s.UID == expected.UID
}

func (e *Engine) abortNewlyBlockedTCP(ctx context.Context, edit *tcpBlockEdit, candidate EstablishedTCP, a identity.Attribution, status EnforcementStatus) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if ctx.Err() != nil {
		return
	}
	current := e.Enforcement()
	if current.State != "active" || current.Session != status.Session || current.Profile != status.Profile {
		return
	}
	e.refreshZonesLocked()
	now := e.Now()
	f := candidate.Flow
	// Conntrack identifies the direction, but it does not attest the packet's
	// interface or a local peer's identity. If a rule could depend on either,
	// evaluating without that evidence could incorrectly select a Block.
	if requiresTCPPacketEvidence(edit.before, f, edit.at) || requiresTCPPacketEvidence(edit.after, f, edit.at) || requiresTCPPacketEvidence(e.rules, f, now) {
		return
	}
	base, priorRule, _ := e.evaluateLocked(edit.before, f, a, edit.at)
	if before, _, _ := leaseOverlay(edit.leases, base, priorRule, f, a, edit.at); before == "block" {
		return
	}
	after, winner, _ := e.evaluateLocked(edit.after, f, a, edit.at)
	version, triggered := edit.blocks[winner]
	if after != "block" || !triggered {
		return
	}
	r := e.ruleLocked(winner)
	if r == nil || r.Version != version {
		return
	}
	if action, currentWinner, _ := e.evaluateLocked(e.rules, f, a, now); action != "block" || currentWinner != winner {
		return
	}
	if result, err := e.tcpDisconnect.abort(ctx, candidate.Socket); err != nil && result.Status != socketcontrol.NotFound {
		log.Printf("established TCP Block %s: socket abort %s: %v", winner, result.Status, err)
	}
}

func requiresTCPPacketEvidence(rules []policy.Rule, f identity.Flow, now time.Time) bool {
	for _, r := range policy.FlowCandidates(rules, f) {
		if !r.Expires.IsZero() && !now.Before(r.Expires) {
			continue
		}
		x := r.Filter
		if x.InterfaceIndex != 0 || x.InterfaceName != "" || x.PeerService != (policy.PeerService{}) {
			return true
		}
	}
	return false
}

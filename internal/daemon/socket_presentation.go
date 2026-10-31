package daemon

// Presentation only. Nothing in this file supplies attribution or policy evidence.
import (
	"encoding/binary"
	"encoding/hex"
	"flowgate/internal/identity"
	"flowgate/internal/socketgrant"
	"fmt"
	"strings"
	"time"
)

type socketGrantHint struct {
	application, revision, prefix string
	netns, cookie, local, remote  string
	deadline                      uint64
	ifindex                       uint32
	key                           socketgrant.Key
	inode, uid                    uint32
	runtime                       *identity.RuntimeApplication
	active, statsKnown            bool
}
type socketFastPathHints struct {
	available, disabled bool
	failure             string
	grants              []socketGrantHint
	stats               func(socketgrant.Key) (socketgrant.Stats, error)
}

// Caller already holds Engine.mu for the existing bounded presentation publisher.
// No resolver, policy evaluation, route lookup or BPF reads occur in this capture.
func (e *Engine) socketFastPathHintsLocked() socketFastPathHints {
	s := e.socketAuthorization
	if s == nil {
		return socketFastPathHints{}
	}
	out := socketFastPathHints{available: s.productionSession && s.routeBound, disabled: s.disabled}
	if s.store != nil {
		out.stats = s.store.Stats
	}
	if s.failure != nil {
		out.failure = s.failure.Error()
	}
	for _, f := range s.flows {
		if len(out.grants) >= 64 {
			break
		}
		if !f.haveKey {
			continue
		}
		var cookie [8]byte
		binary.NativeEndian.PutUint64(cookie[:], f.key.Cookie)
		g := socketGrantHint{netns: f.flow.NetNS, cookie: hex.EncodeToString(cookie[:]), local: f.flow.Local.String(), remote: f.flow.Remote.String(), deadline: f.deadline, ifindex: f.key.Interface, key: f.key}
		if a := f.connectionPolicy; a != nil && a.Application != nil && a.VisibilityComplete && a.Principal() != nil {
			g.uid = a.Principal().UID
			g.application = a.Application.Key
			g.revision = a.Application.Revision
			g.prefix = a.Application.Prefix
			for _, socket := range a.Sockets {
				if socket.NetNS == g.netns && socket.Cookie == g.cookie {
					g.inode = socket.Inode
					break
				}
			}
			if a.Application.Kind == "wine" && a.Table != nil {
				copy := snapshotConnectionPolicy(*a)
				g.runtime = &identity.RuntimeApplication{Application: *copy.Application, UID: g.uid, Evidence: *copy.Table, DisplaySource: "established-grant"}
			}
		}
		out.grants = append(out.grants, g)
	}
	return out
}

// Read only the bounded grant keys already captured; never under the policy lock.
// A counter failure affects presentation only, never a grant or packet decision.
func (h *socketFastPathHints) sampleHits() {
	if h.stats == nil || h.disabled || h.failure != "" {
		h.stats = nil
		return
	}
	now := socketgrant.BootNow()
	for i := range h.grants {
		g := &h.grants[i]
		stats, err := h.stats(g.key)
		if err == nil {
			g.statsKnown = true
			g.active = stats.LastSeen != 0 && stats.LastSeen <= now && now-stats.LastSeen <= uint64(1500*time.Millisecond)
		}
	}
	h.stats = nil
}

func (h socketFastPathHints) matchingSocket(row identity.ActivityRow) []socketGrantHint {
	if row.Socket.Protocol != "udp" || !row.Socket.Local.Addr().Is4() {
		return nil
	}
	var out []socketGrantHint
	for _, g := range h.grants {
		if g.inode == 0 || g.inode != row.Socket.Inode || g.uid != row.Socket.UID || g.netns != row.Socket.NetNS || g.cookie != row.Socket.Cookie {
			continue
		}
		if g.deadline != 0 && socketgrant.BootNow() >= g.deadline {
			continue
		}
		out = append(out, g)
	}
	return out
}

// Live grants retain an authorization identity, not a claim of a new census.
// Only annotate freshly observed exact sockets; never invent a process/socket row.
func retainGrantedRuntime(row *identity.ActivityRow, grants []socketGrantHint) bool {
	var selected *identity.RuntimeApplication
	signature := ""
	for _, g := range grants {
		current := g.application + "|" + g.revision + "|" + g.prefix
		if signature != "" && current != signature {
			return false
		}
		signature = current
		if g.runtime == nil {
			continue
		}
		if selected != nil && (selected.Application.Key != g.runtime.Application.Key || selected.Application.Revision != g.runtime.Application.Revision || selected.Application.Prefix != g.runtime.Application.Prefix) {
			return false
		}
		selected = g.runtime
	}
	if row.RuntimeApplication != nil {
		return selected == nil || row.RuntimeApplication.Application.Key == selected.Application.Key && row.RuntimeApplication.Application.Revision == selected.Application.Revision && row.RuntimeApplication.Application.Prefix == selected.Application.Prefix
	}
	if selected != nil {
		copy := *selected
		copy.Evidence.Owners = append([]identity.WindowsOwner(nil), selected.Evidence.Owners...)
		row.RuntimeApplication = &copy
	}
	return true
}

// Called only after the existing Activity UID projection. The complete grant
// inventory never crosses the API; visible rows receive only their own hint.
func (e *Engine) annotateSocketFastPath(snapshot identity.ActivitySnapshot) identity.ActivitySnapshot {
	snapshot.Rows = append(snapshot.Rows[:0:0], snapshot.Rows...)
	p := e.listReads.published.Load()
	for i := range snapshot.Rows {
		row := &snapshot.Rows[i]
		hint := identity.FastPathPresentation{State: "unknown", Code: "status_unavailable", Reason: "Fast-path status is unavailable from this backend."}
		if p != nil {
			hint.SampledAt = p.at
			matches := p.socketHints.matchingSocket(*row)
			consistent := true
			// A shared/passed descriptor must not attach a prior UID's application to
			// a row whose freshly visible holders belong to another user.
			if len(matches) > 0 {
				for _, id := range row.Owners {
					owner, ok := snapshot.Processes[id]
					if !ok || owner.UID != matches[0].uid {
						consistent = false
						break
					}
				}
			}
			if consistent && time.Since(p.at) <= time.Second && p.socketHints.available && !p.socketHints.disabled && p.socketHints.failure == "" {
				consistent = retainGrantedRuntime(row, matches)
			}
			switch {
			case time.Since(p.at) > time.Second:
				hint.Code = "status_stale"
				hint.Reason = "Fast-path status is stale; current use is unknown."
			case !consistent:
				hint.Code = "conflicting_grant_identity"
				hint.Reason = "Socket grants disagree with each other or the current observed application; fast-path attribution is unknown."
			case !strings.EqualFold(row.Socket.Protocol, "udp"):
				hint.State = "unsupported"
				hint.Code = "protocol_outside_scope"
				hint.Reason = "This UDP accelerator does not apply to TCP. Established TCP can already use its ordinary kernel path."
			case !row.Socket.Local.Addr().Is4() || !row.Socket.Remote.Addr().Is4():
				hint.State = "unsupported"
				hint.Code = "family_outside_scope"
				hint.Reason = "This accelerator supports IPv4 UDP only; this connection uses the ordinary path."
			case row.Initiation.State == "known" && row.Initiation.Direction == "incoming":
				hint.State = "unsupported"
				hint.Code = "direction_outside_scope"
				hint.Reason = "This accelerator applies to outgoing connections only."
			case !p.socketHints.available:
				hint.State = "inactive"
				hint.Code = "session_unavailable"
				hint.Reason = "Connection acceleration is not active for this protection session."
			case p.socketHints.disabled || p.socketHints.failure != "":
				hint.State = "inactive"
				hint.Code = "session_disabled"
				hint.Reason = "Connection acceleration is disabled for this session; traffic uses ordinary policy enforcement."
			case len(matches) > 0:
				hint.State = "authorized"
				hint.Code = "grant_installed"
				hint.Reason = fmt.Sprintf("UDP grants exist for %d destination/interface entries on this exact socket. No recent fast-path hit was observed; this does not prove every packet bypasses checking.", len(matches))
				known := true
				for _, g := range matches {
					known = known && g.statsKnown
					if g.active {
						hint.State = "in_use"
						hint.Code = "recent_udp_hit"
						hint.Reason = "UDP fast-path packets were observed on this exact socket within the last 1.5 seconds; other destinations can still use normal checking."
						break
					}
				}
				if hint.State != "in_use" && !known {
					hint.State = "unknown"
					hint.Code = "hit_status_unavailable"
					hint.Reason = "Socket grants are present, but recent UDP fast-path use could not be read."
				}
			case row.Socket.Remote.Port() == 0 || row.Socket.Remote.Addr().IsUnspecified():
				hint.Code = "destination_not_observed"
				hint.Reason = "This unconnected UDP socket has no single observed destination. Fast-path grants are destination-specific; use cannot be inferred from this row."
			default:
				hint.State = "inactive"
				hint.Code = "no_grant_observed"
				hint.Reason = "No socket/destination grant is present in the latest published state. The initial verification or policy/capacity reason was not recorded; this is not a Deny verdict."
				for _, grant := range p.socketHints.grants {
					if grant.netns == row.Socket.NetNS && grant.cookie == row.Socket.Cookie && grant.local == row.Socket.Local.String() && grant.remote == row.Socket.Remote.String() {
						// A horizon in the past must not appear as an installed live authorization.
						if grant.deadline != 0 && socketgrant.BootNow() >= grant.deadline {
							hint.Code = "permission_expired"
							hint.Reason = "The recorded temporary authorization has expired."
							break
						}
						hint.State = "authorized"
						hint.Code = "grant_installed"
						hint.Reason = fmt.Sprintf("A grant is installed for this socket and destination on output interface %d seen at verification. A route change falls back to ordinary checking. This is not a per-packet hit or delivery guarantee.", grant.ifindex)
						break
					}
				}
			}
		}
		row.FastPath = &hint
	}
	return snapshot
}

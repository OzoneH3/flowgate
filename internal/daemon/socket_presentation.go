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
	netns, cookie, local, remote string
	deadline                     uint64
	ifindex                      uint32
}
type socketFastPathHints struct {
	available, disabled bool
	failure             string
	grants              []socketGrantHint
}

// Caller already holds Engine.mu for the existing bounded presentation publisher.
// No resolver, policy evaluation, route lookup, or additional BPF reads occur here.
func (e *Engine) socketFastPathHintsLocked() socketFastPathHints {
	s := e.socketAuthorization
	if s == nil {
		return socketFastPathHints{}
	}
	out := socketFastPathHints{available: s.productionSession && s.routeBound, disabled: s.disabled}
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
		out.grants = append(out.grants, socketGrantHint{netns: f.flow.NetNS, cookie: hex.EncodeToString(cookie[:]), local: f.flow.Local.String(), remote: f.flow.Remote.String(), deadline: f.deadline, ifindex: f.key.Interface})
	}
	return out
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
			switch {
			case time.Since(p.at) > time.Second:
				hint.Code = "status_stale"
				hint.Reason = "Fast-path status is stale; current use is unknown."
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

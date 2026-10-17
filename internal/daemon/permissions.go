package daemon

import "flowgate/internal/identity"

// AdministratorUID is configured by a privileged daemon before serving, never
// supplied in a request. Each endpoint still authenticates SO_PEERCRED and 0600.
type Permissions struct {
	Role             string `json:"role"`
	ObservationScope string `json:"observation_scope"`
	PolicyScope      string `json:"policy_scope"`
	CanManageRules   bool   `json:"can_manage_rules"`
	CanDecide        bool   `json:"can_decide"`
}

func (e *Engine) administrator(uid uint32) bool {
	return uid == 0 || (e.AdministratorUID != nil && uid == *e.AdministratorUID)
}
func (e *Engine) permissions(uid uint32, readonly bool) Permissions {
	p := Permissions{Role: "user", ObservationScope: "self", PolicyScope: "self", CanManageRules: !readonly && e.SaveRules != nil, CanDecide: !readonly && e.Mode != "daemon-monitor"}
	if e.APIUID == nil && e.Mode == "host-monitor" {
		p.ObservationScope = "user-visible"
	}
	if e.administrator(uid) {
		p.Role = "administrator"
		p.ObservationScope = "machine"
		p.PolicyScope = "machine"
	}
	return p
}

// A root census must not disclose another user's process metadata on an ordinary
// user's endpoint. Copy before projection; never mutate collector-owned maps.
func activityFor(s identity.ActivitySnapshot, uid uint32, admin bool) identity.ActivitySnapshot {
	if admin {
		return s
	}
	out := s
	out.Rows = []identity.ActivityRow{}
	out.Processes = map[string]identity.ActivityProcess{}
	out.OwnershipCounts = map[string]int{}
	for _, r := range s.Rows {
		own := false
		foreign := false
		for _, id := range r.Owners {
			p, ok := s.Processes[id]
			if !ok {
				foreign = true
				continue
			}
			if p.UID == uid {
				own = true
			} else {
				foreign = true
			}
		}
		// Mixed-user shared sockets are withheld, not projected into a falsely
		// exclusive one-owner application. Creation UID alone is not a policy owner.
		if foreign || (!own && r.Socket.UID != uid) {
			continue
		}
		out.Rows = append(out.Rows, r)
		out.OwnershipCounts[r.OwnershipCategory]++
		for _, id := range r.Owners {
			out.Processes[id] = s.Processes[id]
		}
	}
	if s.UDP != nil {
		u := *s.UDP
		u.Rows = nil
		if u.UID != uid {
			u = identity.UDPSnapshot{State: "unavailable", Reason: "Collector metadata outside authorized user scope"}
		}
		out.UDP = &u
	}
	out.Issues = append([]string{}, s.Issues...)
	out.Issues = append(out.Issues, "User-scoped projection; foreign and mixed-user ownership rows withheld; not machine-wide visibility")
	return out
}

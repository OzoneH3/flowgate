package daemon

import "flowgate/internal/identity"

// AdministratorUID is configured by a privileged daemon before serving, never
// supplied in a request. Each endpoint still authenticates SO_PEERCRED and 0600.
type Permissions struct {
	CanManageMachineRules bool `json:"can_manage_machine_rules"`
	CanViewMeasurements   bool `json:"can_view_measurements"`
	CanControlTraffic     bool `json:"can_control_traffic"`
	CanControlProtection  bool `json:"can_control_protection"`
	CanControlEvaluation  bool `json:"can_control_evaluation"`

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
	if e.Evaluation != nil {
		p.CanDecide = !readonly && e.Evaluation.Status().State == "active"
		p.CanControlEvaluation = !readonly && (uid == 0 || (e.EvaluationControlUID != nil && uid == *e.EvaluationControlUID && e.administrator(uid)))
	}
	if e.Protection != nil {
		p.CanControlProtection = !readonly && (uid == 0 || (e.ProtectionControlUID != nil && uid == *e.ProtectionControlUID && e.administrator(uid)))
		if e.Protection.ProtectionStatus().State == "active" {
			p.CanDecide = !readonly
		}
	}
	p.CanViewMeasurements = e.Activity != nil
	p.CanControlTraffic = !readonly && e.Traffic != nil && (uid == 0 || (e.TrafficControlUID != nil && uid == *e.TrafficControlUID && e.administrator(uid)))
	if e.APIUID == nil && e.Mode == "host-monitor" {
		p.ObservationScope = "user-visible"
	}
	if e.administrator(uid) {
		p.Role = "administrator"
		p.ObservationScope = "machine"
		p.PolicyScope = "machine"
	}
	p.CanManageMachineRules = p.CanManageRules && e.administrator(uid)
	return p
}

// A root census must not disclose another user's process metadata on an ordinary
// user's endpoint. Copy before projection; never mutate collector-owned maps.
func activityFor(s identity.ActivitySnapshot, uid uint32, admin bool) identity.ActivitySnapshot {
	if admin {
		return s
	}
	out := s
	if s.TCPInitiation != nil {
		v := *s.TCPInitiation
		v.Rows = nil
		v.Lost = 0
		v.Partial = true
		v.Reason = "User-scoped event evidence; machine-global loss counters withheld"
		out.TCPInitiation = &v
	}
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
		if r.Socket.Protocol == "udp" && s.UDP != nil && s.UDP.Machine {
			if !own || len(r.Owners) == 0 || (r.OwnershipCategory != "visible-holder" && r.OwnershipCategory != "shared") {
				r.Traffic = identity.Traffic{State: "unavailable", Reason: "UDP ownership unresolved; machine counters withheld from ordinary peer"}
				r.Socket.Counters = nil
			} else {
				r.Traffic.Partial = true
				if r.Traffic.Available {
					r.Traffic.Reason = "UDP API-returned bytes across all peers; user-scoped view is partial, machine loss telemetry withheld; not delivery evidence"
				} else {
					r.Traffic.Reason = "UDP collection/registration unavailable for this user-scoped socket"
				}
			}
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
		if u.Machine {
			u.Missed = 0
			u.UID = uid
			u.Machine = false
			u.Reason = "User-scoped machine UDP view; only current visible same-UID ownership can carry measurements; global loss telemetry withheld"
		} else if u.UID != uid {
			u = identity.UDPSnapshot{State: "unavailable", Reason: "Collector metadata outside authorized user scope"}
		}
		out.UDP = &u
	}
	out.Issues = append([]string{}, s.Issues...)
	out.Issues = append(out.Issues, "User-scoped projection; foreign and mixed-user ownership rows withheld; not machine-wide visibility")
	return out
}

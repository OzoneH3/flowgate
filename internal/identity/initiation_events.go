package identity

import "time"

type InitiationEvents struct {
	State      string                `json:"state"`
	Generation string                `json:"generation,omitempty"`
	NetNS      string                `json:"netns"`
	Reason     string                `json:"reason"`
	Partial    bool                  `json:"partial"`
	Lost       uint64                `json:"lost_events"`
	Collected  time.Time             `json:"collected,omitempty"`
	Rows       map[string]Initiation `json:"-"`
}

func ApplyInitiationEvents(out *ActivitySnapshot, events InitiationEvents) {
	status := events
	status.Rows = nil
	out.TCPInitiation = &status
	if events.Generation == "" || events.NetNS == "" || events.Collected.After(time.Now().Add(5*time.Second)) || events.State != "active" || events.Collected.IsZero() || time.Since(events.Collected) > 4*time.Second {
		return
	}
	for i := range out.Rows {
		r := &out.Rows[i]
		s := r.Socket
		if s.Protocol != "tcp" || s.State == 10 || s.State == 7 || s.NetNS != events.NetNS || directionKey(s) == "" {
			continue
		}
		v, ok := events.Rows[s.Cookie]
		if !ok || v.Generation != events.Generation || v.ObservedAt == nil || v.ObservedAt.After(events.Collected) || v.State != "known" && v.State != "ambiguous" {
			continue
		}
		if v.State == "known" && v.Direction != "incoming" && v.Direction != "outgoing" {
			continue
		}
		// Same kernel cookie/current namespace only. Never copied into process authority.
		r.Initiation = v
		r.Direction = "Unknown"
		if v.State == "known" {
			if v.Direction == "incoming" {
				r.Direction = "Incoming"
			} else {
				r.Direction = "Outgoing"
			}
		}
	}
}

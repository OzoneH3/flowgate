package identity

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// Initiation describes observed TCP initiation, never firewall admission or byte
// direction. No process, application, port convention or policy decision is used.
type Initiation struct {
	State      string     `json:"state"`
	Direction  string     `json:"direction,omitempty"`
	Source     string     `json:"source"`
	Reason     string     `json:"reason"`
	ObservedAt *time.Time `json:"observed_at,omitempty"`
}
type initiationSample struct {
	socket   Socket
	evidence Initiation
	at       time.Time
}

func directionKey(s Socket) string {
	b, err := hex.DecodeString(s.Cookie)
	if err != nil || len(b) != 8 || s.NetNS == "" || s.Cookie == "0000000000000000" || s.Cookie == "ffffffffffffffff" {
		return ""
	}
	return fmt.Sprintf("%s:%d:%s:%s", s.NetNS, s.Family, s.Protocol, s.Cookie)
}
func ambiguous(reason string) Initiation {
	return Initiation{State: "ambiguous", Source: "inet-diag", Reason: reason}
}
func (c *ActivityCollector) directions(out *ActivitySnapshot, now time.Time) {
	next := make(map[string]initiationSample, len(out.Rows))
	if !out.Complete {
		c.initiations = nil
	}
	for i := range out.Rows {
		row := &out.Rows[i]
		s := row.Socket
		row.Direction = "Unknown"
		info := Initiation{State: "unknown", Source: "inet-diag", Reason: "Initiation not observed for this socket; established state/endpoints do not identify the initiator"}
		if s.Protocol == "udp" {
			info.Reason = "UDP socket diagnostics do not identify an initiating peer; no inference from connect, ports or byte direction"
			if s.Remote.Port() == 0 && s.Remote.Addr().IsUnspecified() {
				info.State = "unconnected"
			}
		} else if s.Protocol == "tcp" {
			key := directionKey(s)
			old, ok := c.initiations[key]
			if key == "" || now.Sub(old.at) > 60*time.Second || now.Before(old.at) {
				ok = false
			}
			if ok {
				info = old.evidence
				if old.socket.Local != s.Local || old.socket.Remote != s.Remote || (old.socket.Inode != s.Inode && !(old.socket.Inode == 0 && s.Inode != 0 && info.Direction == "incoming")) {
					info = ambiguous("Socket identity constraints changed for the same cookie; previous initiation evidence is not transferred")
				}
			}
			switch s.State {
			case 7:
				info = Initiation{State: "unknown", Source: "inet-diag", Reason: "TCP socket is closed/disconnected; previous handshake evidence is cleared"}
			case 10:
				info = Initiation{State: "listening", Source: "inet-diag", Reason: "TCP listener, not an initiated connection"}
			case 2: // TCP_SYN_SENT: active open is observed on this exact socket.
				if info.State == "ambiguous" || (info.Direction != "" && info.Direction != "outgoing") {
					info = ambiguous("Conflicting handshake observations for this cookie; initiation is ambiguous")
				} else {
					at := now
					info = Initiation{State: "known", Direction: "outgoing", Source: "inet-diag-syn-sent", Reason: "Observed TCP SYN-sent on this kernel socket cookie; retained only while this socket remains continuously visible", ObservedAt: &at}
				}
			case 3, 12:
				// inet_diag reports passive request_sock as SYN_RECV with inode zero
				// and without full-socket diagnostic attributes. Orphaned full sockets
				// can also have inode zero: that alone is not sufficient evidence.
				// A full socket in SYN_RECV can instead be simultaneous active open.
				if s.Inode != 0 || !s.diagObserved || s.diagFull || info.State == "ambiguous" || (info.Direction != "" && info.Direction != "incoming") {
					info = ambiguous("SYN-received full socket or conflicting handshake observations; simultaneous open cannot be excluded")
				} else {
					at := now
					info = Initiation{State: "known", Direction: "incoming", Source: "inet-diag-passive-request", Reason: "Observed passive TCP request (SYN-received, inode zero) for this cookie; not inferred from a listener port", ObservedAt: &at}
				}
			}
			if key == "" && info.State == "known" {
				info = Initiation{State: "unknown", Source: "inet-diag", Reason: "No valid kernel socket cookie/namespace for stable initiation evidence"}
			}
			if key != "" {
				next[key] = initiationSample{s, info, now}
			}
		}
		if info.State == "known" {
			row.Direction = strings.ToUpper(info.Direction[:1]) + info.Direction[1:]
		}
		row.Initiation = info
	}
	// Missing sockets, incomplete census, observer restart and long gaps never
	// inherit evidence by endpoint/PID. Memory is bounded by the current row census.
	c.initiations = next
}

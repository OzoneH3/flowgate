package identity

// TCP_INFO is a length-versioned Linux UAPI. Requesting it via inet_diag needs
// no packet interception. Do not interpret queue occupancy as a byte counter.
import (
	"encoding/binary"
	"strings"
	"time"
)

type TCPBytes struct {
	Uploaded   uint64 `json:"uploaded"`
	Downloaded uint64 `json:"downloaded"`
}

func parseTCPBytes(b []byte) *TCPBytes {
	// include/uapi/linux/tcp.h: tcpi_bytes_received at 128, tcpi_bytes_sent at 200.
	if len(b) < 208 {
		return nil
	}
	return &TCPBytes{Uploaded: binary.NativeEndian.Uint64(b[200:208]), Downloaded: binary.NativeEndian.Uint64(b[128:136])}
}

type Traffic struct {
	State        string    `json:"state"`
	Partial      bool      `json:"partial"`
	Available    bool      `json:"available"`
	Definition   string    `json:"definition"`
	Reason       string    `json:"reason"`
	Source       string    `json:"source,omitempty"`
	Since        time.Time `json:"since,omitempty"`
	Uploaded     uint64    `json:"uploaded"`
	Downloaded   uint64    `json:"downloaded"`
	UploadRate   *float64  `json:"upload_bps,omitempty"`
	DownloadRate *float64  `json:"download_bps,omitempty"`
}
type trafficSample struct {
	base, previous TCPBytes
	since, at      time.Time
	owners         string
	udpGeneration  string
	udpSample      int64
}

func (c *ActivityCollector) measure(out *ActivitySnapshot, now time.Time) {
	next := make(map[string]trafficSample, len(out.Rows))
	for i := range out.Rows {
		row := &out.Rows[i]
		s := row.Socket
		udp := false
		udpSince := time.Time{}
		if s.Protocol == "udp" && out.UDP != nil && out.UDP.State == "active" && time.Since(out.UDP.Collected) < 4*time.Second {
			if count, ok := out.UDP.Rows[s.Cookie]; ok {
				s.Counters = &TCPBytes{Uploaded: count.Uploaded, Downloaded: count.Downloaded}
				udp = true
				udpSince = count.Since
			}
		}
		t := Traffic{State: "unavailable", Reason: "TCP byte counters unavailable for this socket/state or kernel"}
		if s.Protocol != "tcp" {
			t.Reason = "UDP collector is not enabled; basic inet_diag has no transferred-byte counters"
			if out.UDP != nil {
				t.Reason = "UDP collector " + out.UDP.State + ": " + out.UDP.Reason
				if out.UDP.State == "warming-up" {
					t.State = "warming-up"
				}
				if out.UDP.State == "active" {
					t.State = "warming-up"
					t.Reason = "UDP cookie registration warming up; no registered counters yet"
					if !out.UDP.Machine && out.UDP.UID != s.UID {
						t.State = "unavailable"
						t.Reason = "UDP socket UID is outside this collector's selected-user scope"
					}
				}
			}
		}
		valid := s.Counters != nil && (s.Protocol == "tcp" || udp) && (s.Protocol != "tcp" || (s.State != 10 && s.State != 6)) && s.Cookie != "" && s.Cookie != "ffffffffffffffff"
		if valid {
			// Row identity contains namespace, cookie, inode, protocol and endpoints.
			// Ownership changes retain socket totals, but suppress rates for that interval.
			owners := strings.Join(row.Owners, "|")
			for _, id := range row.Owners {
				p := out.Processes[id]
				owners += "|" + p.Application.Key + "|" + p.Application.Revision
			}
			raw := *s.Counters
			old, ok := c.traffic[row.ID]
			dt := now.Sub(old.at).Seconds()
			if udp {
				dt = float64(out.UDP.SampleNS-old.udpSample) / 1e9
			}
			continuous := ok && (!udp || old.udpGeneration == out.UDP.Generation) && raw.Uploaded >= old.previous.Uploaded && raw.Downloaded >= old.previous.Downloaded && (dt > 0 || (udp && dt == 0)) && dt <= 60 && (udpSince.IsZero() || old.since.Equal(udpSince))
			if !continuous {
				old = trafficSample{base: raw, previous: raw, since: now, at: now, owners: owners}
			}
			if udp && !continuous {
				old.base = TCPBytes{}
				old.since = udpSince
			}
			t = Traffic{State: "warming-up", Definition: "tcp-transport-payload", Available: true, Source: "Linux INET_DIAG_INFO TCP_INFO payload counters", Since: old.since, Uploaded: raw.Uploaded - old.base.Uploaded, Downloaded: raw.Downloaded - old.base.Downloaded, Reason: "Observed since baseline; upload includes retransmitted payload, download is accepted TCP payload; excludes headers/ACKs"}
			if udp {
				t.Definition = "udp-api-reported"
				t.Source = "BPF sock_send_length/sock_recv_length (socket totals, all peers)"
				t.Reason = "Successful send return bytes and non-PEEK/non-ERRQUEUE receive return bytes; not wire traffic or remote delivery. MSG_TRUNC can report full datagram; ordinary truncated receive reports copied size. Socket totals across all peers."
				if reason := out.UDP.TracingGapReason(); reason != "" {
					t.Partial = true
					t.Reason += " " + reason
				}
				if out.UDP.Missed > 0 {
					t.Partial = true
					t.Reason += " Partial: collector missed operations before cookie registration or hit coverage limits"
				}
			}
			if continuous && dt > 0 && owners == old.owners {
				up := float64(raw.Uploaded-old.previous.Uploaded) / dt
				down := float64(raw.Downloaded-old.previous.Downloaded) / dt
				t.State = "measured"
				t.UploadRate = &up
				t.DownloadRate = &down
			}
			if udp {
				old.udpGeneration = out.UDP.Generation
				old.udpSample = out.UDP.SampleNS
			}
			old.owners = owners
			old.previous = raw
			old.at = now
			next[row.ID] = old
		}
		row.Traffic = t
	}
	// No absent/closed sockets or missing counters are retained. A later return is
	// a fresh baseline, not a zero sample. State is bounded by the 2048-row census.
	c.traffic = next
}

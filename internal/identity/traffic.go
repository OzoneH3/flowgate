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
	Available    bool      `json:"available"`
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
}

func (c *ActivityCollector) measure(out *ActivitySnapshot, now time.Time) {
	next := make(map[string]trafficSample, len(out.Rows))
	for i := range out.Rows {
		row := &out.Rows[i]
		s := row.Socket
		t := Traffic{Reason: "TCP byte counters unavailable for this socket/state or kernel"}
		if s.Protocol != "tcp" {
			t.Reason = "UDP transferred-byte counters are not supplied by inet_diag; queue occupancy is not traffic"
		}
		valid := s.Counters != nil && s.Protocol == "tcp" && s.State != 10 && s.State != 6 && s.Cookie != "" && s.Cookie != "ffffffffffffffff"
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
			continuous := ok && raw.Uploaded >= old.previous.Uploaded && raw.Downloaded >= old.previous.Downloaded && dt > 0 && dt <= 60
			if !continuous {
				old = trafficSample{base: raw, previous: raw, since: now, at: now, owners: owners}
			}
			t = Traffic{Available: true, Source: "Linux INET_DIAG_INFO TCP_INFO payload counters", Since: old.since, Uploaded: raw.Uploaded - old.base.Uploaded, Downloaded: raw.Downloaded - old.base.Downloaded, Reason: "Observed since baseline; upload includes retransmitted payload, download is accepted TCP payload; excludes headers/ACKs"}
			if continuous && owners == old.owners {
				up := float64(raw.Uploaded-old.previous.Uploaded) / dt
				down := float64(raw.Downloaded-old.previous.Downloaded) / dt
				t.UploadRate = &up
				t.DownloadRate = &down
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

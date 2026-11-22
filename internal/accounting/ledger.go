// Package accounting retains sampled counter deltas, not packet-delivery or
// permission evidence. It consumes collector observations independently of reads.
package accounting

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flowgate/internal/identity"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const Capability = "observed-usage-v1"
const MaxEntries = 1024
const MaxBaselines = 2048
const TCP = "tcp-transport-payload"
const UDP = "udp-api-reported"

type Application struct {
	Key      string `json:"key"`
	Revision string `json:"revision"`
	Kind     string `json:"kind"`
	Name     string `json:"name"`
}
type Entry struct {
	ID              string      `json:"id"`
	UID             uint32      `json:"uid"`
	Application     Application `json:"application"`
	Source          string      `json:"source"`
	Uploaded        string      `json:"uploaded"`
	Downloaded      string      `json:"downloaded"`
	FirstObservedAt time.Time   `json:"first_observed_at"`
	LastObservedAt  time.Time   `json:"last_observed_at"`
	Partial         bool        `json:"partial"`
}
type Total struct {
	Source     string `json:"source"`
	Uploaded   string `json:"uploaded"`
	Downloaded string `json:"downloaded"`
}
type Source struct {
	Source string `json:"source"`
	State  string `json:"state"`
	Reason string `json:"reason"`
}
type Snapshot struct {
	Version         int        `json:"version"`
	Epoch           string     `json:"epoch"`
	Sequence        string     `json:"sequence"`
	StartedAt       time.Time  `json:"started_at"`
	SampledAt       *time.Time `json:"sampled_at,omitempty"`
	Scope           string     `json:"scope"`
	Partial         bool       `json:"partial"`
	Attribution     string     `json:"attribution"`
	CapacityLimited bool       `json:"capacity_limited"`
	Saturated       bool       `json:"saturated"`
	Sources         []Source   `json:"sources"`
	Entries         []Entry    `json:"entries"`
	Unattributed    []Total    `json:"unattributed,omitempty"`
	Gaps            string     `json:"gaps,omitempty"`
}
type counts struct {
	up, down  uint64
	saturated bool
}
type retained struct {
	entry  Entry
	counts counts
}
type baseline struct {
	up, down   uint64
	since      time.Time
	generation string
	source     string
	sampleNS   int64
	at         time.Time
	owner      string
	entry      Entry
}

// Ledger never evicts totals. On cardinality exhaustion it freezes accumulation
// until restart, explicitly reporting the loss of coverage. Memory is bounded by
// fixed row counts and bounded metadata; baselines retain hashes, not processes.
type Ledger struct {
	udpRawPrevious                    map[string]baseline
	udpRawGeneration, udpRawNamespace string
	udpRawSample                      int64
	udpRawMissed                      uint64
	udpRawSkipped                     uint64
	udpRawSkippedKnown                bool
	udpRawTail                        bool
	udpRawFinalsLost                  uint64

	mu               sync.Mutex
	epoch            string
	started, sampled time.Time
	sequence         uint64
	entries          map[string]*retained
	previous         map[string]baseline
	unattributed     map[string]*counts
	sources          []Source
	gaps             uint64
	frozen           bool
	udpGeneration    string
	udpMissed        uint64
}

func New() *Ledger {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		panic(err)
	}
	return &Ledger{epoch: hex.EncodeToString(nonce[:]), started: time.Now().UTC(), entries: map[string]*retained{}, previous: map[string]baseline{}, unattributed: map[string]*counts{TCP: {}, UDP: {}}, sources: []Source{{TCP, "unavailable", "No complete observation yet"}, {UDP, "unavailable", "No collector observation yet"}}}
}
func hash(v any) string {
	b, _ := json.Marshal(v)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
func decimal(n uint64) string { return strconv.FormatUint(n, 10) }
func add(a, b uint64) (uint64, bool) {
	if b >= math.MaxUint64-a {
		return math.MaxUint64, true
	}
	return a + b, false
}
func (c *counts) add(up, down uint64) {
	var a, b bool
	c.up, a = add(c.up, up)
	c.down, b = add(c.down, down)
	c.saturated = c.saturated || a || b
}
func (l *Ledger) gap() {
	if l.gaps < math.MaxUint64 {
		l.gaps++
	}
}
func name(s string) string {
	if len(s) > 256 {
		s = s[:256]
		for !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return strings.Clone(s)
}

// owner trusts only the collector's verified identity fields. DisplayApplication,
// launch provenance, socket creation UID and name never establish attribution.
func owner(s identity.ActivitySnapshot, r identity.ActivityRow) (Entry, string) {
	var a identity.Application
	var uid uint32
	var runtime any
	if v := r.RuntimeApplication; v != nil {
		// Activity can retain a previous Wine label after the fresh runtime
		// census fails. It still looks like an association on the wire.
		// Keep the counters and withhold this endpoint's ownership evidence.
		if v.DisplaySource != "" || v.DisplayVerifiedAt != "" {
			return Entry{}, ""
		}
		ev := v.Evidence
		if v.Application.Kind != "wine" || v.Application.Prefix == "" || ev.Prefix != v.Application.Prefix || ev.UID != v.UID || ev.Generation == "" || ev.BrokerPID <= 0 || ev.BrokerStart == "" || ev.SocketCookie != r.Socket.Cookie || len(ev.Owners) != 1 || ev.Owners[0].PID == 0 || ev.Owners[0].Created == 0 {
			return Entry{}, ""
		}
		if exe := v.Application.Executable; exe == "" || len(exe) > 4096 || !utf8.ValidString(exe) {
			return Entry{}, ""
		}
		if r.OwnershipCategory != "visible-holder" && r.OwnershipCategory != "shared" {
			return Entry{}, ""
		}
		a, uid = v.Application, v.UID
		// Only holder incarnation fields: mutable socket state is not identity.
		w := ev.Owners[0]
		runtime = []any{v.Application.Executable, ev.Generation, ev.Runtime, ev.Prefix, ev.BrokerPID, ev.BrokerStart, ev.DirectPID, ev.DirectStart, w.PID, w.Created, w.CreationTime, w.UnixPID, w.Image}
	} else {
		if r.OwnershipCategory != "visible-holder" || len(r.Owners) != 1 {
			return Entry{}, ""
		}
		p, ok := s.Processes[r.Owners[0]]
		if !ok || !identity.LiveRuleable(p.Application) {
			return Entry{}, ""
		}
		a, uid = p.Application, p.UID
	}
	if !utf8.ValidString(a.Key+a.Revision+a.Kind+a.Runtime+a.Prefix) || a.Key == "" || a.Revision == "" || len(a.Key) > 256 || len(a.Revision) > 256 || len(a.Kind) > 256 || len(a.Runtime) > 4096 || len(a.Prefix) > 4096 || len(r.Owners) == 0 || len(r.Owners) > 32 {
		return Entry{}, ""
	}
	var holders []string
	brokerFound := r.RuntimeApplication == nil
	for _, id := range r.Owners {
		p, ok := s.Processes[id]
		if !ok || p.UID != uid || p.PID <= 0 || p.Start == "" || p.BootID == "" || p.NetNS != r.Socket.NetNS || p.ExecutableRevision == "" {
			return Entry{}, ""
		}
		if v := r.RuntimeApplication; v != nil {
			if p.PID == v.Evidence.BrokerPID && p.Start == v.Evidence.BrokerStart {
				brokerFound = true
			} else if p.Application.Kind != "wine" || p.Application.Prefix != v.Application.Prefix || p.Application.Key != v.Application.Key || p.Application.Revision != v.Application.Revision {
				return Entry{}, ""
			}
		}
		holders = append(holders, hash([]any{p.BootID, p.NetNS, p.PIDNS, p.MountNS, p.PID, p.Start, p.ExecutableRevision, p.Application.Key, p.Application.Revision, p.Application.Prefix}))
	}
	if !brokerFound {
		return Entry{}, ""
	}
	sort.Strings(holders)
	e := Entry{UID: uid, Application: Application{a.Key, a.Revision, a.Kind, name(a.Name)}, Source: r.Traffic.Definition, Partial: true}
	// Bound the encoded metadata too (control characters expand in JSON).
	if encoded, _ := json.Marshal(e.Application); len(encoded) > 1024 {
		return Entry{}, ""
	}
	e.ID = hash([]any{uid, a.Key, a.Revision, a.Kind, a.Runtime, a.Prefix, e.Source})
	return e, hash([]any{e.ID, holders, runtime})
}
func activityBaselines(s identity.ActivitySnapshot, rawUDP, udpActive bool) map[string]baseline {
	next := make(map[string]baseline, len(s.Rows))
	for _, r := range s.Rows {
		t := r.Traffic
		if !t.Available || t.Since.IsZero() || r.Socket.Cookie == "" || r.Socket.Cookie == "ffffffffffffffff" || r.Socket.NetNS == "" {
			continue
		}
		generation := "tcp"
		switch t.Definition {
		case TCP:
			if r.Socket.Protocol != "tcp" {
				continue
			}
		case UDP:
			if rawUDP {
				continue
			} // source counters already reduced independently
			if r.Socket.Protocol != "udp" || !udpActive || s.UDP.NetNS != r.Socket.NetNS {
				continue
			}
			generation = s.UDP.Generation
		default:
			continue
		}
		key := hash([]any{r.Socket.NetNS, r.Socket.Cookie, r.Socket.Inode, r.Socket.Family, r.Socket.Protocol})
		// Duplicate socket records cannot donate the same bytes twice or choose an
		// arbitrary owner. Reject these Activity rows before applying their deltas.
		if _, exists := next[key]; exists {
			return nil
		}
		e, o := owner(s, r)
		if t.Definition == UDP && !s.UDP.Machine && e.UID != s.UDP.UID {
			e, o = Entry{}, ""
		}
		b := baseline{up: t.Uploaded, down: t.Downloaded, since: t.Since, generation: generation, source: t.Definition, at: s.Collected, owner: o, entry: e}
		if t.Definition == UDP {
			b.sampleNS = s.UDP.SampleNS
		}
		next[key] = b
	}
	return next
}

func (l *Ledger) Observe(s identity.ActivitySnapshot) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.frozen || s.Sequence == 0 || s.Sequence <= l.sequence {
		return
	}
	discontinuity := l.sequence != 0 && (s.Sequence != l.sequence+1 || !s.Collected.After(l.sampled) || s.Collected.Sub(l.sampled) > 60*time.Second)
	invalidTime := s.Collected.IsZero() || (!l.sampled.IsZero() && !s.Collected.After(l.sampled))
	complete := s.Complete && s.Error == "" && !invalidTime
	sources := []Source{{TCP, "unavailable", "Collection incomplete; counters rebaseline"}, {UDP, "unavailable", "UDP collector unavailable"}}
	if s.Complete && s.Error == "" {
		sources[0] = Source{TCP, "active", "Sampled TCP payload; includes upload retransmissions, not delivery"}
	}
	if s.UDP != nil && s.UDP.State == "active" && s.UDP.Generation != "" && len(s.UDP.Generation) <= 256 && s.UDP.SampleNS > 0 && !s.UDP.Collected.IsZero() && s.Collected.Sub(s.UDP.Collected) >= 0 && s.Collected.Sub(s.UDP.Collected) < 4*time.Second {
		sources[1] = Source{UDP, "active", "Successful UDP API return bytes; not wire bytes or delivery"}
	}
	rawUDP := s.UDP != nil && s.UDP.AccountingRows != nil
	udpActive := sources[1].State == "active"
	rawActive := rawUDP && udpActive

	// Both reducers share one identity limit. Reject the entire observation
	// before advancing any cursor, even if only the second source would overflow.
	additions := map[string]bool{}
	var rawOwners map[string]baseline
	if rawActive {
		rawOwners = rawUDPOwners(s, complete && !discontinuity)
		if !l.planRawUDP(s.UDP, rawOwners, additions) {
			l.frozen = true
			l.gap()
			return
		}
	}
	var next map[string]baseline
	if complete && len(s.Rows) <= MaxBaselines {
		next = activityBaselines(s, rawUDP, udpActive)
	}
	if !discontinuity {
		for key, b := range next {
			old, ok := l.previous[key]
			if ok && b.owner != "" && b.owner == old.owner && b.since.Equal(old.since) && b.generation == old.generation && b.up >= old.up && b.down >= old.down && (b.source != UDP || (b.sampleNS > old.sampleNS && b.sampleNS-old.sampleNS <= int64(60*time.Second))) && (b.up != old.up || b.down != old.down) && l.entries[b.entry.ID] == nil {
				additions[b.entry.ID] = true
			}
		}
	}
	if len(l.entries)+len(additions) > MaxEntries {
		l.frozen = true
		l.gap()
		return
	}

	l.sequence = s.Sequence
	if !invalidTime {
		l.sampled = s.Collected
	}
	l.sources = sources
	if rawActive {
		l.observeRawUDP(s, rawOwners)
	}
	if discontinuity || !complete {
		l.gap()
		clear(l.previous)
		if !complete {
			for i := range l.sources {
				if i == 1 && rawActive {
					l.sources[i].Reason = "Registered UDP payload conserved; incomplete ownership goes to unattributed"
					continue
				}
				l.sources[i].State = "unavailable"
				l.sources[i].Reason = "Collection incomplete or timestamp invalid; counters rebaseline"
			}
			return
		}
	}
	if len(s.Rows) > MaxBaselines {
		clear(l.previous)
		l.gap()
		return
	}
	if s.UDP != nil && !rawUDP {
		if l.udpGeneration == s.UDP.Generation && l.udpMissed != s.UDP.Missed {
			l.gap()
			// Misses concern unregistered cookies, not counters of already
			// registered cookies. Preserve their monotonic, generation-scoped
			// baselines; each still needs matching ownership bookends below.
		}
		l.udpGeneration, l.udpMissed = s.UDP.Generation, s.UDP.Missed
	}
	if next == nil {
		l.gap()
		clear(l.previous)
		return
	}
	keys := make([]string, 0, len(next))
	for key := range next {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		b := next[key]
		old, ok := l.previous[key]
		if !ok {
			continue
		}
		if !b.since.Equal(old.since) || b.generation != old.generation || b.up < old.up || b.down < old.down {
			l.gap()
			continue
		}
		if b.source == UDP && b.sampleNS > old.sampleNS && b.sampleNS-old.sampleNS > int64(60*time.Second) {
			l.gap()
			continue
		}
		if b.source == UDP && b.sampleNS <= old.sampleNS {
			if b.sampleNS < old.sampleNS || b.up != old.up || b.down != old.down {
				// Removal below records this coverage break once.
				delete(next, key)
				continue
			}
			// A repeated collector sample cannot advance the ownership baseline.
			if b.owner != old.owner {
				old.owner = ""
			}
			next[key] = old
			continue
		}
		up, down := b.up-old.up, b.down-old.down
		if up == 0 && down == 0 {
			continue
		}
		if b.owner == "" || b.owner != old.owner {
			l.unattributed[b.source].add(up, down)
			continue
		}
		row := l.entries[b.entry.ID]
		if row == nil {
			b.entry.FirstObservedAt = old.at
			row = &retained{entry: b.entry}
			l.entries[b.entry.ID] = row
		}
		row.counts.add(up, down)
		row.entry.LastObservedAt = l.sampled
	}
	for key := range l.previous {
		if _, ok := next[key]; !ok {
			l.gap()
		}
	}
	l.previous = next
}

// Snapshot copies and projects before serialization. Reads do not change the
// reducer cursor. Entry IDs are opaque; foreign/global totals are never returned
// to an ordinary principal, even after the original owners have exited.
func (l *Ledger) Snapshot(uid uint32, admin bool) Snapshot {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := Snapshot{Version: 1, Epoch: l.epoch, Sequence: decimal(l.sequence), StartedAt: l.started, Scope: "user", Partial: true, Attribution: "sampled-owner", CapacityLimited: l.frozen, Sources: append([]Source(nil), l.sources...), Entries: []Entry{}}
	if !l.sampled.IsZero() {
		if time.Since(l.sampled) > 10*time.Second {
			for i := range out.Sources {
				out.Sources[i].State = "unavailable"
				out.Sources[i].Reason = "Observation overdue; retained totals are historical"
			}
		}
		at := l.sampled
		out.SampledAt = &at
	}
	for _, r := range l.entries {
		if !admin && r.entry.UID != uid {
			continue
		}
		e := r.entry
		e.Uploaded = decimal(r.counts.up)
		e.Downloaded = decimal(r.counts.down)
		out.Entries = append(out.Entries, e)
		out.Saturated = out.Saturated || r.counts.saturated
	}
	sort.Slice(out.Entries, func(i, j int) bool { return out.Entries[i].ID < out.Entries[j].ID })
	if admin {
		out.Scope = "machine"
		out.Gaps = decimal(l.gaps)
		for _, src := range []string{TCP, UDP} {
			c := l.unattributed[src]
			out.Unattributed = append(out.Unattributed, Total{src, decimal(c.up), decimal(c.down)})
			out.Saturated = out.Saturated || c.saturated
		}
	}
	return out
}

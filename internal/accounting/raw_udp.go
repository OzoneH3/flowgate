package accounting

import (
	"flowgate/internal/identity"
	"time"
)

// observeRawUDP conserves registered API payload counters independently of the
// FD census. Identity only chooses an application bucket versus unattributed;
// it never changes the collector's counter cursor or grants a permission.
func (l *Ledger) observeRawUDP(s identity.ActivitySnapshot, ownersValid bool) {
	u := s.UDP
	if l.frozen || u == nil || l.sources[1].State != "active" || u.AccountingRows == nil {
		return
	}
	if len(u.AccountingRows) > MaxBaselines || len(u.Retired) > MaxBaselines {
		l.gap()
		return
	}
	if l.udpRawGeneration != u.Generation || l.udpRawNamespace != u.NetNS {
		if len(l.udpRawPrevious) > 0 {
			l.gap()
		}
		l.udpRawPrevious = map[string]baseline{}
		l.udpRawGeneration = u.Generation
		l.udpRawNamespace = u.NetNS
		l.udpRawSample = 0
		l.udpRawMissed = u.Missed
		l.udpRawSkipped = 0
		l.udpRawSkippedKnown = false
	}
	if l.udpRawPrevious == nil {
		l.udpRawPrevious = map[string]baseline{}
	}
	if u.Missed != l.udpRawMissed {
		l.gap()
		l.udpRawMissed = u.Missed
	}
	l.sources[1].Reason = "Registered successful UDP API payload bytes; not delivery; uncertain ownership and post-observation close tails are unattributed"
	if reason := u.TracingGapReason(); reason != "" {
		l.sources[1].Reason += "; " + reason
	}
	if u.TracingSkipped != nil {
		if *u.TracingSkipped != l.udpRawSkipped {
			l.gap()
		}
		l.udpRawSkipped = *u.TracingSkipped
		l.udpRawSkippedKnown = true
	} else if l.udpRawSample == 0 || l.udpRawSkippedKnown {
		l.gap()
		l.udpRawSkippedKnown = false
	}
	owners := map[string]baseline{}
	if ownersValid {
		for _, r := range s.Rows {
			if r.Socket.Protocol != "udp" || r.Socket.NetNS != u.NetNS {
				continue
			}
			e, o := owner(s, r)
			if !u.Machine && e.UID != u.UID {
				o = ""
				e = Entry{}
			}
			if _, duplicate := owners[r.Socket.Cookie]; duplicate {
				owners[r.Socket.Cookie] = baseline{}
				continue
			}
			owners[r.Socket.Cookie] = baseline{owner: o, entry: e}
		}
	}
	if u.SampleNS <= l.udpRawSample {
		if u.SampleNS < l.udpRawSample {
			l.gap()
			return
		}
		// Repeated counter samples cannot donate bytes through a changed owner.
		for k, b := range l.udpRawPrevious {
			if owners[k].owner != b.owner {
				b.owner = ""
				l.udpRawPrevious[k] = b
			}
		}
		return
	}
	if l.udpRawSample != 0 && u.SampleNS-l.udpRawSample > int64(60*time.Second) {
		l.gap()
		for k, b := range l.udpRawPrevious {
			b.owner = ""
			l.udpRawPrevious[k] = b
		}
	}
	l.udpRawSample = u.SampleNS
	if u.FinalsLost != l.udpRawFinalsLost {
		l.gap()
		l.udpRawFinalsLost = u.FinalsLost
	}
	// Retired cookies have no verified holder at close. Preserve their final
	// delta once as unattributed, even if their last live owner was unambiguous.
	for cookie, c := range u.Retired {
		if _, live := u.AccountingRows[cookie]; live {
			l.gap()
			continue
		}
		l.rawUDPDelta(cookie, c, baseline{}, s.Collected, true)
		delete(l.udpRawPrevious, cookie)
	}
	// A legacy helper may omit a final snapshot. Wait a bounded interval, report
	// a gap and release its baseline; never fabricate a final zero counter.
	for k, b := range l.udpRawPrevious {
		if _, live := u.AccountingRows[k]; !live && u.SampleNS-b.sampleNS > int64(4*time.Second) {
			delete(l.udpRawPrevious, k)
			l.gap()
		}
	}
	for cookie, c := range u.AccountingRows {
		if cookie == "" || cookie == "ffffffffffffffff" || c.Since.IsZero() {
			l.gap()
			continue
		}
		b := owners[cookie]
		l.rawUDPDelta(cookie, c, b, s.Collected, false)
	}
}

func (l *Ledger) rawUDPDelta(cookie string, c identity.UDPCount, b baseline, at time.Time, retired bool) {
	old, exists := l.udpRawPrevious[cookie]
	if !exists && retired {
		l.gap()
		return
	} // no cursor: never replay a lifetime total
	if !exists && len(l.udpRawPrevious) >= MaxBaselines {
		l.frozen = true
		l.gap()
		return
	}
	current := b
	up, down := c.Uploaded, c.Downloaded
	continuous := exists && c.Since.Equal(old.since) && up >= old.up && down >= old.down
	if continuous {
		up -= old.up
		down -= old.down
	} else {
		if exists {
			l.gap()
			if c.Since.Equal(old.since) {
				up = 0
				down = 0
			}
		}
		// The first observation has no earlier ownership bookend.
		b.owner = ""
	}
	if up != 0 || down != 0 {
		if retired {
			l.gap()
			l.udpRawTail = true
		}
		if retired || b.owner == "" || !continuous || b.owner != old.owner {
			l.unattributed[UDP].add(up, down)
		} else {
			row := l.entries[b.entry.ID]
			if row == nil {
				if len(l.entries) >= MaxEntries {
					l.frozen = true
					l.gap()
					return
				}
				b.entry.FirstObservedAt = old.at
				row = &retained{entry: b.entry}
				l.entries[b.entry.ID] = row
			}
			row.counts.add(up, down)
			row.entry.LastObservedAt = at
		}
	}
	if retired {
		return
	}
	if !exists && len(l.udpRawPrevious) >= MaxBaselines {
		l.gap()
		return
	}
	// Preserve current ownership only for the next observation's bookend.
	l.udpRawPrevious[cookie] = baseline{up: c.Uploaded, down: c.Downloaded, since: c.Since, at: at, owner: current.owner, entry: current.entry, source: UDP, sampleNS: l.udpRawSample}
}

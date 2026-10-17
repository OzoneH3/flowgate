package decisionlog

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Query is decoded strictly; all filters are applied server-side to both
// paging directions. Cursors are decimal sequence strings from this log_id.
type Query struct {
	Limit       *int       `json:"limit"`
	Before      string     `json:"before"`
	After       string     `json:"after"`
	Since       *time.Time `json:"since"`
	Until       *time.Time `json:"until"`
	Direction   string     `json:"direction"`
	Action      string     `json:"action"`
	Source      string     `json:"source"`
	Application string     `json:"application"`
	LogID       string     `json:"log_id"`
}
type Page struct {
	Records     []Record `json:"records"`
	HasMore     bool     `json:"has_more"`
	NextBefore  string   `json:"next_before"`
	NextAfter   string   `json:"next_after"`
	Order       string   `json:"order"`
	Scope       string   `json:"scope"`
	Health      Health   `json:"health"`
	Limitations []string `json:"limitations"`
}

// QueryError carries an API error code: invalid_request, invalid_cursor,
// not_found or unavailable.
type QueryError struct{ Code, Message string }

func (e *QueryError) Error() string { return e.Message }
func qerr(code, format string, a ...any) error {
	return &QueryError{code, fmt.Sprintf(format, a...)}
}

var appKey = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Limitations states coverage honestly for every response.
var Limitations = []string{
	"Recorded only while FlowGate evaluates new connections (enforcing host or isolated lab); the non-enforcing monitor never records allow/block decisions and Activity rows are never backfilled.",
	"One record per evaluated initiation: a TCP SYN (retransmissions collapse) or a UDP flow lease; individual datagrams/packets are not logged.",
	"Allow means a FlowGate policy decision and kernel verdict submission; other firewall chains may still drop and receiver delivery is never observed.",
	"Records buffered in memory up to durability_window_ms (or a full batch) are lost if the daemon crashes; gap records mark known losses.",
	"Unparseable/non-initial queued packets (fragments, extension headers, non-SYN TCP) are dropped without a decision record.",
	"Retention keeps at most max_records within max_age_days; older records are removed in bounded steps.",
}

// DecodeQuery rejects unknown fields and malformed values.
func DecodeQuery(raw json.RawMessage) (Query, error) {
	var q Query
	if len(raw) == 0 {
		return q, nil
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&q); err != nil {
		return q, qerr("invalid_request", "malformed decision_query: %v", err)
	}
	if d.Decode(new(any)) != io.EOF {
		return q, qerr("invalid_request", "trailing decision_query data")
	}
	if q.Limit != nil && (*q.Limit < 0 || *q.Limit > MaxPage) {
		return q, qerr("invalid_request", "limit must be 0..%d", MaxPage)
	}
	if q.Before != "" && q.After != "" {
		return q, qerr("invalid_request", "use before or after, not both")
	}
	// after:"0" reads from the oldest retained record; before needs a real record.
	for _, c := range []string{q.Before, q.After} {
		if c != "" {
			if _, err := cursor(c); err != nil {
				return q, err
			}
		}
	}
	if q.Before == "0" {
		return q, qerr("invalid_cursor", "cursor must be a sequence from this log")
	}
	if q.Since != nil && q.Until != nil && !q.Since.Before(*q.Until) {
		return q, qerr("invalid_request", "since must be before until")
	}
	if q.Direction != "" && q.Direction != "incoming" && q.Direction != "outgoing" {
		return q, qerr("invalid_request", "direction must be incoming or outgoing")
	}
	if q.Action != "" && q.Action != "allow" && q.Action != "block" && q.Action != "pending" {
		return q, qerr("invalid_request", "action must be allow, block or pending")
	}
	if q.Source != "" && !Sources[q.Source] {
		return q, qerr("invalid_request", "unknown source")
	}
	if q.Application != "" && !appKey.MatchString(q.Application) {
		return q, qerr("invalid_request", "application must be an application key")
	}
	if len(q.LogID) > 64 {
		return q, qerr("invalid_request", "invalid log_id")
	}
	return q, nil
}
func cursor(c string) (int64, error) {
	if len(c) > 19 || strings.TrimLeft(c, "0123456789") != "" || (len(c) > 1 && c[0] == '0') {
		return 0, qerr("invalid_cursor", "cursor must be a sequence from this log")
	}
	n, err := strconv.ParseInt(c, 10, 64)
	if err != nil || n < 0 {
		return 0, qerr("invalid_cursor", "cursor must be a sequence from this log")
	}
	return n, nil
}

// Query returns one bounded page. Ordinary peers see only records whose
// principal UID is theirs plus metadata-free gap records; unknown-owner records
// are never shown to them.
func (l *Log) Query(q Query, uid uint32, admin bool) (Page, error) {
	if l == nil || l.db == nil {
		return Page{}, qerr("unavailable", "decision log unavailable: %v", l.causeText())
	}
	if q.LogID != "" && q.LogID != l.id {
		return Page{}, qerr("invalid_cursor", "log_id changed; restart paging from the newest records")
	}
	limit := DefaultPage
	if q.Limit != nil {
		limit = *q.Limit
	}
	p := Page{Records: []Record{}, Order: "newest_first", Scope: "self", Health: l.Health(admin), Limitations: Limitations}
	if admin {
		p.Scope = "machine"
	}
	where, args := []string{}, []any{}
	order := "DESC"
	if q.After != "" {
		n, _ := cursor(q.After)
		where, args, order, p.Order = append(where, "seq > ?"), append(args, n), "ASC", "oldest_first"
		p.NextAfter = q.After
	} else if q.Before != "" {
		n, _ := cursor(q.Before)
		where, args = append(where, "seq < ?"), append(args, n)
	}
	if !admin {
		where, args = append(where, "(owner_uid = ? OR kind = 'gap')"), append(args, int64(uid))
	}
	if q.Since != nil {
		where, args = append(where, "at >= ?"), append(args, q.Since.UnixNano())
	}
	if q.Until != nil {
		where, args = append(where, "at < ?"), append(args, q.Until.UnixNano())
	}
	for col, v := range map[string]string{"direction": q.Direction, "action": q.Action, "source": q.Source, "application": q.Application} {
		if v != "" {
			where, args = append(where, col+" = ?"), append(args, v)
		}
	}
	if limit == 0 {
		return p, nil
	}
	sqlText := "SELECT seq, document FROM decisions"
	if len(where) > 0 {
		sqlText += " WHERE " + strings.Join(where, " AND ")
	}
	sqlText += " ORDER BY seq " + order + " LIMIT ?"
	rows, err := l.db.Query(sqlText, append(args, limit+1)...)
	if err != nil {
		return Page{}, qerr("unavailable", "decision log query failed: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var seq int64
		var doc string
		if err = rows.Scan(&seq, &doc); err != nil {
			return Page{}, qerr("unavailable", "decision log read failed: %v", err)
		}
		if len(p.Records) == limit {
			p.HasMore = true
			break
		}
		r, err := decode(seq, doc, admin)
		if err != nil {
			return Page{}, qerr("unavailable", "corrupt decision record %d", seq)
		}
		p.Records = append(p.Records, r)
	}
	if err = rows.Err(); err != nil {
		return Page{}, qerr("unavailable", "decision log read failed: %v", err)
	}
	if n := len(p.Records); n > 0 {
		last := p.Records[n-1].Sequence
		if order == "ASC" {
			p.NextAfter = last
		} else if p.HasMore {
			p.NextBefore = last
		}
	}
	return p, nil
}

// Get returns one visible record; invisible and unknown IDs are both not_found.
func (l *Log) Get(id string, uid uint32, admin bool) (Record, error) {
	if l == nil || l.db == nil {
		return Record{}, qerr("unavailable", "decision log unavailable: %v", l.causeText())
	}
	if len(id) == 0 || len(id) > 64 {
		return Record{}, qerr("invalid_request", "decision_id required")
	}
	var seq int64
	var owner sql.NullInt64
	var kind, doc string
	err := l.db.QueryRow("SELECT seq, owner_uid, kind, document FROM decisions WHERE id = ?", id).Scan(&seq, &owner, &kind, &doc)
	if err == sql.ErrNoRows || (err == nil && !admin && kind != KindGap && (!owner.Valid || owner.Int64 != int64(uid))) {
		return Record{}, qerr("not_found", "unknown, removed or not visible decision record")
	}
	if err != nil {
		return Record{}, qerr("unavailable", "decision log read failed: %v", err)
	}
	return decode(seq, doc, admin)
}
func decode(seq int64, doc string, admin bool) (Record, error) {
	var r Record
	if err := json.Unmarshal([]byte(doc), &r); err != nil {
		return r, err
	}
	r.Sequence = uitoa(uint64(seq))
	if r.Kind == KindGap && !admin && r.Gap != nil {
		r.Gap.Dropped = nil // machine-wide loss counts withheld from ordinary peers
	}
	return r, nil
}
func (l *Log) causeText() string {
	if l == nil || l.cause == nil {
		return "not configured"
	}
	return l.cause.Error()
}

// ID is the log identity; it changes only when the database is recreated.
func (l *Log) ID() string {
	if l == nil {
		return ""
	}
	return l.id
}

package decisionlog

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"net/url"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// Bounds. A record document is capped, the buffer and batch are fixed, and
// retention keeps at most MaxRecords newer than MaxAge (pruned in bounded steps).
const (
	MaxRecords    = 20000
	MaxAge        = 30 * 24 * time.Hour
	BufferSize    = 1024
	BatchSize     = 256
	FlushInterval = time.Second
	MaxDocument   = 8192
	MaxPage       = 100
	DefaultPage   = 50
	pruneStep     = 1000
	maxFileSize   = 256 << 20
)

var ErrUnavailable = errors.New("decision log unavailable")

type Retention struct {
	MaxRecords     int    `json:"max_records"`
	MaxAgeDays     int    `json:"max_age_days"`
	Removed        uint64 `json:"removed"`
	RemovedThrough string `json:"removed_through"`
}
type Health struct {
	LogID              string    `json:"log_id"`
	State              string    `json:"state"`
	Recording          bool      `json:"recording"`
	CountsWithheld     bool      `json:"counts_withheld,omitempty"`
	Buffered           int       `json:"buffered"`
	Dropped            uint64    `json:"dropped"`
	WriteFailures      uint64    `json:"write_failures"`
	LostInFailures     uint64    `json:"lost_in_failures"`
	LastError          string    `json:"last_error,omitempty"`
	LastWrite          time.Time `json:"last_write"`
	DurabilityWindowMS int       `json:"durability_window_ms"`
	Retention          Retention `json:"retention"`
	Oldest             string    `json:"oldest"`
	Newest             string    `json:"newest"`
}

type Log struct {
	db    *sql.DB
	owner *os.File
	id    string
	cause error // set when the log could not be opened

	generation, mode string
	recording        bool
	now              func() time.Time

	sendMu sync.RWMutex // guards closed vs. channel send; never held during I/O
	closed bool
	ch     chan Record
	done   chan struct{}

	mu            sync.Mutex
	dropped       uint64 // buffer overflow + oversized + closed sends
	gapReported   uint64 // dropped+lost already covered by a gap record
	writeFailures uint64
	lost          uint64
	lastErr       string
	lastWrite     time.Time
	failing       bool

	// Test seam: a failing write simulates storage failure without touching disk.
	failWrite func() error
}

// Unavailable returns a log that records nothing and reports why; enforcement
// continues unchanged.
func Unavailable(cause error) *Log {
	return &Log{cause: cause, now: time.Now}
}

// Open creates or opens the private decision database (schema v1). The parent
// directory must already be validated by the caller. It holds an exclusive
// advisory lock on the database inode like the rule store.
func Open(path, generation, mode string, recording bool) (*Log, error) {
	if st, err := os.Lstat(path); err == nil && (!st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() > maxFileSize) {
		return nil, fmt.Errorf("decision log must be a private regular file below %d MiB", maxFileSize>>20)
	}
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	owner := os.NewFile(uintptr(fd), path)
	if err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		owner.Close()
		return nil, fmt.Errorf("another daemon owns this decision log: %w", err)
	}
	db, err := sql.Open("sqlite3", "file:"+url.PathEscape(path)+"?_busy_timeout=2000&_synchronous=FULL")
	if err != nil {
		owner.Close()
		return nil, err
	}
	db.SetMaxOpenConns(1)
	fail := func(e error) (*Log, error) { db.Close(); owner.Close(); return nil, e }
	if err = migrate(db); err != nil {
		return fail(err)
	}
	var check string
	if err = db.QueryRow("PRAGMA quick_check").Scan(&check); err != nil || check != "ok" {
		return fail(fmt.Errorf("decision log integrity failure: %s: %v", check, err))
	}
	l := &Log{db: db, owner: owner, generation: generation, mode: mode, recording: recording, now: time.Now, ch: make(chan Record, BufferSize), done: make(chan struct{})}
	if err = db.QueryRow("SELECT value FROM meta WHERE key='log_id'").Scan(&l.id); err != nil {
		return fail(err)
	}
	go l.run()
	return l, nil
}

// migrate: version 0 (new empty file) -> 1. Unknown versions refuse; a
// nonempty unversioned file is never adopted.
func migrate(db *sql.DB) error {
	var version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	switch version {
	case 1:
		return nil
	case 0:
	default:
		return fmt.Errorf("unsupported decision log version %d", version)
	}
	var n int
	if err := db.QueryRow("SELECT count(*) FROM sqlite_master").Scan(&n); err != nil {
		return err
	}
	if n != 0 {
		return fmt.Errorf("unversioned nonempty decision log")
	}
	id := newID()
	_, err := db.Exec(`BEGIN;
CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE decisions(
 seq INTEGER PRIMARY KEY AUTOINCREMENT,
 id TEXT NOT NULL UNIQUE CHECK(length(id)<=64),
 at INTEGER NOT NULL,
 kind TEXT NOT NULL,
 owner_uid INTEGER,
 direction TEXT,
 action TEXT,
 source TEXT,
 application TEXT,
 document TEXT NOT NULL CHECK(length(document)<=8192));
CREATE INDEX decisions_at ON decisions(at);
CREATE INDEX decisions_owner ON decisions(owner_uid, seq);
INSERT INTO meta VALUES('log_id','` + id + `'),('removed','0'),('removed_through','0');
PRAGMA user_version=1;
COMMIT;`)
	return err
}

func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}
func uitoa(v uint64) string { return strconv.FormatUint(v, 10) }

// NewRecordID is exported so callers can link pending/final records.
func NewRecordID() string { return newID() }

// Record enqueues without blocking. Overflow, oversize and use after Close are
// counted and later reported by a gap record; firewall behavior never changes.
func (l *Log) Record(r Record) {
	if l == nil {
		return
	}
	if l.db == nil {
		l.count(1)
		return
	}
	l.sendMu.RLock()
	defer l.sendMu.RUnlock()
	if l.closed {
		l.count(1)
		return
	}
	select {
	case l.ch <- r:
	default:
		l.count(1)
	}
}
func (l *Log) count(n uint64) { l.mu.Lock(); l.dropped += n; l.mu.Unlock() }

// Close flushes buffered records (the durability window ends here) and releases
// the database lock.
func (l *Log) Close() error {
	if l == nil || l.db == nil {
		return nil
	}
	l.sendMu.Lock()
	if !l.closed {
		l.closed = true
		close(l.ch)
	}
	l.sendMu.Unlock()
	<-l.done
	err := l.db.Close()
	l.owner.Close()
	return err
}

func (l *Log) run() {
	defer close(l.done)
	ticker := time.NewTicker(FlushInterval)
	defer ticker.Stop()
	batch := make([]Record, 0, BatchSize)
	for {
		select {
		case r, ok := <-l.ch:
			if !ok {
				l.write(batch)
				return
			}
			batch = append(batch, r)
			if len(batch) >= BatchSize {
				l.write(batch)
				batch = batch[:0]
			}
		case <-ticker.C:
			l.write(batch)
			batch = batch[:0]
		}
	}
}

// write commits one batch plus a gap record for anything lost since the last
// gap, then prunes in bounded steps, all in one transaction.
func (l *Log) write(batch []Record) {
	l.mu.Lock()
	missing := l.dropped + l.lost - l.gapReported
	l.mu.Unlock()
	if len(batch) == 0 && missing == 0 {
		l.prune()
		return
	}
	docs := make([]Record, 0, len(batch)+1)
	if missing > 0 {
		n := missing
		docs = append(docs, Record{ID: newID(), Time: l.now(), Generation: l.generation, Mode: l.mode, Kind: KindGap, Gap: &Gap{Dropped: &n, Reason: "records lost to buffer overflow, oversize or storage failure; history is incomplete here"}})
	}
	rows := l.encode(append(docs, batch...))
	err := l.insert(rows)
	l.mu.Lock()
	defer l.mu.Unlock()
	if err != nil {
		l.writeFailures++
		l.lost += uint64(len(rows))
		if missing > 0 {
			l.lost-- // the unwritten gap record itself is not a lost decision
		}
		l.lastErr = err.Error()
		l.failing = true
		return
	}
	l.gapReported += missing
	l.failing = false
	l.lastWrite = l.now()
}

type row struct {
	r   Record
	doc string
}

// encode marshals outside the transaction; an oversized record is dropped and
// counted once, then reported by the next gap record.
func (l *Log) encode(docs []Record) []row {
	out := make([]row, 0, len(docs))
	for _, r := range docs {
		b, err := json.Marshal(r)
		if err == nil && len(b) > MaxDocument && r.Decision != nil {
			r.Decision.MatchingRules = nil
			b, err = json.Marshal(r)
		}
		if err != nil || len(b) > MaxDocument {
			l.count(1)
			continue
		}
		out = append(out, row{r, string(b)})
	}
	return out
}

func (l *Log) insert(rows []row) error {
	if l.failWrite != nil {
		if err := l.failWrite(); err != nil {
			return err
		}
	}
	tx, err := l.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, x := range rows {
		r := x.r
		var owner, direction, action, source, app any
		if r.PrincipalUID != nil {
			owner = int64(*r.PrincipalUID)
		}
		if r.Flow != nil {
			direction = r.Flow.Direction
		}
		if r.Decision != nil {
			action, source = r.Decision.Action, r.Decision.Source
		}
		if r.Application != nil {
			app = r.Application.Key
		}
		if _, err = tx.Exec("INSERT INTO decisions(id,at,kind,owner_uid,direction,action,source,application,document) VALUES(?,?,?,?,?,?,?,?,?)", r.ID, r.Time.UnixNano(), r.Kind, owner, direction, action, source, app, x.doc); err != nil {
			return err
		}
	}
	if err = pruneTx(tx, l.now()); err != nil {
		return err
	}
	return tx.Commit()
}

func (l *Log) prune() {
	tx, err := l.db.Begin()
	if err != nil {
		return
	}
	defer tx.Rollback()
	if pruneTx(tx, l.now()) == nil {
		tx.Commit()
	}
}

// pruneTx removes at most pruneStep records by age and pruneStep by count, and
// records how many were removed and the highest removed sequence.
func pruneTx(tx *sql.Tx, now time.Time) error {
	var removed int64
	var through sql.NullInt64
	cutoff := now.Add(-MaxAge).UnixNano()
	if err := tx.QueryRow("SELECT count(*), max(seq) FROM (SELECT seq FROM decisions WHERE at < ? ORDER BY seq LIMIT ?)", cutoff, pruneStep).Scan(&removed, &through); err != nil {
		return err
	}
	if removed > 0 {
		if _, err := tx.Exec("DELETE FROM decisions WHERE seq <= ? AND at < ?", through.Int64, cutoff); err != nil {
			return err
		}
	}
	var total int64
	if err := tx.QueryRow("SELECT count(*) FROM decisions").Scan(&total); err != nil {
		return err
	}
	if excess := total - MaxRecords; excess > 0 {
		if excess > pruneStep {
			excess = pruneStep
		}
		var n int64
		var upto sql.NullInt64
		if err := tx.QueryRow("SELECT count(*), max(seq) FROM (SELECT seq FROM decisions ORDER BY seq LIMIT ?)", excess).Scan(&n, &upto); err != nil {
			return err
		}
		if _, err := tx.Exec("DELETE FROM decisions WHERE seq <= ?", upto.Int64); err != nil {
			return err
		}
		removed += n
		if upto.Int64 > through.Int64 {
			through = upto
		}
	}
	if removed == 0 {
		return nil
	}
	if _, err := tx.Exec("UPDATE meta SET value=CAST(CAST(value AS INTEGER)+? AS TEXT) WHERE key='removed'", removed); err != nil {
		return err
	}
	_, err := tx.Exec("UPDATE meta SET value=CAST(max(CAST(value AS INTEGER),?) AS TEXT) WHERE key='removed_through'", through.Int64)
	return err
}

// Health reports recording state. Ordinary peers get state only: machine-wide
// loss counts are withheld like UDP miss telemetry.
func (l *Log) Health(admin bool) Health {
	h := Health{DurabilityWindowMS: int(FlushInterval / time.Millisecond), Retention: Retention{MaxRecords: MaxRecords, MaxAgeDays: int(MaxAge / (24 * time.Hour))}}
	if l == nil {
		h.State = "unavailable"
		return h
	}
	if l.db == nil {
		h.State, h.LastError = "unavailable", fmt.Sprint(l.cause)
		h.Recording = false
		l.mu.Lock()
		h.Dropped = l.dropped
		l.mu.Unlock()
		return withhold(h, admin)
	}
	h.LogID, h.Recording, h.Buffered = l.id, l.recording, len(l.ch)
	l.mu.Lock()
	h.Dropped, h.WriteFailures, h.LostInFailures, h.LastError, h.LastWrite = l.dropped, l.writeFailures, l.lost, l.lastErr, l.lastWrite
	failing := l.failing
	l.mu.Unlock()
	h.State = "ok"
	if failing || h.Dropped > 0 || h.WriteFailures > 0 {
		h.State = "degraded"
	}
	var oldest, newest sql.NullInt64
	var removed, through string
	if err := l.db.QueryRow("SELECT min(seq), max(seq), (SELECT value FROM meta WHERE key='removed'), (SELECT value FROM meta WHERE key='removed_through') FROM decisions").Scan(&oldest, &newest, &removed, &through); err == nil {
		if oldest.Valid {
			h.Oldest, h.Newest = uitoa(uint64(oldest.Int64)), uitoa(uint64(newest.Int64))
		}
		h.Retention.Removed, _ = strconv.ParseUint(removed, 10, 64)
		if through != "0" {
			h.Retention.RemovedThrough = through
		}
	} else {
		h.State, h.LastError = "degraded", err.Error()
	}
	return withhold(h, admin)
}
func withhold(h Health, admin bool) Health {
	if !admin {
		h.CountsWithheld = true
		h.Buffered, h.Dropped, h.WriteFailures, h.LostInFailures, h.LastError = 0, 0, 0, 0, ""
	}
	return h
}

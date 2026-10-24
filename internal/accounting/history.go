// Durable history stores sampled checkpoint deltas, never permission authority.
package accounting

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	sqlite3 "github.com/mattn/go-sqlite3"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const HistoryCapability = "usage-history-v1"
const HistoryMaxRows = 50000
const HistoryMaxEpochs = 128
const HistoryMaxBytes = 32 << 20        // database alone
const HistoryJournalMaxBytes = 34 << 20 // rollback pages plus bounded headers
const HistoryBucketSeconds = 300
const HistoryCheckpointInterval = 30 * time.Second

var ErrHistoryCapacity = errors.New("history capacity reached; recording paused until retention frees space")

type HistorySettings struct {
	Enabled       bool   `json:"enabled"`
	RetentionDays int    `json:"retention_days"`
	Revision      string `json:"revision"`
}
type HistoryOptions struct {
	Enabled          *bool  `json:"enabled"`
	RetentionDays    int    `json:"retention_days"`
	ExpectedRevision string `json:"expected_revision"`
}
type HistoryQuery struct {
	Range        string `json:"range"`
	Source       string `json:"source"`
	EntryID      string `json:"entry_id,omitempty"`
	Unattributed bool   `json:"unattributed,omitempty"`
}
type HistoryPoint struct {
	At              time.Time `json:"at"`
	Uploaded        string    `json:"uploaded"`
	Downloaded      string    `json:"downloaded"`
	ObservedBuckets int       `json:"observed_buckets"`
	EpochCount      int       `json:"epoch_count"`
	Flags           int       `json:"flags"`
	Partial         bool      `json:"partial"`
}
type HistoryEpoch struct {
	Epoch            string    `json:"epoch"`
	DaemonGeneration string    `json:"daemon_generation"`
	StartedAt        time.Time `json:"started_at"`
}
type HistorySnapshot struct {
	Version           int             `json:"version"`
	Scope             string          `json:"scope"`
	Partial           bool            `json:"partial"`
	State             string          `json:"state"`
	Settings          HistorySettings `json:"settings"`
	Source            string          `json:"source"`
	From              time.Time       `json:"from"`
	Until             time.Time       `json:"until"`
	ResolutionSeconds int             `json:"resolution_seconds"`
	Entries           []Entry         `json:"entries"`
	Points            []HistoryPoint  `json:"points"`
	Epochs            []HistoryEpoch  `json:"epochs"`
	LastCommitAt      *time.Time      `json:"last_commit_at,omitempty"`
	Error             string          `json:"error,omitempty"`
}
type historyPair struct {
	Up   uint64 `json:"up"`
	Down uint64 `json:"down"`
}
type historyCheckpoint struct {
	Epoch    string                 `json:"epoch"`
	Sequence uint64                 `json:"sequence"`
	At       time.Time              `json:"at"`
	Counts   map[string]historyPair `json:"counts"`
}
type History struct {
	mu                sync.Mutex
	db                *sql.DB
	owner             *os.File
	ledger            *Ledger
	epoch, generation string
	settings          HistorySettings
	lastCommit        time.Time
	lastErr           error
	limited           bool
	baselineReady     bool
	cancel            context.CancelFunc
	done              chan struct{}
	now               func() time.Time
}

func validDays(days int) bool { return days == 1 || days == 7 || days == 30 }
func historyDecimal(s string) (uint64, error) {
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil || strconv.FormatUint(v, 10) != s {
		return 0, fmt.Errorf("invalid history counter")
	}
	return v, nil
}
func historyID(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// OpenHistory requires an existing private directory; it never alters rules or
// restores live socket baselines. Its writer is independent of API polling.
func OpenHistory(path string, ledger *Ledger, generation string) (*History, error) {
	return openHistory(path, ledger, generation, true)
}
func openHistory(path string, ledger *Ledger, generation string, run bool) (*History, error) {
	if ledger == nil || len(generation) == 0 || len(generation) > 128 {
		return nil, fmt.Errorf("history needs a ledger generation")
	}
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("absolute history path required")
	}
	for d := filepath.Dir(path); ; d = filepath.Dir(d) {
		v, er := os.Lstat(d)
		if er != nil || !v.IsDir() || v.Mode().Perm()&0022 != 0 {
			return nil, fmt.Errorf("history directory ancestry is not secure")
		}
		uid := v.Sys().(*syscall.Stat_t).Uid
		if uid != 0 && uid != uint32(os.Geteuid()) {
			return nil, fmt.Errorf("history directory ancestry is not owned")
		}
		if filepath.Dir(d) == d {
			break
		}
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || parent.Mode().Perm() != 0700 || parent.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return nil, fmt.Errorf("history requires an owned private directory")
	}
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	owner := os.NewFile(uintptr(fd), path)
	failOwner := func(e error) (*History, error) { owner.Close(); return nil, e }
	st, err := owner.Stat()
	if err != nil {
		return failOwner(err)
	}
	raw := st.Sys().(*syscall.Stat_t)
	if !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || raw.Uid != uint32(os.Geteuid()) || raw.Nlink != 1 || st.Size() > HistoryMaxBytes {
		return failOwner(fmt.Errorf("history must be an owned private single-link file below 32 MiB"))
	}
	if err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return failOwner(fmt.Errorf("history already has a writer: %w", err))
	}
	for _, suffix := range []string{"-journal", "-wal", "-shm"} {
		v, er := os.Lstat(path + suffix)
		if os.IsNotExist(er) {
			continue
		}
		if er != nil {
			return failOwner(er)
		}
		if suffix != "-journal" {
			return failOwner(fmt.Errorf("unexpected history WAL sidecar; data left unchanged"))
		}
		stat := v.Sys().(*syscall.Stat_t)
		if !v.Mode().IsRegular() || v.Mode().Perm()&0077 != 0 || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 || v.Size() > HistoryJournalMaxBytes {
			return failOwner(fmt.Errorf("history rollback journal is unsafe or oversized"))
		}
	}
	db, err := sql.Open("sqlite3", "file:"+url.PathEscape(path)+"?_busy_timeout=100&_synchronous=FULL&_foreign_keys=on")
	if err != nil {
		return failOwner(err)
	}
	db.SetMaxOpenConns(1)
	fail := func(e error) (*History, error) { db.Close(); owner.Close(); return nil, e }
	var version int
	if err = db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return fail(err)
	}
	if version != 0 && version != 1 {
		return fail(fmt.Errorf("unsupported usage history schema"))
	}
	var mode string
	if err = db.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil || mode != "delete" {
		return fail(fmt.Errorf("history requires DELETE journal mode"))
	}
	if version == 0 {
		var count int
		if err = db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table'").Scan(&count); err != nil || count != 0 {
			return fail(fmt.Errorf("unversioned nonempty history"))
		}
		_, err = db.Exec(`PRAGMA page_size=4096; BEGIN;
CREATE TABLE settings(id INTEGER PRIMARY KEY CHECK(id=1),enabled INTEGER NOT NULL,days INTEGER NOT NULL,revision TEXT NOT NULL);
INSERT INTO settings VALUES(1,0,7,'1');
CREATE TABLE epochs(epoch TEXT PRIMARY KEY,generation TEXT NOT NULL,started TEXT NOT NULL);
CREATE TABLE entries(id TEXT PRIMARY KEY,uid INTEGER NOT NULL,source TEXT NOT NULL,document TEXT NOT NULL CHECK(length(document)<=2048));
CREATE TABLE buckets(at INTEGER NOT NULL,epoch TEXT NOT NULL REFERENCES epochs(epoch),id TEXT NOT NULL REFERENCES entries(id),up TEXT NOT NULL,down TEXT NOT NULL,flags INTEGER NOT NULL,PRIMARY KEY(at,epoch,id));
CREATE INDEX buckets_time ON buckets(at);
CREATE INDEX buckets_identity ON buckets(id);
CREATE INDEX buckets_epoch ON buckets(epoch);
CREATE TABLE checkpoint(id INTEGER PRIMARY KEY CHECK(id=1),document TEXT NOT NULL CHECK(length(document)<=2097152));
PRAGMA user_version=1; COMMIT;`)
		if err != nil {
			return fail(err)
		}
	}
	var pageSize, maxPages int
	var check string
	if err = db.QueryRow("PRAGMA page_size").Scan(&pageSize); err != nil || pageSize != 4096 {
		return fail(fmt.Errorf("unsupported history page size"))
	}
	if err = db.QueryRow("PRAGMA max_page_count=8192").Scan(&maxPages); err != nil || maxPages > 8192 {
		return fail(fmt.Errorf("history exceeds page capacity"))
	}
	if _, err = db.Exec("PRAGMA journal_size_limit=0; PRAGMA temp_store=MEMORY; PRAGMA cache_size=-2048"); err != nil {
		return fail(err)
	}
	if err = db.QueryRow("PRAGMA quick_check").Scan(&check); err != nil || check != "ok" {
		return fail(fmt.Errorf("history integrity failure"))
	}
	// Verify the SQLite connection still points to the inode we locked.
	current, err := os.Lstat(path)
	if err != nil || !os.SameFile(st, current) {
		return fail(fmt.Errorf("history inode changed"))
	}
	h := &History{db: db, owner: owner, ledger: ledger, epoch: ledger.Snapshot(0, true).Epoch, generation: generation, now: time.Now, done: make(chan struct{})}
	var enabled int
	if err = db.QueryRow("SELECT enabled,days,revision FROM settings WHERE id=1").Scan(&enabled, &h.settings.RetentionDays, &h.settings.Revision); err != nil {
		return fail(err)
	}
	if (enabled != 0 && enabled != 1) || !validDays(h.settings.RetentionDays) {
		return fail(fmt.Errorf("invalid history settings"))
	}
	if _, err = historyDecimal(h.settings.Revision); err != nil {
		return fail(err)
	}
	h.settings.Enabled = enabled == 1
	// A new ledger incarnation is always a fresh baseline, never restored counters.
	if _, err = db.Exec("DELETE FROM checkpoint"); err != nil {
		return fail(err)
	}
	// The first periodic checkpoint after open establishes the baseline; no backfill.
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	if run {
		go h.loop(ctx)
	} else {
		close(h.done)
	}
	return h, nil
}
func (h *History) Close() error {
	if h == nil || h.db == nil {
		return nil
	}
	h.cancel()
	<-h.done
	h.mu.Lock()
	defer h.mu.Unlock()
	err := h.db.Close()
	h.owner.Close()
	return err
}
func (h *History) loop(ctx context.Context) {
	defer close(h.done)
	t := time.NewTicker(HistoryCheckpointInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			h.record(h.ledger.Snapshot(0, true))
			return
		case <-t.C:
			h.record(h.ledger.Snapshot(0, true))
		}
	}
}
func historyCounts(s Snapshot) (map[string]historyPair, error) {
	if len(s.Entries) > MaxEntries || len(s.Unattributed) > 2 {
		return nil, fmt.Errorf("history checkpoint cardinality exceeded")
	}
	out := make(map[string]historyPair, len(s.Entries)+2)
	for _, e := range s.Entries {
		if !historyID(e.ID) || e.Partial != true || e.Application.Key == "" || e.Application.Revision == "" || len(e.Application.Key) > 256 || len(e.Application.Revision) > 256 || len(e.Application.Kind) > 256 || (e.Source != TCP && e.Source != UDP) {
			return nil, fmt.Errorf("invalid historical identity")
		}
		doc, _ := json.Marshal(e.Application)
		if len(doc) > 1024 {
			return nil, fmt.Errorf("history metadata too large")
		}
		if _, ok := out[e.ID]; ok {
			return nil, fmt.Errorf("duplicate historical identity")
		}
		u, err := historyDecimal(e.Uploaded)
		if err != nil {
			return nil, err
		}
		d, err := historyDecimal(e.Downloaded)
		if err != nil {
			return nil, err
		}
		out[e.ID] = historyPair{u, d}
	}
	for _, e := range s.Unattributed {
		if e.Source != TCP && e.Source != UDP {
			return nil, fmt.Errorf("invalid historical source")
		}
		id := "unattributed:" + e.Source
		if _, ok := out[id]; ok {
			return nil, fmt.Errorf("duplicate historical source")
		}
		u, err := historyDecimal(e.Uploaded)
		if err != nil {
			return nil, err
		}
		d, err := historyDecimal(e.Downloaded)
		if err != nil {
			return nil, err
		}
		out[id] = historyPair{u, d}
	}
	return out, nil
}
func checkpointFor(s Snapshot) (historyCheckpoint, error) {
	counts, err := historyCounts(s)
	if err != nil {
		return historyCheckpoint{}, err
	}
	seq, err := historyDecimal(s.Sequence)
	if err != nil {
		return historyCheckpoint{}, err
	}
	at := s.StartedAt
	if s.SampledAt != nil {
		at = *s.SampledAt
	}
	return historyCheckpoint{s.Epoch, seq, at, counts}, nil
}
func writeCheckpoint(tx *sql.Tx, c historyCheckpoint) error {
	b, err := json.Marshal(c)
	if err != nil || len(b) > 2<<20 {
		return fmt.Errorf("history checkpoint too large")
	}
	_, err = tx.Exec("INSERT OR REPLACE INTO checkpoint VALUES(1,?)", string(b))
	return err
}
func (h *History) baselineLocked(s Snapshot) error {
	c, err := checkpointFor(s)
	if err != nil {
		return err
	}
	tx, err := h.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = writeCheckpoint(tx, c); err != nil {
		return err
	}
	return tx.Commit()
}
func pruneHistory(tx *sql.Tx, cutoff int64) error {
	_, err := tx.Exec("DELETE FROM buckets WHERE at<?", cutoff)
	if err != nil {
		return err
	}
	_, err = tx.Exec("DELETE FROM entries WHERE NOT EXISTS(SELECT 1 FROM buckets WHERE buckets.id=entries.id)")
	if err != nil {
		return err
	}
	_, err = tx.Exec("DELETE FROM epochs WHERE NOT EXISTS(SELECT 1 FROM buckets WHERE buckets.epoch=epochs.epoch)")
	return err
}
func (h *History) Configure(o HistoryOptions) (HistorySettings, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.db == nil {
		return h.settings, fmt.Errorf("usage history unavailable")
	}
	if o.Enabled == nil || !validDays(o.RetentionDays) || o.ExpectedRevision != h.settings.Revision {
		return h.settings, fmt.Errorf("history settings changed or invalid; refresh before saving")
	}
	rev, err := historyDecimal(h.settings.Revision)
	if err != nil || rev == ^uint64(0) {
		return h.settings, fmt.Errorf("history settings revision exhausted")
	}
	next := HistorySettings{*o.Enabled, o.RetentionDays, decimal(rev + 1)}
	tx, err := h.db.Begin()
	if err != nil {
		return h.settings, err
	}
	defer tx.Rollback()
	if !h.settings.Enabled || !next.Enabled {
		if _, err = tx.Exec("DELETE FROM checkpoint"); err != nil {
			return h.settings, err
		}
	}
	if err = pruneHistory(tx, h.now().UTC().Add(-time.Duration(next.RetentionDays)*24*time.Hour).Unix()); err != nil {
		return h.settings, err
	}
	if _, err = tx.Exec("UPDATE settings SET enabled=?,days=?,revision=? WHERE id=1", next.Enabled, next.RetentionDays, next.Revision); err != nil {
		return h.settings, err
	}
	if err = tx.Commit(); err != nil {
		return h.settings, err
	}
	if !h.settings.Enabled || !next.Enabled {
		h.baselineReady = false
	}
	h.settings = next
	h.lastErr = nil
	h.limited = false
	return next, nil
}
func (h *History) record(s Snapshot) {
	h.mu.Lock()
	defer h.mu.Unlock()
	err := h.recordLocked(s)
	var sqliteErr sqlite3.Error
	if errors.As(err, &sqliteErr) && sqliteErr.Code == sqlite3.ErrFull {
		err = ErrHistoryCapacity
	}
	h.lastErr = err
	h.limited = errors.Is(err, ErrHistoryCapacity)
}
func (h *History) recordLocked(s Snapshot) error {
	if s.Epoch != h.epoch {
		return fmt.Errorf("history refuses another ledger incarnation")
	}
	c, err := checkpointFor(s)
	if err != nil {
		return err
	}
	tx, err := h.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = pruneHistory(tx, h.now().UTC().Add(-time.Duration(h.settings.RetentionDays)*24*time.Hour).Unix()); err != nil {
		return err
	}
	if !h.settings.Enabled {
		return tx.Commit()
	}
	var doc string
	err = tx.QueryRow("SELECT document FROM checkpoint WHERE id=1").Scan(&doc)
	if err == sql.ErrNoRows {
		if err = writeCheckpoint(tx, c); err != nil {
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
		h.baselineReady = true
		h.lastCommit = h.now().UTC()
		return nil
	}
	if err != nil {
		return err
	}
	if len(doc) > 2<<20 {
		return fmt.Errorf("oversize history checkpoint")
	}
	var old historyCheckpoint
	if err = json.Unmarshal([]byte(doc), &old); err != nil {
		return err
	}
	if old.Epoch != s.Epoch {
		return fmt.Errorf("history epoch mismatch")
	}
	if old.At.Before(h.now().UTC().Add(-time.Duration(h.settings.RetentionDays) * 24 * time.Hour)) {
		// Never resurrect expired observations from a delayed cumulative checkpoint.
		if err = writeCheckpoint(tx, c); err != nil {
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
		h.baselineReady = true
		h.lastCommit = h.now().UTC()
		return nil
	}
	if c.Sequence <= old.Sequence {
		return tx.Commit()
	}
	if !c.At.After(old.At) {
		return fmt.Errorf("history clock did not advance")
	}
	// Same-epoch cumulative regressions are refused without lowering the durable
	// watermark: a later rebound must not count previously committed bytes twice.
	for id, prev := range old.Counts {
		v, ok := c.Counts[id]
		if !ok || v.Up < prev.Up || v.Down < prev.Down {
			return fmt.Errorf("history cumulative counters regressed; checkpoint refused")
		}
	}

	if s.SampledAt == nil {
		return tx.Commit()
	}
	var rows, epochs, entries int
	if err = tx.QueryRow("SELECT count(*) FROM buckets").Scan(&rows); err != nil {
		return err
	}
	if err = tx.QueryRow("SELECT count(*) FROM epochs").Scan(&epochs); err != nil {
		return err
	}
	if err = tx.QueryRow("SELECT count(*) FROM entries WHERE uid>=0").Scan(&entries); err != nil {
		return err
	}
	var haveEpoch int
	if err = tx.QueryRow("SELECT count(*) FROM epochs WHERE epoch=?", s.Epoch).Scan(&haveEpoch); err != nil {
		return err
	}
	if haveEpoch == 0 {
		if epochs >= HistoryMaxEpochs {
			return ErrHistoryCapacity
		}
		if _, err = tx.Exec("INSERT INTO epochs VALUES(?,?,?)", s.Epoch, h.generation, s.StartedAt.UTC().Format(time.RFC3339Nano)); err != nil {
			return err
		}
	}
	catalog := make(map[string]Entry, len(s.Entries))
	for _, e := range s.Entries {
		catalog[e.ID] = e
	}
	at := c.At.UTC().Unix() / HistoryBucketSeconds * HistoryBucketSeconds
	for id, v := range c.Counts {
		prev := old.Counts[id]
		up, down := v.Up-prev.Up, v.Down-prev.Down
		if up == 0 && down == 0 {
			continue
		}
		var entry Entry
		uid := int64(-1)
		source := strings.TrimPrefix(id, "unattributed:")
		if e, ok := catalog[id]; ok {
			entry = e
			uid = int64(e.UID)
			source = e.Source
		}
		var exists int
		if err = tx.QueryRow("SELECT count(*) FROM entries WHERE id=?", id).Scan(&exists); err != nil {
			return err
		}
		if exists != 0 {
			var storedUID int64
			var storedSource, storedDoc string
			if err = tx.QueryRow("SELECT uid,source,document FROM entries WHERE id=?", id).Scan(&storedUID, &storedSource, &storedDoc); err != nil {
				return err
			}
			if storedUID != uid || storedSource != source {
				return fmt.Errorf("historical identity collision")
			}
			if uid >= 0 {
				var prior Entry
				if err = json.Unmarshal([]byte(storedDoc), &prior); err != nil {
					return err
				}
				if prior.Application.Key != entry.Application.Key || prior.Application.Revision != entry.Application.Revision || prior.Application.Kind != entry.Application.Kind {
					return fmt.Errorf("historical identity metadata changed")
				}
			}
		}
		if exists == 0 {
			if uid >= 0 && entries >= MaxEntries {
				return ErrHistoryCapacity
			}
			metadata, _ := json.Marshal(entry)
			if len(metadata) > 2048 {
				return fmt.Errorf("history entry too large")
			}
			if _, err = tx.Exec("INSERT INTO entries VALUES(?,?,?,?)", id, uid, source, string(metadata)); err != nil {
				return err
			}
			if uid >= 0 {
				entries++
			}
		}
		flags := 0
		if s.CapacityLimited {
			flags |= 2
		}
		if s.Saturated {
			flags |= 4
		}
		for _, v := range s.Sources {
			if v.Source == source && v.State != "active" {
				flags |= 1
			}
		}
		var previousUp, previousDown string
		var previousFlags int
		err = tx.QueryRow("SELECT up,down,flags FROM buckets WHERE at=? AND epoch=? AND id=?", at, s.Epoch, id).Scan(&previousUp, &previousDown, &previousFlags)
		if err == sql.ErrNoRows {
			if rows >= HistoryMaxRows {
				return ErrHistoryCapacity
			}
			rows++
		} else if err != nil {
			return err
		} else {
			a, er := historyDecimal(previousUp)
			if er != nil {
				return er
			}
			b, er := historyDecimal(previousDown)
			if er != nil {
				return er
			}
			var sat1, sat2 bool
			up, sat1 = add(up, a)
			down, sat2 = add(down, b)
			flags |= previousFlags
			if sat1 || sat2 {
				flags |= 4
			}
		}
		if _, err = tx.Exec("INSERT OR REPLACE INTO buckets VALUES(?,?,?,?,?,?)", at, s.Epoch, id, decimal(up), decimal(down), flags); err != nil {
			if strings.Contains(err.Error(), "database or disk is full") {
				return ErrHistoryCapacity
			}
			return err
		}
	}
	if err = writeCheckpoint(tx, c); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	h.lastCommit = h.now().UTC()
	return nil
}

func historyRange(r string) (time.Duration, int, error) {
	switch r {
	case "1h":
		return time.Hour, 300, nil
	case "24h":
		return 24 * time.Hour, 300, nil
	case "7d":
		return 7 * 24 * time.Hour, 1800, nil
	case "30d":
		return 30 * 24 * time.Hour, 7200, nil
	}
	return 0, 0, fmt.Errorf("history range must be 1h,24h,7d,30d")
}

// Query projects before aggregation. No client-selected UID or process identity
// can broaden the authenticated principal, including for ended applications.
func (h *History) Query(q HistoryQuery, uid uint32, admin bool) (HistorySnapshot, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.now().UTC()
	duration, res, err := historyRange(q.Range)
	if err != nil {
		return HistorySnapshot{}, err
	}
	if q.Source != TCP && q.Source != UDP {
		return HistorySnapshot{}, fmt.Errorf("one explicit history source required")
	}
	if q.EntryID != "" && !historyID(q.EntryID) {
		return HistorySnapshot{}, fmt.Errorf("invalid history entry")
	}
	if q.Unattributed && (!admin || q.EntryID != "") {
		return HistorySnapshot{}, fmt.Errorf("unattributed history requires administrator and separate series")
	}
	from := now.Add(-duration)
	cutoff := now.Add(-time.Duration(h.settings.RetentionDays) * 24 * time.Hour)
	if cutoff.After(from) {
		from = cutoff
	}
	// Query never reveals a bucket older than the effective retention cutoff.
	out := HistorySnapshot{Version: 1, Scope: "user", Partial: true, State: "disabled", Settings: h.settings, Source: q.Source, From: from, Until: now, ResolutionSeconds: res, Entries: []Entry{}, Points: []HistoryPoint{}, Epochs: []HistoryEpoch{}}
	if h.settings.Enabled {
		out.State = "recording"
		if !h.baselineReady {
			out.State = "starting"
		}
	}
	if h.lastErr != nil {
		out.State = "unavailable"
		if admin {
			out.Error = h.lastErr.Error()
		}
	}
	if h.limited {
		out.State = "capacity_limited"
	}
	if admin {
		out.Scope = "machine"
		if !h.lastCommit.IsZero() {
			t := h.lastCommit
			out.LastCommitAt = &t
		}
	}
	if h.db == nil {
		return out, nil
	}
	where := "b.at>=? AND b.at<=? AND e.source=?"
	args := []any{from.Unix(), now.Unix(), q.Source}
	if q.Unattributed {
		where += " AND e.uid=-1"
	} else {
		where += " AND e.uid>=0"
		if !admin {
			where += " AND e.uid=?"
			args = append(args, uid)
		}
	}
	// Catalog totals cover the range/source; the selected entry filters only the
	// graph, so its application selector does not lose the other recorded entries.
	rows, err := h.db.Query(`SELECT b.at,b.epoch,e.id,e.uid,e.document,b.up,b.down,b.flags,p.generation,p.started FROM buckets b JOIN entries e ON e.id=b.id JOIN epochs p ON p.epoch=b.epoch WHERE `+where+` ORDER BY b.at,e.id LIMIT 50001`, args...)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	type point struct {
		up, down uint64
		flags    int
		buckets  map[int64]bool
		epochs   map[string]bool
	}
	points := map[int64]*point{}
	entries := map[string]Entry{}
	totals := map[string]historyPair{}
	epochs := map[string]HistoryEpoch{}
	count := 0
	for rows.Next() {
		count++
		if count > HistoryMaxRows {
			return out, fmt.Errorf("history row bound exceeded")
		}
		var at int64
		var epoch, id, doc, upText, downText, generation, started string
		var rowUID int64
		var flags int
		if err = rows.Scan(&at, &epoch, &id, &rowUID, &doc, &upText, &downText, &flags, &generation, &started); err != nil {
			return out, err
		}
		if len(doc) > 2048 || !historyID(epoch+epoch) || len(generation) > 128 || flags < 0 || flags > 7 || at%HistoryBucketSeconds != 0 {
			return out, fmt.Errorf("invalid historical row metadata")
		}
		up, er := historyDecimal(upText)
		if er != nil {
			return out, er
		}
		down, er := historyDecimal(downText)
		if er != nil {
			return out, er
		}
		var e Entry
		if er = json.Unmarshal([]byte(doc), &e); er != nil {
			return out, er
		}
		if rowUID >= 0 {
			if rowUID > int64(^uint32(0)) || e.ID != id || e.UID != uint32(rowUID) || e.Source != q.Source || !e.Partial || !historyID(id) {
				return out, fmt.Errorf("historical identity mismatch")
			}
			entries[id] = e
			p := totals[id]
			var a, b bool
			p.Up, a = add(p.Up, up)
			p.Down, b = add(p.Down, down)
			totals[id] = p
			if a || b {
				flags |= 4
			}
		}
		if q.EntryID != "" && id != q.EntryID {
			continue
		}
		bucket := at / int64(res) * int64(res)
		p := points[bucket]
		if p == nil {
			p = &point{buckets: map[int64]bool{}, epochs: map[string]bool{}}
			points[bucket] = p
		}
		var a, b bool
		p.up, a = add(p.up, up)
		p.down, b = add(p.down, down)
		p.flags |= flags
		if a || b {
			p.flags |= 4
		}
		p.buckets[at] = true
		p.epochs[epoch] = true
		start, er := time.Parse(time.RFC3339Nano, started)
		if er != nil {
			return out, er
		}
		epochs[epoch] = HistoryEpoch{epoch, generation, start}
	}
	if err = rows.Err(); err != nil {
		return out, err
	}
	if len(entries) > MaxEntries || len(points) > 512 || len(epochs) > HistoryMaxEpochs {
		return out, fmt.Errorf("history query bound exceeded")
	}
	for id, e := range entries {
		p := totals[id]
		e.Uploaded = decimal(p.Up)
		e.Downloaded = decimal(p.Down)
		out.Entries = append(out.Entries, e)
	}
	sort.Slice(out.Entries, func(i, j int) bool { return out.Entries[i].ID < out.Entries[j].ID })
	for at, p := range points {
		out.Points = append(out.Points, HistoryPoint{time.Unix(at, 0).UTC(), decimal(p.up), decimal(p.down), len(p.buckets), len(p.epochs), p.flags, true})
	}
	sort.Slice(out.Points, func(i, j int) bool { return out.Points[i].At.Before(out.Points[j].At) })
	for _, e := range epochs {
		out.Epochs = append(out.Epochs, e)
	}
	sort.Slice(out.Epochs, func(i, j int) bool { return out.Epochs[i].Epoch < out.Epochs[j].Epoch })
	return out, nil
}

// An unavailable history store is diagnostic-only; protection and the live
// observation ledger remain independent, with no silent reset or new file path.
func UnavailableHistory(cause error) *History {
	return &History{settings: HistorySettings{false, 7, "0"}, lastErr: cause, now: time.Now}
}

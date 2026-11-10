package serveprofile

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"
)

func awaitRecord(t *testing.T, r *Recorder, id string) CaptureStatus {
	t.Helper()
	until := time.Now().Add(5 * time.Second)
	for time.Now().Before(until) {
		s := r.Status()
		for _, v := range s.Recent {
			if v.ID == id {
				return v
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("capture did not complete")
	return CaptureStatus{}
}
func awaitRunning(t *testing.T, r *Recorder) {
	t.Helper()
	until := time.Now().Add(2 * time.Second)
	for time.Now().Before(until) {
		s := r.Status()
		if s.Active != nil && s.Active.State == "running" {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("capture did not start")
}
func TestRecorderLifecycleAndIsolatedCounters(t *testing.T) {
	r := NewRecorder(context.Background(), func() any { return map[string]string{"build": "test"} })
	defer r.Close()
	if active.Load() != nil || r.Status().Active != nil {
		t.Fatal("enabled at creation")
	}
	for _, n := range []int64{-1, 1, 4, 61, 1 << 62} {
		if _, err := r.Start(n); err == nil {
			t.Fatalf("accepted duration%d", n)
		}
	}
	ids := []string{}
	for i := 0; i < 3; i++ {
		s, err := r.start(40 * time.Millisecond)
		if err != nil {
			t.Fatal(err)
		}
		id := s.Active.ID
		ids = append(ids, id)
		if _, err = r.Start(5); err == nil {
			t.Fatal("overlapping start")
		}
		if _, err = r.Fetch(id, "cpu.pprof", 0); err == nil {
			t.Fatal("in-progress artifact exposed")
		}
		if _, err = r.Stop("other"); err == nil {
			t.Fatal("wrong ID stopped capture")
		}
		awaitRunning(t, r)
		Count(Parsed, uint64(i+1))
		v := awaitRecord(t, r, id)
		if v.State != "finished" || v.Error != "" || active.Load() != nil {
			t.Fatal(v)
		}
		c, err := r.Fetch(id, "summary.json", 0)
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Counters map[string]uint64 `json:"counters"`
		}
		if err = json.Unmarshal(c.Data, &doc); err != nil {
			t.Fatal(err)
		}
		if doc.Counters["parsed"] != uint64(i+1) {
			t.Fatal("counter leaked between captures", doc.Counters)
		}
		c, err = r.Fetch(id, "cpu.pprof", 0)
		if err != nil {
			t.Fatal(err)
		}
		z, err := gzip.NewReader(bytes.NewReader(c.Data))
		if err != nil {
			t.Fatal(err)
		}
		n, err := io.Copy(io.Discard, z)
		z.Close()
		if err != nil || n == 0 {
			t.Fatal(n, err)
		}
		// The previous ID cannot stop a newer capture; returned metadata is detached.
		v.Artifacts[0] = "corrupt"
		if r.Status().Recent[len(r.Status().Recent)-1].Artifacts[0] == "corrupt" {
			t.Fatal("status aliases storage")
		}
	}
	if len(r.Status().Recent) != 2 {
		t.Fatal(r.Status())
	}
	if _, err := r.Fetch(ids[0], "summary.json", 0); err == nil {
		t.Fatal("old capture retained")
	}
}
func TestRecorderCancellationAndGlobalExclusion(t *testing.T) {
	r := NewRecorder(context.Background(), nil)
	captureMu.Lock()
	if _, err := r.Start(5); err == nil {
		t.Fatal("legacy lock ignored")
	}
	captureMu.Unlock()
	s, err := r.Start(5)
	if err != nil {
		t.Fatal(err)
	}
	id := s.Active.ID
	awaitRunning(t, r)
	if captureMu.TryLock() {
		captureMu.Unlock()
		t.Fatal("legacy could overlap")
	}
	if _, err = r.Stop(id); err != nil {
		t.Fatal(err)
	}
	v := awaitRecord(t, r, id)
	if v.State != "canceled" {
		t.Fatal(v)
	}
	s, err = r.Start(5)
	if err != nil {
		t.Fatal(err)
	}
	awaitRunning(t, r)
	if _, err = r.Stop(id); err == nil {
		t.Fatal("old ID canceled new capture")
	}
	r.Close()
	if r.Status().Active != nil || active.Load() != nil {
		t.Fatal("shutdown left profiler active")
	}
	if _, err = r.Start(5); err == nil {
		t.Fatal("closed recorder restarted")
	}
	if !captureMu.TryLock() {
		t.Fatal("global lock leaked")
	}
	captureMu.Unlock()
}
func TestRecorderChunkBoundsAndDetachedBytes(t *testing.T) {
	data := bytes.Repeat([]byte("x"), ArtifactChunkLimit+7)
	h := sha256.Sum256(data)
	r := NewRecorder(context.Background(), nil)
	defer r.Close()
	r.recent = []*recording{{status: CaptureStatus{ID: "abc"}, artifacts: map[string][]byte{"cpu.pprof": data}, hashes: map[string]string{"cpu.pprof": hex.EncodeToString(h[:])}}}
	c, err := r.Fetch("abc", "cpu.pprof", 0)
	if err != nil || len(c.Data) != ArtifactChunkLimit || c.Total != int64(len(data)) {
		t.Fatal(c, err)
	}
	c.Data[0] = 'y'
	c2, _ := r.Fetch("abc", "cpu.pprof", 0)
	if c2.Data[0] != 'x' {
		t.Fatal("artifact alias")
	}
	tail, err := r.Fetch("abc", "cpu.pprof", ArtifactChunkLimit)
	if err != nil || len(tail.Data) != 7 || tail.SHA256 != c.SHA256 {
		t.Fatal(tail, err)
	}
	for _, n := range []int64{-1, int64(len(data) + 1), 1 << 62} {
		if _, err = r.Fetch("abc", "cpu.pprof", n); err == nil {
			t.Fatal("invalid offset")
		}
	}
	for _, name := range []string{"../cpu.pprof", "/etc/passwd", "mutex.pprof"} {
		if _, err = r.Fetch("abc", name, 0); err == nil {
			t.Fatal("invalid artifact")
		}
	}
}
func TestRecorderOversizedSummaryReportsFailure(t *testing.T) {
	r := NewRecorder(context.Background(), func() any { return strings.Repeat("x", summaryLimit) })
	defer r.Close()
	s, err := r.start(10 * time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	v := awaitRecord(t, r, s.Active.ID)
	if v.State != "failed" || !strings.Contains(v.Error, "summary incomplete") {
		t.Fatal(v)
	}
	c, err := r.Fetch(v.ID, "summary.json", 0)
	if err != nil || !json.Valid(c.Data) || len(c.Data) > 1024 {
		t.Fatal(err, len(c.Data))
	}
	if active.Load() != nil {
		t.Fatal("failed output left capture active")
	}
	if !captureMu.TryLock() {
		t.Fatal("failed output held lock")
	}
	captureMu.Unlock()
}
func TestWorkDisabledDoesNotArmProfiler(t *testing.T) {
	count := 0
	Work(context.Background(), "activity_collection", func() { count++ })
	if count != 1 || active.Load() != nil {
		t.Fatal("work label changes capture")
	}
}

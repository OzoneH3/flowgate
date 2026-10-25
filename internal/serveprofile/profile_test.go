package serveprofile

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func privateTemp(t *testing.T) string {
	t.Helper()
	p := t.TempDir()
	if err := os.Chmod(p, 0700); err != nil {
		t.Fatal(err)
	}
	return p
}
func TestPrivateDirectoryAndExclusiveFiles(t *testing.T) {
	dir := privateTemp(t)
	fd, err := privateDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer closeFD(fd)
	f, err := createAt(fd, "existing")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("retain")
	f.Close()
	if _, err = createAt(fd, "existing"); err == nil {
		t.Fatal("existing file overwritten")
	}
	if err = os.Symlink("existing", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err = createAt(fd, "link"); err == nil {
		t.Fatal("symlink accepted")
	}
	for _, path := range []string{dir + "/../" + filepath.Base(dir), "relative", filepath.Join(dir, "link")} {
		if got, e := privateDirectory(path); e == nil {
			closeFD(got)
			t.Fatalf("unsafe directory accepted %s", path)
		}
	}
	parent := privateTemp(t)
	if err = os.Symlink(dir, filepath.Join(parent, "alias")); err != nil {
		t.Fatal(err)
	}
	if got, e := privateDirectory(filepath.Join(parent, "alias")); e == nil {
		closeFD(got)
		t.Fatal("directory symlink accepted")
	}
	if err = os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if got, e := privateDirectory(dir); e == nil {
		closeFD(got)
		t.Fatal("public directory accepted")
	}
}
func TestCappedWriterNeverExceedsLimit(t *testing.T) {
	var b bytes.Buffer
	w := &cappedWriter{dst: &b, left: 5}
	if n, e := w.Write([]byte("1234")); n != 4 || e != nil {
		t.Fatal(n, e)
	}
	if _, e := w.Write([]byte("56")); e != errLimit {
		t.Fatal(e)
	}
	w.Write([]byte("7"))
	if b.String() != "1234" {
		t.Fatal(b.String())
	}
}
func TestFixedTimingStorageAndConcurrentCounters(t *testing.T) {
	if Begin(LinkQuery).session != nil {
		t.Fatal("default enabled")
	}
	now := time.Now()
	s := &session{from: now, until: now.Add(time.Minute)}
	active.Store(s)
	defer active.Store(nil)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				Count(Offered, 1)
				record(s, PolicyEvaluate, 3*time.Microsecond)
			}
		}()
	}
	wg.Wait()
	if s.counters[Offered].Load() != 16000 || s.stages[PolicyEvaluate].count.Load() != 16000 {
		t.Fatal("counter loss")
	}
	Since(QueueResidence, now.Add(-time.Second))
	if s.stages[QueueResidence].count.Load() != 0 {
		t.Fatal("included pre-window job")
	}
	span := Begin(LinkQuery)
	active.Store(nil)
	span.End()
	if s.stages[LinkQuery].count.Load() != 0 {
		t.Fatal("span crossed end")
	}
	if _, err := json.Marshal(snapshot(s)); err != nil {
		t.Fatal(err)
	}
}
func TestCaptureCanceledAndExistingOutputsAreSafe(t *testing.T) {
	dir := privateTemp(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e := capture(ctx, dir, time.Second, time.Second); e != context.Canceled {
		t.Fatal(e)
	}
	files, _ := os.ReadDir(dir)
	if len(files) != 0 {
		t.Fatal("canceled startup wrote files")
	}
	if e := os.WriteFile(filepath.Join(dir, "summary.json"), []byte("retain"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := capture(context.Background(), dir, 0, time.Second); e == nil {
		t.Fatal("existing output accepted")
	}
	b, _ := os.ReadFile(filepath.Join(dir, "summary.json"))
	if string(b) != "retain" {
		t.Fatal("existing output changed")
	}
	if _, e := os.Stat(filepath.Join(dir, "cpu.pprof")); !os.IsNotExist(e) {
		t.Fatal("partial setup left new file")
	}
}
func TestBoundedCaptureFinishesAndDisables(t *testing.T) {
	dir := privateTemp(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for ctx.Err() == nil {
			span := Begin(PolicyEvaluate)
			Count(Parsed, 1)
			for i := 0; i < 10000; i++ {
				time.Now()
			}
			span.End()
		}
	}()
	if e := capture(ctx, dir, 0, time.Second); e != nil {
		t.Fatal(e)
	}
	cancel()
	<-done
	if active.Load() != nil {
		t.Fatal("capture left active")
	}
	for _, name := range []string{"cpu.pprof", "mutex.pprof", "summary.json", "started.json"} {
		p := filepath.Join(dir, name)
		st, e := os.Stat(p)
		if e != nil {
			t.Fatal(e)
		}
		if st.Mode().Perm() != 0600 || st.Size() > profileLimit {
			t.Fatal(st)
		}
		if filepath.Ext(name) == ".pprof" {
			f, _ := os.Open(p)
			z, e := gzip.NewReader(f)
			if e != nil {
				t.Fatal(e)
			}
			n, e := io.Copy(io.Discard, io.LimitReader(z, 32<<20))
			z.Close()
			f.Close()
			if e != nil || n == 0 {
				t.Fatal(n, e)
			}
		}
	}
	b, _ := os.ReadFile(filepath.Join(dir, "summary.json"))
	var v map[string]any
	if e := json.Unmarshal(b, &v); e != nil {
		t.Fatal(e)
	}
	if v["canceled"] != false || len(v["errors"].([]any)) != 0 {
		t.Fatal(v)
	}
	if v["elapsed_seconds"].(float64) < 1 || v["elapsed_seconds"].(float64) > 3 {
		t.Fatal(v)
	}
}

func closeFD(fd int) { unix.Close(fd) }

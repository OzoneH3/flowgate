package identity

import (
	"errors"
	"flowgate/internal/fditer"
	"os"
	"testing"
	"time"
)

func TestUnavailableIteratorFallsBackWithoutPublishingRows(t *testing.T) {
	calls, visits := 0, 0
	p := holderProc{iterator: fditer.New(nil), now: time.Now, deadline: time.Now().Add(time.Second),
		fds: func(tgid, tid int, visit func(string, string) bool) error {
			calls++
			if tgid != 7 || tid != 9 {
				t.Fatal(tgid, tid)
			}
			visit("/proc/7/task/9/fd/3", "socket:[42]")
			return nil
		}}
	err := p.scanFDTable(7, 9, 1, func(path, target string) bool {
		visits++
		if target != "socket:[42]" {
			t.Fatal(target)
		}
		return true
	})
	if err != nil || calls != 1 || visits != 1 {
		t.Fatalf("err=%v calls=%d visits=%d", err, calls, visits)
	}
}

func TestIteratorFallbackDoesNotExtendExpiredCensus(t *testing.T) {
	p := holderProc{iterator: fditer.New(nil), now: time.Now, deadline: time.Now().Add(-time.Second),
		fds: func(int, int, func(string, string) bool) error { t.Fatal("expired census retried"); return nil }}
	if err := p.scanFDTable(7, 9, 1, func(string, string) bool { t.Fatal("published rows"); return true }); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal(err)
	}
}

package identity

import (
	"flowgate/internal/fditer"
	diagnostics "flowgate/internal/serveprofile"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

var holderIterator atomic.Pointer[fditer.Reader]
var holderIteratorReason atomic.Pointer[string]
var iteratorTableCount, iteratorFallbackCount, procTableCount atomic.Uint64

type HolderEnumerationStatus struct {
	Mechanism      string `json:"mechanism"`
	Reason         string `json:"reason,omitempty"`
	IteratorTables uint64 `json:"iterator_tables"`
	FallbackTables uint64 `json:"fallback_tables"`
	ProcTables     uint64 `json:"proc_tables"`
}

func HolderEnumeration() HolderEnumerationStatus {
	s := HolderEnumerationStatus{Mechanism: "proc", IteratorTables: iteratorTableCount.Load(), FallbackTables: iteratorFallbackCount.Load(), ProcTables: procTableCount.Load()}
	if holderIterator.Load() != nil {
		s.Mechanism = "task_file_iterator_with_proc_fallback"
	}
	if p := holderIteratorReason.Load(); p != nil {
		s.Reason = *p
	}
	return s
}

// EnableHolderIterator is an explicit startup capability probe. A failure
// leaves /proc selected. It never changes existing identity/permission rules.
func EnableHolderIterator(helper, expectedSHA256 string) (cleanup func(), result error) {
	defer func() {
		if result != nil {
			reason := result.Error()
			holderIteratorReason.Store(&reason)
		}
	}()
	// task_file TIDs use the reader's active PID namespace. Do not mix them
	// with descriptor paths from a /proc mount belonging to an ancestor.
	selfNS := link("/proc/self/ns/pid")
	if selfNS == "" || link("/proc/1/ns/pid") != selfNS {
		return nil, fmt.Errorf("iterator requires /proc for the current PID namespace")
	}
	r, err := fditer.Load(helper, expectedSHA256)
	if err != nil {
		return nil, err
	}
	if err = probeHolderIterator(r); err != nil {
		r.Close()
		return nil, err
	}
	if !holderIterator.CompareAndSwap(nil, r) {
		r.Close()
		return nil, fmt.Errorf("holder iterator already configured")
	}
	holderIteratorReason.Store(nil)
	return func() { holderIterator.CompareAndSwap(r, nil); r.Close() }, nil
}

func probeHolderIterator(r *fditer.Reader) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	tid := unix.Gettid()
	base := fmt.Sprintf("/proc/self/task/%d/fd", tid)
	before := map[uint32]string{}
	collect := func(path, target string) bool {
		if strings.HasPrefix(target, "socket:[") {
			n, e := strconv.ParseUint(path[strings.LastIndexByte(path, '/')+1:], 10, 32)
			if e == nil {
				before[uint32(n)] = target
			}
		}
		return true
	}
	if err = readFDTable(base, os.Readlink, collect); err != nil {
		return err
	}
	rows, err := r.Read(tid, fditer.MaxFDs, time.Now().Add(time.Second))
	if err != nil {
		return err
	}
	seen := 0
	for _, row := range rows {
		if row.Inode != 0 {
			seen++
			if before[row.FD] != fmt.Sprintf("socket:[%d]", row.Inode) {
				return fmt.Errorf("iterator startup socket mismatch")
			}
		}
	}
	if seen != len(before) || before[uint32(fd)] == "" {
		return fmt.Errorf("iterator startup socket coverage incomplete")
	}
	after := map[uint32]string{}
	before, after = after, before
	if err = readFDTable(base, os.Readlink, collect); err != nil {
		return err
	}
	if len(before) != len(after) {
		return fmt.Errorf("iterator startup socket set changed")
	}
	for fd, target := range after {
		if before[fd] != target {
			return fmt.Errorf("iterator startup socket changed")
		}
	}
	return nil
}

func (p holderProc) scanFDTable(tgid, tid, remaining int, visit func(string, string) bool) error {
	if p.iterator != nil {
		rows, err := p.iterator.Read(tid, min(max(remaining, 0), fditer.MaxFDs), p.deadline)
		if err == nil {
			iteratorTableCount.Add(1)
			diagnostics.Count(diagnostics.HolderIteratorTables, 1)
			for _, row := range rows {
				target := ""
				if row.Inode != 0 {
					target = fmt.Sprintf("socket:[%d]", row.Inode)
				}
				if !visit(fmt.Sprintf("/proc/%d/task/%d/fd/%d", tgid, tid, row.FD), target) {
					break
				}
			}
			return nil
		}
		diagnostics.Count(diagnostics.HolderIteratorFallback, 1)
		iteratorFallbackCount.Add(1)
		if p.late() {
			return os.ErrDeadlineExceeded
		}
	}
	diagnostics.Count(diagnostics.HolderProcTables, 1)
	procTableCount.Add(1)
	return p.fds(tgid, tid, visit)
}

// Package fditer enumerates fresh descriptor tables with a task_file iterator.
// It supplies observations only. The identity layer retains its task topology,
// generation, sharing, identity and descriptor rechecks. No result is cached.
package fditer

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const MaxFDs = 131072
const rowSize = 16

type Row struct {
	Inode uint64
	FD    uint32
}

// Reader owns the program FD. A close waits for bounded outstanding reads.
type Reader struct {
	mu      sync.RWMutex
	program *os.File
	slots   chan struct{}
	success atomic.Uint64
	failure atomic.Uint64
}

func (r *Reader) Stats() (success, failure uint64) { return r.success.Load(), r.failure.Load() }

func New(program *os.File) *Reader { return &Reader{program: program, slots: make(chan struct{}, 4)} }
func (r *Reader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.program == nil {
		return nil
	}
	err := r.program.Close()
	r.program = nil
	return err
}

func bpf(cmd int, attr unsafe.Pointer, size uintptr) (int, error) {
	fd, _, e := unix.Syscall(unix.SYS_BPF, uintptr(cmd), uintptr(attr), size)
	if e != 0 {
		return -1, e
	}
	return int(fd), nil
}

// Read returns a complete, validated stream or no rows at all. Callers may
// retry with /proc after any error, without double-counting partially read FDs.
// The explicit TID selects that task's table, including unshared CLONE_FILES.
func (r *Reader) Read(tid, limit int, deadline time.Time) (rows []Row, err error) {
	defer func() {
		if err == nil {
			r.success.Add(1)
		} else {
			r.failure.Add(1)
		}
	}()
	if tid <= 0 || limit < 0 || limit > MaxFDs || deadline.IsZero() {
		return nil, fmt.Errorf("invalid iterator bounds")
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.program == nil {
		return nil, os.ErrClosed
	}
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case r.slots <- struct{}{}:
		defer func() { <-r.slots }()
	case <-timer.C:
		return nil, os.ErrDeadlineExceeded
	}
	info := &[3]uint32{uint32(tid), 0, 0}
	// iter_info is an address embedded in a syscall ABI integer. Pin it so a
	// stack move cannot invalidate the address while building/calling the syscall.
	var pin runtime.Pinner
	pin.Pin(info)
	defer pin.Unpin()
	attr := struct {
		Program, Target, Attach, Flags uint32
		Info                           uint64
		InfoLen, Pad                   uint32
	}{
		Program: uint32(r.program.Fd()), Attach: unix.BPF_TRACE_ITER,
		Info: uint64(uintptr(unsafe.Pointer(info))), InfoLen: uint32(unsafe.Sizeof(*info)),
	}
	link, err := bpf(unix.BPF_LINK_CREATE, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	runtime.KeepAlive(info)
	if err != nil {
		return nil, err
	}
	defer unix.Close(link)
	create := [2]uint32{uint32(link), 0}
	fd, err := bpf(unix.BPF_ITER_CREATE, unsafe.Pointer(&create), unsafe.Sizeof(create))
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "task-file-iterator")
	defer f.Close()
	return decode(f, limit, deadline, time.Now)
}

var ErrBudget = errors.New("descriptor iterator budget exceeded")

func decode(src io.Reader, limit int, deadline time.Time, now func() time.Time) ([]Row, error) {
	// One read is at most 4096 records; memory and residence never grow with a
	// hostile task beyond the existing descriptor/deadline budget.
	buf := make([]byte, 4096*rowSize)
	rows := make([]Row, 0, min(limit, 1024))
	ended := false
	pending := 0
	empty := 0
	for {
		if !now().Before(deadline) {
			return nil, os.ErrDeadlineExceeded
		}
		n, err := src.Read(buf[pending:])
		n += pending
		if n == pending && err == nil {
			empty++
			if empty >= 100 {
				return nil, io.ErrNoProgress
			}
		} else {
			empty = 0
		}
		full := n / rowSize * rowSize
		for p := 0; p < full; p += rowSize {
			inode := binary.NativeEndian.Uint64(buf[p:])
			fd := binary.NativeEndian.Uint32(buf[p+8:])
			end := binary.NativeEndian.Uint32(buf[p+12:])
			if ended || end > 1 {
				return nil, fmt.Errorf("invalid iterator record")
			}
			if end == 1 {
				if inode != 0 || fd != 0 {
					return nil, fmt.Errorf("invalid iterator trailer")
				}
				ended = true
				continue
			}
			if len(rows) >= limit {
				return nil, ErrBudget
			}
			if len(rows) > 0 && fd <= rows[len(rows)-1].FD {
				return nil, fmt.Errorf("iterator descriptor order changed")
			}
			rows = append(rows, Row{Inode: inode, FD: fd})
		}
		pending = n - full
		copy(buf, buf[full:n])
		if err != nil {
			if err == io.EOF && ended && pending == 0 {
				return rows, nil
			}
			if err == io.EOF {
				return nil, io.ErrUnexpectedEOF
			}
			return nil, err
		}
	}
}

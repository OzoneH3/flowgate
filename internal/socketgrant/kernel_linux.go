//go:build socketprototype

package socketgrant

/*
#cgo pkg-config: libbpf libnftnl libmnl
#include "kernel.h"
*/
import "C"
import (
	"fmt"
	"golang.org/x/sys/unix"
	"unsafe"
)

type kernel struct{ p *C.struct_fg_gate }

func code(n C.int) error {
	if n < 0 {
		return unix.Errno(-n)
	}
	return nil
}

// OpenKernel is ONLY invoked by guarded serve-lab, after its queue exists.
func OpenKernel() (Backend, error) {
	if unsafe.Sizeof(Key{}) != 24 || unsafe.Sizeof(Value{}) != 16 {
		return nil, fmt.Errorf("socket gate ABI mismatch")
	}
	var result C.int
	p := C.fg_open(&result)
	if p == nil {
		return nil, fmt.Errorf("socket gate load: %w", code(result))
	}
	if result != 0 {
		// A partial insertion retains its owner, even when the ACK was lost.
		// The caller must Close this non-nil backend before discarding it.
		return &kernel{p}, fmt.Errorf("socket gate insert: %w", code(result))
	}
	return &kernel{p}, nil
}
func (k *kernel) Put(key Key, v Value) error {
	return code(C.fg_put(k.p, unsafe.Pointer(&key), unsafe.Pointer(&v)))
}
func (k *kernel) Delete(key Key) error { return code(C.fg_delete(k.p, unsafe.Pointer(&key))) }
func (k *kernel) Epoch(n uint64) error { return code(C.fg_epoch(k.p, C.uint64_t(n))) }
func (k *kernel) Stats(key Key) (Stats, error) {
	var out Stats
	err := code(C.fg_stats(k.p, unsafe.Pointer(&key), unsafe.Pointer(&out)))
	return out, err
}
func (k *kernel) Totals() (Stats, error) {
	var out Stats
	err := code(C.fg_totals(k.p, unsafe.Pointer(&out)))
	return out, err
}
func (k *kernel) Close() error {
	if k.p == nil {
		return nil
	}
	if err := code(C.fg_close(k.p)); err != nil {
		return err
	}
	k.p = nil
	return nil
}

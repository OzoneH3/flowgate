//go:build socketprototype

package socketgrant

/*
#cgo pkg-config: libbpf libnftnl libmnl
#include "route_kernel.h"
#include <stdlib.h>
*/
import "C"
import (
	"errors"
	"fmt"
	"sync"
	"unsafe"
)

// RoutedKernel is prepared for an already-owned private firewall chain. It does
// not establish chain ownership, install a hook, or track link generations. The
// protection-session coordinator must supply those before enabling this backend.
type RoutedKernel struct {
	mu sync.Mutex
	p  *C.struct_fg_route_gate
}

func OpenRoutedKernel(table, chain string) (*RoutedKernel, error) {
	if unsafe.Sizeof(Key{}) != 24 || unsafe.Sizeof(Value{}) != 16 {
		return nil, errors.New("socket gate ABI mismatch")
	}
	t, c := C.CString(table), C.CString(chain)
	defer C.free(unsafe.Pointer(t))
	defer C.free(unsafe.Pointer(c))
	var result C.int
	p := C.fg_route_open(t, c, &result)
	if p == nil {
		return nil, fmt.Errorf("route gate load: %w", code(result))
	}
	return &RoutedKernel{p: p}, nil
}

// AddInterface must only be called for a link instance whose identity is being
// monitored by the owning session. Reusing a number after link replacement
// requires revocation and reconstruction, never this idempotent call alone.
func (k *RoutedKernel) AddInterface(ifindex uint32) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.p == nil {
		return errors.New("route gate closed")
	}
	return code(C.fg_route_add(k.p, C.uint32_t(ifindex)))
}
func (k *RoutedKernel) Put(key Key, v Value) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.p == nil {
		return errors.New("route gate closed")
	}
	return code(C.fg_route_put(k.p, unsafe.Pointer(&key), unsafe.Pointer(&v)))
}
func (k *RoutedKernel) Delete(key Key) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.p == nil {
		return errors.New("route gate closed")
	}
	return code(C.fg_route_delete(k.p, unsafe.Pointer(&key)))
}
func (k *RoutedKernel) Epoch(n uint64) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.p == nil {
		return errors.New("route gate closed")
	}
	return code(C.fg_route_epoch(k.p, C.uint64_t(n)))
}
func (k *RoutedKernel) Stats(key Key) (Stats, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	var out Stats
	if k.p == nil {
		return out, errors.New("route gate closed")
	}
	err := code(C.fg_route_stats(k.p, unsafe.Pointer(&key), unsafe.Pointer(&out)))
	return out, err
}
func (k *RoutedKernel) Totals() (Stats, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	var out Stats
	if k.p == nil {
		return out, errors.New("route gate closed")
	}
	err := code(C.fg_route_totals(k.p, unsafe.Pointer(&out)))
	return out, err
}
func (k *RoutedKernel) Close() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.p == nil {
		return nil
	}
	if err := code(C.fg_route_close(k.p)); err != nil {
		return err
	}
	k.p = nil
	return nil
}

// CloseAfterTableDeletion rechecks exact rule absence in the kernel; a caller
// assertion alone cannot free the live owner after an epoch-write failure.
func (k *RoutedKernel) CloseAfterTableDeletion() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.p == nil {
		return nil
	}
	if err := code(C.fg_route_release_removed(k.p)); err != nil {
		return err
	}
	k.p = nil
	return nil
}

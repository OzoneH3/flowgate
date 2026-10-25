package identity

import (
	"encoding/binary"
	"fmt"
	"runtime"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// linkIsLoopback queries this exact interface in the current network namespace.
// Unlike net.InterfaceByIndex, it requests one RTM_GETLINK reply rather than a
// full link dump. Nothing is retained between calls, including negative results.
type linkQueryConnection interface {
	SetDeadline(time.Time) error
	Execute(netlink.Message) ([]netlink.Message, error)
	Close() error
}
type pooledLinkConnection struct {
	ns   string
	conn linkQueryConnection
}
type linkQueryPool struct {
	idle chan pooledLinkConnection
	busy chan struct{}
}

func newLinkQueryPool(limit int) *linkQueryPool {
	return &linkQueryPool{make(chan pooledLinkConnection, limit), make(chan struct{}, limit)}
}

var loopbackQueries = newLinkQueryPool(8)

func linkIsLoopback(index uint32) bool {
	if index == 0 || index > 1<<31-1 {
		return false
	}
	// A netlink connection belongs to the creating thread's network namespace.
	// Keep that thread fixed through checkout/dial/query; pooled connections from
	// another namespace are closed, never used to answer this observation.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ns := link("/proc/thread-self/ns/net")
	if ns == "" {
		return false
	}
	flags, err := loopbackQueries.query(index, ns, time.Now().Add(time.Second), func() (linkQueryConnection, error) { return netlink.Dial(unix.NETLINK_ROUTE, nil) })
	return err == nil && flags&unix.IFF_LOOPBACK != 0
}

// Only transport connections are reused, never link observations. Each checkout
// is exclusive and sends a fresh indexed request with its own sequence. Any
// deadline/protocol/I/O failure discards the connection, including late replies.
func (p *linkQueryPool) query(index uint32, ns string, until time.Time, dial func() (linkQueryConnection, error)) (uint32, error) {
	timer := time.NewTimer(time.Until(until))
	defer timer.Stop()
	select {
	case p.busy <- struct{}{}:
	case <-timer.C:
		return 0, fmt.Errorf("link query capacity deadline")
	}
	defer func() { <-p.busy }()
	var item pooledLinkConnection
	select {
	case item = <-p.idle:
	default:
	}
	if item.conn != nil && item.ns != ns {
		item.conn.Close()
		item.conn = nil
	}
	if item.conn == nil {
		c, err := dial()
		if err != nil {
			return 0, err
		}
		item = pooledLinkConnection{ns, c}
	}
	healthy := false
	defer func() {
		if healthy {
			p.idle <- item
		} else {
			item.conn.Close()
		}
	}()
	if err := item.conn.SetDeadline(until); err != nil {
		return 0, err
	}
	data := make([]byte, unix.SizeofIfInfomsg)
	data[0] = unix.AF_UNSPEC
	binary.NativeEndian.PutUint32(data[4:8], index)
	rows, err := item.conn.Execute(netlink.Message{Header: netlink.Header{Type: unix.RTM_GETLINK, Flags: netlink.Request}, Data: data})
	if err != nil {
		return 0, err
	}
	flags, err := exactLinkFlags(index, rows)
	if err != nil {
		return 0, err
	}
	healthy = true
	return flags, nil
}

func exactLinkFlags(index uint32, rows []netlink.Message) (uint32, error) {
	if len(rows) != 1 || rows[0].Header.Type != unix.RTM_NEWLINK || len(rows[0].Data) < unix.SizeofIfInfomsg || rows[0].Header.Flags&netlink.Multi != 0 {
		return 0, fmt.Errorf("unexpected indexed link reply")
	}
	b := rows[0].Data
	if index == 0 || binary.NativeEndian.Uint32(b[4:8]) != index {
		return 0, fmt.Errorf("link index changed")
	}
	return binary.NativeEndian.Uint32(b[8:12]), nil
}

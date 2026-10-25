package identity

import (
	"encoding/binary"
	"errors"
	"net"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

type modelLinkConnection struct {
	calls, closes int
	fail          bool
	deadline      time.Time
}

func (c *modelLinkConnection) SetDeadline(t time.Time) error { c.deadline = t; return nil }
func (c *modelLinkConnection) Close() error                  { c.closes++; return nil }
func (c *modelLinkConnection) Execute(m netlink.Message) ([]netlink.Message, error) {
	c.calls++
	if c.fail {
		return nil, errors.New("receive failed")
	}
	if m.Header.Type != unix.RTM_GETLINK || m.Header.Flags != netlink.Request || len(m.Data) != unix.SizeofIfInfomsg {
		return nil, errors.New("unexpected request")
	}
	b := append([]byte(nil), m.Data...)
	binary.NativeEndian.PutUint32(b[8:12], unix.IFF_LOOPBACK)
	return []netlink.Message{{Header: netlink.Header{Type: unix.RTM_NEWLINK}, Data: b}}, nil
}
func TestLinkQueryPoolFreshRequestsAndDiscard(t *testing.T) {
	p := newLinkQueryPool(1)
	var opened []*modelLinkConnection
	dial := func() (linkQueryConnection, error) {
		c := &modelLinkConnection{}
		opened = append(opened, c)
		return c, nil
	}
	query := func(ns string) {
		t.Helper()
		if flags, err := p.query(7, ns, time.Now().Add(time.Second), dial); err != nil || flags != unix.IFF_LOOPBACK {
			t.Fatal(flags, err)
		}
	}
	query("one")
	query("one")
	if len(opened) != 1 || opened[0].calls != 2 || opened[0].deadline.IsZero() {
		t.Fatal("did not issue a fresh request on reused transport")
	}
	query("two")
	if len(opened) != 2 || opened[0].closes != 1 {
		t.Fatal("namespace connection reused")
	}
	opened[1].fail = true
	if _, err := p.query(7, "two", time.Now().Add(time.Second), dial); err == nil || opened[1].closes != 1 {
		t.Fatal("failed connection retained")
	}
	query("two")
	if len(opened) != 3 {
		t.Fatal("failed connection reused")
	}
	p.busy <- struct{}{}
	if _, err := p.query(7, "two", time.Now().Add(-time.Second), dial); err == nil {
		t.Fatal("unbounded checkout")
	}
	<-p.busy
	(<-p.idle).conn.Close()
}

func TestLinkQueryPoolExclusiveConcurrentRequests(t *testing.T) {
	p := newLinkQueryPool(1)
	c := &modelLinkConnection{}
	opened := 0
	dial := func() (linkQueryConnection, error) { opened++; return c, nil }
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := p.query(7, "one", time.Now().Add(time.Second), dial); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if opened != 1 || c.calls != 16 {
		t.Fatal("connection not exclusively reused", opened, c.calls)
	}
	(<-p.idle).conn.Close()
}

func TestExactLinkFlagsRejectsWrongReplies(t *testing.T) {
	b := make([]byte, unix.SizeofIfInfomsg)
	binary.NativeEndian.PutUint32(b[4:8], 7)
	binary.NativeEndian.PutUint32(b[8:12], unix.IFF_LOOPBACK)
	good := netlink.Message{Header: netlink.Header{Type: unix.RTM_NEWLINK}, Data: b}
	if flags, err := exactLinkFlags(7, []netlink.Message{good}); err != nil || flags != unix.IFF_LOOPBACK {
		t.Fatal(flags, err)
	}
	for _, rows := range [][]netlink.Message{nil, {good, good}, {{Header: good.Header, Data: b[:8]}}, {{Header: netlink.Header{Type: unix.RTM_NEWADDR}, Data: b}}, {{Header: netlink.Header{Type: unix.RTM_NEWLINK, Flags: netlink.Multi}, Data: b}}} {
		if _, err := exactLinkFlags(7, rows); err == nil {
			t.Fatal("accepted unexpected reply", rows)
		}
	}
	if _, err := exactLinkFlags(8, []netlink.Message{good}); err == nil {
		t.Fatal("accepted another index")
	}
}

func TestIndexedLinkFlagsRealFreshness(t *testing.T) {
	udpPortLab(t)
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range interfaces {
		if got := linkIsLoopback(uint32(iface.Index)); got != (iface.Flags&net.FlagLoopback != 0) {
			t.Fatalf("%s flags mismatch", iface.Name)
		}
	}
	if linkIsLoopback(0) || linkIsLoopback(0xffffffff) {
		t.Fatal("invalid index allowed")
	}
	if out, err := exec.Command("ip", "link", "add", "fg-link-test", "type", "veth", "peer", "name", "fg-link-peer").CombinedOutput(); err != nil {
		t.Fatalf("dummy fixture: %v %s", err, out)
	}
	t.Cleanup(func() { exec.Command("ip", "link", "del", "fg-link-test").Run() })
	iface, err := net.InterfaceByName("fg-link-test")
	if err != nil {
		t.Fatal(err)
	}
	if linkIsLoopback(uint32(iface.Index)) {
		t.Fatal("physical interface treated as loopback")
	}
	if out, err := exec.Command("ip", "link", "del", "fg-link-test").CombinedOutput(); err != nil {
		t.Fatalf("delete: %v %s", err, out)
	}
	if linkIsLoopback(uint32(iface.Index)) {
		t.Fatal("deleted interface reused")
	}
}

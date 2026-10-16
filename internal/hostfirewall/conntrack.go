package hostfirewall

import (
	"errors"
	"flowgate/internal/identity"
	"fmt"
	"github.com/mdlayher/netlink"
	ct "github.com/ti-mo/conntrack"
	"github.com/ti-mo/netfilter"
	"golang.org/x/sys/unix"
	"net/netip"
	"time"
)

const approved uint32 = 0x10000000
const preserved uint32 = 0x20000000
const mask uint32 = approved | preserved

func flows() ([]ct.Flow, error) {
	c, err := ct.Dial(nil)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	// Bound netlink startup wait; Close interrupts a stalled dump.
	timer := time.AfterFunc(3*time.Second, func() { c.Close() })
	defer timer.Stop()
	fs, err := c.Dump(nil)
	if err != nil {
		return nil, err
	}
	if len(fs) > 65536 {
		return nil, fmt.Errorf("conntrack startup snapshot exceeds 65536 entries")
	}
	return fs, nil
}

// Masked conntrack update, including both the tuple and kernel ID. It never
// resets another firewall's bits or deletes a connection.
func setMark(f ct.Flow, value uint32) error {
	c, err := netlink.Dial(unix.NETLINK_NETFILTER, nil)
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	a := func(t uint16, b []byte) netfilter.Attribute { return netfilter.Attribute{Type: t, Data: b} }
	nest := func(t uint16, ch ...netfilter.Attribute) netfilter.Attribute {
		return netfilter.Attribute{Type: t, Nested: true, Children: ch}
	}
	src, dst := f.TupleOrig.IP.SourceAddress, f.TupleOrig.IP.DestinationAddress
	st, dt := uint16(1), uint16(2)
	family := netfilter.ProtoIPv4
	if src.Is6() {
		st, dt = 3, 4
		family = netfilter.ProtoIPv6
	}
	p := f.TupleOrig.Proto
	attrs := []netfilter.Attribute{nest(1, nest(1, a(st, src.AsSlice()), a(dt, dst.AsSlice())), nest(2, a(1, []byte{p.Protocol}), a(2, netfilter.Uint16Bytes(p.SourcePort)), a(3, netfilter.Uint16Bytes(p.DestinationPort)))), a(12, netfilter.Uint32Bytes(f.ID)), a(8, netfilter.Uint32Bytes(value)), a(21, netfilter.Uint32Bytes(mask))}
	if f.Zone != 0 {
		attrs = append(attrs, a(18, netfilter.Uint16Bytes(f.Zone)))
	}
	msg, err := netfilter.MarshalNetlink(netfilter.Header{SubsystemID: netfilter.NFSubsysCTNetlink, MessageType: 0, Family: family, Flags: netlink.Request | netlink.Acknowledge}, attrs)
	if err != nil {
		return err
	}
	_, err = c.Execute(msg)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	return err
}
func bootstrap(claim func() error) error {
	fs, err := flows()
	if err != nil {
		return err
	}
	for _, f := range fs {
		if f.Mark&mask != 0 {
			return fmt.Errorf("reserved conntrack bits already occupied; recover previous owned run first")
		}
	}
	// Refuse to strand established TCP sockets that were never tracked before
	// activation (for example a host with conntrack hooks previously inactive).
	sockets, err := identity.Sockets()
	if err != nil {
		return err
	}
	known := map[string]bool{}
	for _, f := range fs {
		for _, t := range []ct.Tuple{f.TupleOrig, f.TupleReply} {
			if t.Proto.Protocol == 6 {
				a := netip.AddrPortFrom(t.IP.SourceAddress.Unmap(), t.Proto.SourcePort)
				b := netip.AddrPortFrom(t.IP.DestinationAddress.Unmap(), t.Proto.DestinationPort)
				known[a.String()+"|"+b.String()] = true
			}
		}
	}
	for _, s := range sockets {
		if s.Protocol == "tcp" && s.State == 1 && !known[s.Local.String()+"|"+s.Remote.String()] {
			return fmt.Errorf("established TCP socket lacks a pre-existing conntrack entry; refusing activation to preserve it")
		}
	}
	if err := claim(); err != nil {
		return err
	}
	for _, f := range fs {
		p := f.TupleOrig.Proto.Protocol
		if (p == 6 || p == 17) && f.Status.Confirmed() {
			if err = setMark(f, preserved); err != nil {
				return err
			}
		}
	}
	return nil
}
func clearMarks() error {
	fs, err := flows()
	if err != nil {
		return err
	}
	for _, f := range fs {
		if f.Mark&mask != 0 {
			if err = setMark(f, 0); err != nil {
				return err
			}
		}
	}
	return nil
}

package queue

import (
	"bytes"
	"encoding/binary"
	"flowgate/internal/identity"
	"fmt"
	"github.com/mdlayher/netlink"
	"github.com/ti-mo/netfilter"
	"golang.org/x/sys/unix"
	"net"
	"time"
)

// Only the incoming half has a confirmed conntrack entry: the outgoing SYN
// passed postrouting before reaching input. Both halves still require their
// ordinary policy verdict. This is a TCP window-tracking adjustment, not an
// admission mark or an exception to the invalid-packet firewall rules.
func selfConnect(f identity.Flow) bool {
	return f.Direction == "incoming" && f.Protocol == "tcp" && f.Local == f.Remote && f.Local.Port() != 0 && f.Local.Addr().IsLoopback()
}

func selfConnectUpdate(f identity.Flow, raw []byte) (netlink.Message, error) {
	if !selfConnect(f) {
		return netlink.Message{}, fmt.Errorf("not an incoming loopback TCP self-connection")
	}
	iface, err := net.InterfaceByIndex(int(f.Interface))
	if err != nil || iface.Flags&net.FlagLoopback == 0 {
		return netlink.Message{}, fmt.Errorf("self-connection is not on a verified loopback interface")
	}
	attrs, err := netfilter.UnmarshalAttributes(raw)
	if err != nil {
		return netlink.Message{}, err
	}
	var orig, id, zone netfilter.Attribute
	var original, reply, confirmed bool
	for _, a := range attrs {
		switch a.Type {
		case 1:
			orig = a
			original = selfTuple(a, f)
		case 2:
			reply = selfTuple(a, f)
		case 3:
			confirmed = len(a.Data) == 4 && binary.BigEndian.Uint32(a.Data)&8 != 0
		case 12:
			id = a
		case 18:
			zone = a
		}
	}
	if !original || !reply || !confirmed || len(id.Data) != 4 || (zone.Type != 0 && len(zone.Data) != 2) {
		return netlink.Message{}, fmt.Errorf("self-connection lacks confirmed exact conntrack evidence")
	}
	// nf_conntrack_tcp.h: BE_LIBERAL=8. Mask only this bit in both directions;
	// leave TCP state, sequence tracking, marks and all other flags untouched.
	tcp := netfilter.Attribute{Type: 1, Nested: true, Children: []netfilter.Attribute{{Type: 4, Data: []byte{8, 8}}, {Type: 5, Data: []byte{8, 8}}}}
	update := []netfilter.Attribute{orig, id, {Type: 4, Nested: true, Children: []netfilter.Attribute{tcp}}}
	if zone.Type != 0 {
		update = append(update, zone)
	}
	family := netfilter.ProtoIPv4
	if f.Local.Addr().Is6() {
		family = netfilter.ProtoIPv6
	}
	return netfilter.MarshalNetlink(netfilter.Header{SubsystemID: netfilter.NFSubsysCTNetlink, MessageType: 0, Family: family, Flags: netlink.Request | netlink.Acknowledge}, update)
}

func selfTuple(a netfilter.Attribute, f identity.Flow) bool {
	var src, dst, proto, sp, dp bool
	st, dt := uint16(1), uint16(2)
	if f.Local.Addr().Is6() {
		st, dt = 3, 4
	}
	for _, part := range a.Children {
		for _, v := range part.Children {
			if part.Type == 1 {
				if v.Type == st {
					src = bytes.Equal(v.Data, f.Local.Addr().AsSlice())
				}
				if v.Type == dt {
					dst = bytes.Equal(v.Data, f.Local.Addr().AsSlice())
				}
			} else if part.Type == 2 {
				switch v.Type {
				case 1:
					proto = bytes.Equal(v.Data, []byte{6})
				case 2:
					sp = len(v.Data) == 2 && binary.BigEndian.Uint16(v.Data) == f.Local.Port()
				case 3:
					dp = len(v.Data) == 2 && binary.BigEndian.Uint16(v.Data) == f.Local.Port()
				}
			}
		}
	}
	return src && dst && proto && sp && dp
}

// ctnetlink UPDATE ignores CTA_ID. Check the ID explicitly before and after
// changing flags, and never release the queued SYN on a mismatch. These checks
// are not an atomic compare-and-swap; importantly, the update changes no
// permission, admission mark or connection state, even on tuple replacement.
func applySelfConnectUpdate(msg netlink.Message) error {
	c, err := netlink.Dial(unix.NETLINK_NETFILTER, nil)
	if err != nil {
		return err
	}
	defer c.Close()
	if err = c.SetDeadline(time.Now().Add(time.Second)); err != nil {
		return err
	}
	h, attrs, err := netfilter.UnmarshalNetlink(msg)
	if err != nil {
		return err
	}
	var lookup []netfilter.Attribute
	var expected []byte
	for _, a := range attrs {
		if a.Type == 1 || a.Type == 18 {
			lookup = append(lookup, a)
		}
		if a.Type == 12 {
			expected = a.Data
		}
	}
	if len(expected) != 4 {
		return fmt.Errorf("missing conntrack ID")
	}
	h.MessageType = 1 // IPCTNL_MSG_CT_GET
	get, err := netfilter.MarshalNetlink(h, lookup)
	if err != nil {
		return err
	}
	verify := func() error {
		replies, err := c.Execute(get)
		if err != nil {
			return err
		}
		for _, reply := range replies {
			// Execute already rejects negative ACKs; success ACKs have no entry.
			if reply.Header.Type == netlink.Error {
				continue
			}
			_, got, err := netfilter.UnmarshalNetlink(reply)
			if err != nil {
				return err
			}
			for _, a := range got {
				if a.Type == 12 && bytes.Equal(a.Data, expected) {
					return nil
				}
			}
		}
		return unix.ENOENT
	}
	if err = verify(); err != nil {
		return err
	}
	if _, err = c.Execute(msg); err != nil {
		return err
	}
	return verify()
}

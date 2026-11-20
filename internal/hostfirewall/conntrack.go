package hostfirewall

import (
	"context"
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

func flows() ([]ct.Flow, error) { return flowsContext(context.Background()) }

func flowsContext(ctx context.Context) ([]ct.Flow, error) {
	c, err := ct.Dial(nil)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	// Bound netlink startup wait; Close interrupts a stalled dump.
	timer := time.AfterFunc(3*time.Second, func() { c.Close() })
	defer timer.Stop()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
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

// unsupportedEstablishedTCP is a compatibility refusal, not proof of lost
// ownership or a failed consumer. It is produced only before claiming marks.
type unsupportedEstablishedTCP struct{ socket identity.Socket }

func (e *unsupportedEstablishedTCP) Error() string {
	s := e.socket
	return fmt.Sprintf("established TCP socket %s -> %s (inode %d) lacks a pre-existing conntrack entry; refusing activation to preserve it", s.Local, s.Remote, s.Inode)
}

// Read-only early check. bootstrapSnapshots repeats the same proof immediately
// before claim, because sockets and conntrack can change after this observation.
func checkEstablishedTCP(ctx context.Context) error {
	sockets, err := identity.Sockets()
	if err != nil {
		return err
	}
	fs, err := flows()
	if err != nil {
		return err
	}
	return validateBootstrap(ctx, sockets, fs)
}

// The ordering matches activation: a mark collision is an integrity failure,
// even when the same snapshot also contains an unsupported established socket.
func validateBootstrap(ctx context.Context, sockets []identity.Socket, fs []ct.Flow) error {
	for _, f := range fs {
		if err := ctx.Err(); err != nil {
			return err
		}
		if f.Mark&mask != 0 {
			return fmt.Errorf("reserved conntrack bits already occupied; recover previous owned run first")
		}
	}
	return validateEstablishedTCP(ctx, sockets, fs)
}

func validateEstablishedTCP(ctx context.Context, sockets []identity.Socket, fs []ct.Flow) error {
	known := map[string]bool{}
	for _, f := range fs {
		if err := ctx.Err(); err != nil {
			return err
		}
		for _, t := range []ct.Tuple{f.TupleOrig, f.TupleReply} {
			if t.Proto.Protocol == 6 {
				a := netip.AddrPortFrom(t.IP.SourceAddress.Unmap(), t.Proto.SourcePort)
				b := netip.AddrPortFrom(t.IP.DestinationAddress.Unmap(), t.Proto.DestinationPort)
				known[a.String()+"|"+b.String()] = true
			}
		}
	}
	for _, s := range sockets {
		if err := ctx.Err(); err != nil {
			return err
		}
		if s.Protocol == "tcp" && s.State == 1 && !known[s.Local.String()+"|"+s.Remote.String()] {
			return &unsupportedEstablishedTCP{socket: s}
		}
	}
	return nil
}

func bootstrap(claim func() error) error { return bootstrapContext(context.Background(), claim) }
func bootstrapContext(ctx context.Context, claim func() error) error {
	return bootstrapSnapshots(ctx, claim, identity.Sockets, flows, setMark)
}

func bootstrapSnapshots(ctx context.Context, claim func() error, socketSnapshot func() ([]identity.Socket, error), flowSnapshot func() ([]ct.Flow, error), mark func(ct.Flow, uint32) error) error {
	// Read sockets first: a connection established between the snapshots must
	// not be compared with an older conntrack dump and falsely called untracked.
	sockets, err := socketSnapshot()
	if err != nil {
		return err
	}
	fs, err := flowSnapshot()
	if err != nil {
		return err
	}
	if err := validateBootstrap(ctx, sockets, fs); err != nil {
		return err
	}
	if err := claim(); err != nil {
		return err
	}
	for _, f := range fs {
		if err := ctx.Err(); err != nil {
			return err
		}
		p := f.TupleOrig.Proto.Protocol
		if (p == 6 || p == 17) && f.Status.Confirmed() {
			if err = mark(f, preserved); err != nil {
				return err
			}
		}
	}
	return nil
}
func clearMarks() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	fs, err := flows()
	if err != nil {
		return err
	}
	for _, f := range fs {
		if err := ctx.Err(); err != nil {
			return err
		}
		if f.Mark&mask != 0 {
			if err = setMark(f, 0); err != nil {
				return err
			}
		}
	}
	return nil
}

// MarkCensus is read-only and deliberately omits endpoints/peer identities.
func MarkCensus() (map[string]int, error) {
	fs, err := flows()
	if err != nil {
		return nil, err
	}
	out := map[string]int{}
	for _, f := range fs {
		out[fmt.Sprintf("0x%08x", f.Mark)]++
	}
	return out, nil
}

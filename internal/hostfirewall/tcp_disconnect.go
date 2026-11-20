package hostfirewall

import (
	"context"
	"net"
	"net/netip"

	"flowgate/internal/daemon"
	"flowgate/internal/identity"

	ct "github.com/ti-mo/conntrack"
	"golang.org/x/sys/unix"
)

// Read sockets first. An older connection's tuple cannot be used to assign
// direction to a newer socket in the diagnostic snapshot.
func establishedTCP(ctx context.Context) ([]daemon.EstablishedTCP, error) {
	sockets, err := identity.Sockets()
	if err != nil {
		return nil, err
	}
	fs, err := flowsContext(ctx)
	if err != nil {
		return nil, err
	}
	// Same-host traffic can use loopback exemptions even with a non-loopback
	// address. The conntrack tuple does not prove the packet's interface.
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	local := make(map[netip.Addr]bool, len(addresses))
	for _, address := range addresses {
		if p, err := netip.ParsePrefix(address.String()); err == nil {
			local[p.Addr().Unmap()] = true
		}
	}
	var external []identity.Socket
	for _, socket := range sockets {
		peer := socket.Remote.Addr().Unmap()
		if !peer.IsLoopback() && !local[peer] {
			external = append(external, socket)
		}
	}
	return matchEstablishedTCP(external, fs), nil
}

func matchEstablishedTCP(sockets []identity.Socket, fs []ct.Flow) []daemon.EstablishedTCP {
	type endpoints struct{ local, remote netip.AddrPort }
	type direction struct {
		name  string
		count int
	}
	directions := make(map[endpoints]direction)
	add := func(ep endpoints, name string) {
		d := directions[ep]
		d.name = name
		d.count++
		directions[ep] = d
	}
	endpoint := func(addr netip.Addr, port uint16) netip.AddrPort {
		return netip.AddrPortFrom(addr.Unmap(), port)
	}
	for _, flow := range fs {
		orig, reply := flow.TupleOrig, flow.TupleReply
		if orig.Proto.Protocol != unix.IPPROTO_TCP || reply.Proto.Protocol != unix.IPPROTO_TCP ||
			!flow.Status.Confirmed() || !flow.Status.SeenReply() || !flow.Status.Assured() ||
			flow.ProtoInfo.TCP == nil || flow.ProtoInfo.TCP.State != 3 { // TCP_CONNTRACK_ESTABLISHED
			continue
		}
		src := endpoint(orig.IP.SourceAddress, orig.Proto.SourcePort)
		dst := endpoint(orig.IP.DestinationAddress, orig.Proto.DestinationPort)
		// NAT, scoped addresses and ambiguous original directions require
		// additional evidence. Never guess using a local or remote port.
		if src != endpoint(reply.IP.DestinationAddress, reply.Proto.DestinationPort) ||
			dst != endpoint(reply.IP.SourceAddress, reply.Proto.SourcePort) ||
			src.Addr().IsLinkLocalUnicast() || dst.Addr().IsLinkLocalUnicast() {
			continue
		}
		// A preserved connection may have been picked up midstream, so its
		// original tuple alone is not proof of the TCP initiator. A connection
		// admitted through the owned TCP SYN policy has that evidence.
		if flow.Mark&mask != approved || flow.Status.Expected() ||
			(flow.ProtoInfo.TCP.OriginalFlags|flow.ProtoInfo.TCP.ReplyFlags)&0x80 != 0 { // IP_CT_TCP_SIMULTANEOUS_OPEN
			add(endpoints{src, dst}, "")
			add(endpoints{dst, src}, "")
			continue
		}
		add(endpoints{src, dst}, "outgoing")
		add(endpoints{dst, src}, "incoming")
	}
	var out []daemon.EstablishedTCP
	for _, s := range sockets {
		if s.Protocol != "tcp" || s.State != 1 || s.Cookie == "" || s.Inode == 0 || s.NetNS == "" {
			continue
		}
		if d := directions[endpoints{s.Local, s.Remote}]; d.count == 1 && d.name != "" {
			out = append(out, daemon.EstablishedTCP{Socket: s, Flow: identity.Flow{
				Protocol: "tcp", Direction: d.name, Local: s.Local, Remote: s.Remote, NetNS: s.NetNS,
			}})
		}
	}
	return out
}

// ConfigureEstablishedTCP shares one census between continuous protection and
// the private host-start path. Call before exposing the engine's API.
func ConfigureEstablishedTCP(e *daemon.Engine, resolve func(identity.Flow) identity.Attribution) {
	e.ConfigureTCPDisconnect(establishedTCP, resolve)
}

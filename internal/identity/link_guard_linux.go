package identity

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// LinkGuard watches the identity of a fixed activation-time interface set.
// New interfaces are deliberately unsupported until the next session. It is
// permission invalidation input, never application or network-zone authority.
type LinkGuard struct {
	conn    *netlink.Conn
	links   []NetworkLink
	netns   string
	skipped []NetworkLink
}

func NewLinkGuard() (*LinkGuard, error) {
	c, err := netlink.Dial(unix.NETLINK_ROUTE, &netlink.Config{Groups: unix.RTMGRP_LINK})
	if err != nil {
		return nil, err
	}
	// Subscribe before the dump: queued delete/recreate events must not disappear
	// merely because a final dump happens to contain the same numeric ifindex.
	snapshot := CollectNetwork()
	if snapshot.State != "ready" {
		c.Close()
		return nil, fmt.Errorf("link identity snapshot: %s (%s)", snapshot.State, snapshot.Reason)
	}
	links, skipped := selectGateLinks(snapshot)
	return &LinkGuard{conn: c, links: links, skipped: skipped, netns: snapshot.NetNS}, nil
}
func (g *LinkGuard) Links() []NetworkLink        { return append([]NetworkLink(nil), g.links...) }
func (g *LinkGuard) SkippedLinks() []NetworkLink { return append([]NetworkLink(nil), g.skipped...) }
func (g *LinkGuard) Close() error                { return g.conn.Close() }
func linkFromMessage(m netlink.Message) (NetworkLink, error) {
	if len(m.Data) < unix.SizeofIfInfomsg {
		return NetworkLink{}, errors.New("short link event")
	}
	v := NetworkLink{Index: binary.NativeEndian.Uint32(m.Data[4:8])}
	attrs, err := netlink.UnmarshalAttributes(m.Data[unix.SizeofIfInfomsg:])
	if err != nil {
		return v, err
	}
	for _, a := range attrs {
		switch a.Type & 0x3fff {
		case unix.IFLA_IFNAME:
			v.Name = strings.TrimRight(string(a.Data), "\x00")
		case unix.IFLA_ADDRESS:
			v.Address = hex.EncodeToString(a.Data)
		case unix.IFLA_PERM_ADDRESS:
			v.PermanentAddress = hex.EncodeToString(a.Data)
		case unix.IFLA_LINKINFO:
			nested, err := netlink.UnmarshalAttributes(a.Data)
			if err != nil {
				return v, err
			}
			for _, n := range nested {
				if n.Type&0x3fff == unix.IFLA_INFO_KIND {
					v.Kind = strings.TrimRight(string(n.Data), "\x00")
				}
			}
		}
	}
	return v, nil
}
func sameLinkIdentity(a, b NetworkLink) bool {
	if a.Index != b.Index || a.Name != b.Name || a.Kind != b.Kind {
		return false
	}
	if a.PermanentAddress != "" {
		return a.PermanentAddress == b.PermanentAddress
	}
	// Current MAC addresses can legitimately change on reconnect. Instance
	// continuity comes from the loss-checked DELLINK stream, not that address.
	return true
}
func (g *LinkGuard) observe(messages []netlink.Message) error {
	for _, m := range messages {
		if m.Header.Type == unix.NLMSG_OVERRUN {
			return errors.New("link watcher overrun")
		}
		if m.Header.Type != unix.RTM_NEWLINK && m.Header.Type != unix.RTM_DELLINK {
			continue
		}
		v, err := linkFromMessage(m)
		if err != nil {
			return err
		}
		for _, old := range g.links {
			if old.Index == v.Index {
				if m.Header.Type == unix.RTM_DELLINK {
					return fmt.Errorf("installed interface %d was deleted", v.Index)
				}
				if !sameLinkIdentity(old, v) {
					return fmt.Errorf("installed interface %d identity changed", v.Index)
				}
			}
		}
	}
	return nil
}

// Run returns on the first identity uncertainty. Carrier, flags, MTU and
// operstate changes do not disable acceleration. Caller must invalidate before
// rebuilding; simply seeing the same ifindex again never restores permission.
func (g *LinkGuard) Run(ctx context.Context) error {
	if NetNS() != g.netns {
		return errors.New("link watcher network namespace changed")
	}
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := g.conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			return err
		}
		messages, err := g.conn.Receive()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			var timeout interface{ Timeout() bool }
			if errors.As(err, &timeout) && timeout.Timeout() {
				continue
			}
			return fmt.Errorf("link watcher unavailable: %w", err)
		}
		if err = g.observe(messages); err != nil {
			return err
		}
	}
}

// Selection affects acceleration coverage only, never route/zone authority.
func selectGateLinks(snapshot NetworkSnapshot) (installed, skipped []NetworkLink) {
	rank := map[uint32]int{}
	for _, a := range snapshot.Addresses {
		if p, err := netip.ParsePrefix(a.Prefix); err == nil && p.Addr().Is4() {
			rank[a.Interface] = 1
		}
	}
	for _, r := range snapshot.Routes {
		if p, err := netip.ParsePrefix(r.Prefix); err == nil && p.Addr().Is4() && r.Type == unix.RTN_UNICAST {
			if old, ok := rank[r.Interface]; !ok || old != 0 {
				rank[r.Interface] = 1
			}
			if p.Bits() == 0 {
				rank[r.Interface] = 0
			}
		}
	}
	for _, link := range snapshot.Links {
		_, eligible := rank[link.Index]
		if !eligible || link.Index == 0 || link.Flags&unix.IFF_UP == 0 || link.Flags&unix.IFF_LOOPBACK != 0 {
			skipped = append(skipped, link)
			continue
		}
		installed = append(installed, link)
	}
	sort.Slice(installed, func(i, j int) bool {
		a, b := installed[i], installed[j]
		if rank[a.Index] != rank[b.Index] {
			return rank[a.Index] < rank[b.Index]
		}
		return a.Index < b.Index
	})
	if len(installed) > 32 {
		skipped = append(skipped, installed[32:]...)
		installed = installed[:32]
	}
	sort.Slice(skipped, func(i, j int) bool { return skipped[i].Index < skipped[j].Index })
	return installed, skipped
}

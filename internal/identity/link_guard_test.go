package identity

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
	"testing"
)

func linkMessage(t *testing.T, kind uint16, v NetworkLink) netlink.Message {
	t.Helper()
	address, _ := hex.DecodeString(v.Address)
	permanent, _ := hex.DecodeString(v.PermanentAddress)
	nested, err := netlink.MarshalAttributes([]netlink.Attribute{{Type: unix.IFLA_INFO_KIND, Data: []byte(v.Kind + "\x00")}})
	if err != nil {
		t.Fatal(err)
	}
	attrs, err := netlink.MarshalAttributes([]netlink.Attribute{{Type: unix.IFLA_IFNAME, Data: []byte(v.Name + "\x00")}, {Type: unix.IFLA_ADDRESS, Data: address}, {Type: unix.IFLA_PERM_ADDRESS, Data: permanent}, {Type: unix.IFLA_LINKINFO, Data: nested}})
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, unix.SizeofIfInfomsg)
	binary.NativeEndian.PutUint32(data[4:8], v.Index)
	binary.NativeEndian.PutUint32(data[8:12], v.Flags)
	return netlink.Message{Header: netlink.Header{Type: netlink.HeaderType(kind)}, Data: append(data, attrs...)}
}
func TestLinkGuardIdentityAndState(t *testing.T) {
	old := NetworkLink{Index: 7, Name: "synthetic0", Kind: "veth", Address: "020000000001", PermanentAddress: "020000000001"}
	g := &LinkGuard{links: []NetworkLink{old}}
	state := old
	state.Flags = unix.IFF_UP | unix.IFF_RUNNING
	state.Address = "020000000002"
	if err := g.observe([]netlink.Message{linkMessage(t, unix.RTM_NEWLINK, state)}); err != nil {
		t.Fatalf("carrier/current address with stable permanent identity: %v", err)
	}
	withoutPermanent := old
	withoutPermanent.PermanentAddress = ""
	withoutGuard := &LinkGuard{links: []NetworkLink{withoutPermanent}}
	withoutPermanent.Address = "020000000004"
	if err := withoutGuard.observe([]netlink.Message{linkMessage(t, unix.RTM_NEWLINK, withoutPermanent)}); err != nil {
		t.Fatal("current MAC randomization is not link replacement", err)
	}
	other := old
	other.Index = 8
	if err := g.observe([]netlink.Message{linkMessage(t, unix.RTM_NEWLINK, other)}); err != nil {
		t.Fatal("uninstalled interface", err)
	}
	for _, mutate := range []func(*NetworkLink){func(v *NetworkLink) { v.Name = "renamed" }, func(v *NetworkLink) { v.Kind = "dummy" }, func(v *NetworkLink) { v.PermanentAddress = "020000000003" }} {
		changed := old
		mutate(&changed)
		if g.observe([]netlink.Message{linkMessage(t, unix.RTM_NEWLINK, changed)}) == nil {
			t.Fatal("changed identity accepted")
		}
	}
	// Delete+recreate with byte-identical identity is still a new instance.
	if g.observe([]netlink.Message{linkMessage(t, unix.RTM_DELLINK, old), linkMessage(t, unix.RTM_NEWLINK, old)}) == nil {
		t.Fatal("ifindex reuse accepted")
	}
	if g.observe([]netlink.Message{{Header: netlink.Header{Type: unix.NLMSG_OVERRUN}}}) == nil {
		t.Fatal("overrun accepted")
	}
	if g.observe([]netlink.Message{{Header: netlink.Header{Type: unix.RTM_NEWLINK}, Data: []byte{1}}}) == nil {
		t.Fatal("malformed event accepted")
	}
}

func TestGateLinkSelectionBoundsAndPrioritizesUplink(t *testing.T) {
	var snapshot NetworkSnapshot
	for i := uint32(1); i <= 40; i++ {
		snapshot.Links = append(snapshot.Links, NetworkLink{Index: i, Flags: unix.IFF_UP})
		snapshot.Addresses = append(snapshot.Addresses, NetworkAddress{Interface: i, Prefix: "198.18.1.1/24"})
	}
	snapshot.Routes = []NetworkRoute{{Interface: 40, Prefix: "0.0.0.0/0", Type: unix.RTN_UNICAST}}
	snapshot.Links[0].Flags |= unix.IFF_LOOPBACK
	snapshot.Links[1].Flags = 0
	installed, skipped := selectGateLinks(snapshot)
	if len(installed) != 32 || len(skipped) != 8 || installed[0].Index != 40 {
		t.Fatal("wrong bounded selection", installed, skipped)
	}
	for _, link := range installed {
		if link.Index == 1 || link.Index == 2 {
			t.Fatal("loopback/down accelerated")
		}
	}
}

func TestLinkGuardRetiresOnlyChangedInstance(t *testing.T) {
	a := NetworkLink{Index: 7, Name: "uplink-a", Kind: "dummy"}
	b := NetworkLink{Index: 8, Name: "uplink-b", Kind: "dummy"}
	calls := map[uint32]int{}
	g := &LinkGuard{links: []NetworkLink{a, b}, retire: func(v NetworkLink, reason string) error { calls[v.Index]++; return nil }}
	if err := g.observe([]netlink.Message{linkMessage(t, unix.RTM_DELLINK, a), linkMessage(t, unix.RTM_NEWLINK, a)}); err != nil {
		t.Fatal(err)
	}
	if calls[7] != 1 || calls[8] != 0 {
		t.Fatal(calls)
	}
	if err := g.observe([]netlink.Message{linkMessage(t, unix.RTM_DELLINK, a), linkMessage(t, unix.RTM_DELLINK, b)}); err != nil {
		t.Fatal(err)
	}
	if calls[7] != 1 || calls[8] != 1 {
		t.Fatal("surviving link no longer watched", calls)
	}
	if g.observe([]netlink.Message{{Header: netlink.Header{Type: unix.NLMSG_OVERRUN}}}) == nil {
		t.Fatal("lost events accepted")
	}
	fresh := &LinkGuard{links: []NetworkLink{a}, retire: func(NetworkLink, string) error { return errors.New("map write failed") }}
	if fresh.observe([]netlink.Message{linkMessage(t, unix.RTM_DELLINK, a)}) == nil || fresh.retired[7] {
		t.Fatal("unconfirmed retirement accepted")
	}
}

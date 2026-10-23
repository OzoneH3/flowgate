package hostfirewall

import (
	"context"
	"flowgate/internal/identity"
	ct "github.com/ti-mo/conntrack"
	"net/netip"
	"strings"
	"testing"
)

func TestBootstrapSnapshotsSocketBeforeConntrack(t *testing.T) {
	local, remote := netip.MustParseAddrPort("127.0.0.1:41001"), netip.MustParseAddrPort("127.0.0.1:41002")
	observed := false
	claimed := false
	marked := 0
	err := bootstrapSnapshots(context.Background(), func() error { claimed = true; return nil },
		func() ([]identity.Socket, error) {
			observed = true
			return []identity.Socket{{Protocol: "tcp", State: 1, Local: local, Remote: remote}}, nil
		},
		func() ([]ct.Flow, error) {
			// Simulate a connection becoming established during the socket dump. An
			// earlier conntrack snapshot would lack it and incorrectly refuse startup.
			if !observed {
				return nil, nil
			}
			f := ct.Flow{Status: ct.Status{Value: 8}}
			f.TupleOrig.IP.SourceAddress = local.Addr()
			f.TupleOrig.IP.DestinationAddress = remote.Addr()
			f.TupleOrig.Proto.Protocol = 6
			f.TupleOrig.Proto.SourcePort = local.Port()
			f.TupleOrig.Proto.DestinationPort = remote.Port()
			return []ct.Flow{f}, nil
		}, func(_ ct.Flow, value uint32) error {
			if !claimed || value != preserved {
				t.Fatal("mark before claim or wrong bits")
			}
			marked++
			return nil
		})
	if err != nil || !claimed || marked != 1 {
		t.Fatal(err, claimed, marked)
	}
}

func TestBootstrapUntrackedSocketRefusesBeforeClaim(t *testing.T) {
	err := bootstrapSnapshots(context.Background(), func() error { t.Fatal("claimed despite missing entry"); return nil },
		func() ([]identity.Socket, error) {
			return []identity.Socket{{Protocol: "tcp", State: 1, Inode: 42, Local: netip.MustParseAddrPort("127.0.0.1:41001"), Remote: netip.MustParseAddrPort("127.0.0.1:41002")}}, nil
		},
		func() ([]ct.Flow, error) { return nil, nil }, func(ct.Flow, uint32) error { t.Fatal("marked despite missing entry"); return nil })
	if err == nil || !strings.Contains(err.Error(), "127.0.0.1:41001 -> 127.0.0.1:41002 (inode 42)") {
		t.Fatal(err)
	}
}

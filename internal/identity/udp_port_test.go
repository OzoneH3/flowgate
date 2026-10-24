package identity

import (
	"context"
	"encoding/binary"
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"slices"
	"syscall"
	"testing"
)

func TestUDPPortDiagRequestPreservesCompleteCandidateScope(t *testing.T) {
	for _, family := range []byte{unix.AF_INET, unix.AF_INET6} {
		req := diagRequest(family, unix.IPPROTO_UDP, 0, 41001)
		if len(req) != 56 || req[0] != family || req[1] != unix.IPPROTO_UDP || binary.BigEndian.Uint16(req[8:10]) != 41001 || binary.NativeEndian.Uint32(req[4:8]) != 0xffffffff {
			t.Fatal(req)
		}
		for _, value := range req[10:48] {
			if value != 0 {
				t.Fatal("destination/address/interface must not narrow candidates", req)
			}
		}
		for _, value := range req[48:56] {
			if value != 255 {
				t.Fatal("cookie must select all candidates")
			}
		}
	}
	if _, err := UDPPortSockets(0); err == nil {
		t.Fatal("zero port accepted")
	}
}

func udpPortLab(t testing.TB) {
	t.Helper()
	if os.Getenv("FLOWGATE_PARENT_NETNS") == "" || os.Getenv("FLOWGATE_PARENT_NETNS") == NetNS() {
		t.Skip("private lab namespace required")
	}
}

func TestUDPPortCensusAgreesWithFullBothFamiliesAndCompetitors(t *testing.T) {
	udpPortLab(t)
	config := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var setErr error
		err := c.Control(func(fd uintptr) { setErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1) })
		if err != nil {
			return err
		}
		return setErr
	}}
	first, err := config.ListenPacket(context.Background(), "udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	port := first.LocalAddr().(*net.UDPAddr).Port
	competitor, err := config.ListenPacket(context.Background(), "udp4", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer competitor.Close()
	// A v6-only socket can use the same local port. It must not disappear from
	// the census even for an IPv4 query; the normal receiver matcher decides it.
	second, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6unspecified, Port: port})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	other, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	all, err := UDPSockets()
	if err != nil {
		t.Fatal(err)
	}
	selected, err := UDPPortSockets(uint16(port))
	if err != nil {
		t.Fatal(err)
	}
	keys := func(rows []Socket) []string {
		var out []string
		for _, s := range rows {
			if s.Local.Port() == uint16(port) {
				out = append(out, reuseKey(Flow{}, s))
			}
		}
		slices.Sort(out)
		return out
	}
	if len(selected) != 3 || !slices.Equal(keys(selected), keys(all)) {
		t.Fatalf("incomplete filtered census: selected=%+v all=%+v", selected, all)
	}
	for _, s := range selected {
		if s.Local.Port() != uint16(port) {
			t.Fatal("unrelated row retained", s)
		}
	}
}

func BenchmarkUDPPortCensus(b *testing.B) {
	udpPortLab(b)
	var sockets []*net.UDPConn
	defer func() {
		for _, s := range sockets {
			s.Close()
		}
	}()
	for i := 0; i < 256; i++ {
		s, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
		if err != nil {
			b.Fatal(err)
		}
		sockets = append(sockets, s)
	}
	port := uint16(sockets[0].LocalAddr().(*net.UDPAddr).Port)
	b.Run("full", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := UDPSockets(); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("local-port", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := UDPPortSockets(port); err != nil {
				b.Fatal(err)
			}
		}
	})
}

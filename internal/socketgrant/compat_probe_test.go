//go:build socketprototype

package socketgrant

import (
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
	"testing"
)

func TestBPFMatchReplyRequiresExactCapability(t *testing.T) {
	for _, kind := range []string{"valid", "valid-ack", "bad-ack", "duplicate-ack", "empty", "duplicate", "wrong-name", "no-revision", "target", "wrong-family", "short"} {
		t.Run(kind, func(t *testing.T) {
			attrs := []netlink.Attribute{{Type: 1, Data: []byte("bpf\x00")}, {Type: 2, Data: []byte{0, 0, 0, 1}}, {Type: 3, Data: make([]byte, 4)}}
			switch kind {
			case "duplicate":
				attrs = append(attrs, attrs[0])
			case "wrong-name":
				attrs[0].Data = []byte("other\x00")
			case "no-revision":
				attrs = append(attrs[:1], attrs[2])
			case "target":
				attrs[2].Data = []byte{0, 0, 0, 1}
			}
			raw, _ := netlink.MarshalAttributes(attrs)
			data := append([]byte{unix.AF_INET, 0, 0, 0}, raw...)
			if kind == "wrong-family" {
				data[0] = unix.AF_INET6
			}
			if kind == "short" {
				data = data[:2]
			}
			rows := []netlink.Message{{Header: netlink.Header{Type: 11 << 8}, Data: data}}
			if kind == "valid-ack" || kind == "bad-ack" || kind == "duplicate-ack" {
				ack := netlink.Message{Header: netlink.Header{Type: netlink.Error}, Data: make([]byte, 4)}
				if kind == "bad-ack" {
					ack.Data[0] = 1
				}
				rows = append(rows, ack)
				if kind == "duplicate-ack" {
					rows = append(rows, ack)
				}
			}
			if kind == "empty" {
				rows = nil
			}
			if (validateBPFMatchReply(rows) == nil) != (kind == "valid" || kind == "valid-ack") {
				t.Fatal("unexpected capability decision")
			}
		})
	}
}

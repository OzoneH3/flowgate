//go:build socketprototype

package socketgrant

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// EnsureBPFMatch asks the kernel's standard xtables revision-query path for the
// IPv4 bpf match. Unlike inserting an INET-family rule, this query has the
// ipt_bpf module alias and can request its normal autoload. It changes no rule,
// permission, mark, attachment, or expiry. The subsequent rule installation is
// still the operational capability check. A failed probe leaves queue fallback.
func EnsureBPFMatch() error {
	c, err := netlink.Dial(unix.NETLINK_NETFILTER, nil)
	if err != nil {
		return fmt.Errorf("xt_bpf revision-1 match unavailable: %w", err)
	}
	defer c.Close()
	if err := c.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return fmt.Errorf("xt_bpf revision-1 match unavailable: %w", err)
	}
	attrs, _ := netlink.MarshalAttributes([]netlink.Attribute{
		{Type: 1, Data: []byte("bpf\x00")},  // NFTA_COMPAT_NAME
		{Type: 2, Data: []byte{0, 0, 0, 1}}, // NFTA_COMPAT_REV, network order
		{Type: 3, Data: []byte{0, 0, 0, 0}}, // NFTA_COMPAT_TYPE: match
	})
	data := append([]byte{unix.AF_INET, 0, 0, 0}, attrs...) // nfgenmsg
	// NFNL_SUBSYS_NFT_COMPAT (11), NFNL_MSG_COMPAT_GET (0).
	rows, err := c.Execute(netlink.Message{Header: netlink.Header{Type: 11 << 8, Flags: netlink.Request | netlink.Acknowledge}, Data: data})
	if err == nil {
		err = validateBPFMatchReply(rows)
	}
	if err != nil {
		return fmt.Errorf("xt_bpf revision-1 match unavailable: %w", err)
	}
	return nil
}

func validateBPFMatchReply(rows []netlink.Message) error {
	// Execute validates sender/sequence and negative ACKs. A successful query
	// returns the capability record followed by a zero-error ACK, not just data.
	var data []byte
	acks := 0
	for _, row := range rows {
		if row.Header.Type == netlink.Error {
			if len(row.Data) < 4 || binary.NativeEndian.Uint32(row.Data[:4]) != 0 || acks != 0 {
				return fmt.Errorf("invalid compatibility acknowledgement")
			}
			acks++
			continue
		}
		if row.Header.Type != 11<<8 || data != nil {
			return fmt.Errorf("unexpected compatibility reply")
		}
		data = row.Data
	}
	if len(data) < 4 || data[0] != unix.AF_INET || data[1] != 0 || data[2] != 0 || data[3] != 0 {
		return fmt.Errorf("unexpected compatibility reply")
	}
	attrs, err := netlink.UnmarshalAttributes(data[4:])
	if err != nil {
		return err
	}
	seen := map[uint16]bool{}
	for _, a := range attrs {
		if a.Type < 1 || a.Type > 3 || seen[a.Type] {
			return fmt.Errorf("unexpected compatibility attribute")
		}
		seen[a.Type] = true
		switch a.Type {
		case 1:
			if string(a.Data) != "bpf\x00" {
				return fmt.Errorf("unexpected compatibility match")
			}
		case 2:
			if len(a.Data) != 4 || binary.BigEndian.Uint32(a.Data) < 1 {
				return fmt.Errorf("required match revision unavailable")
			}
		case 3:
			if len(a.Data) != 4 || binary.BigEndian.Uint32(a.Data) != 0 {
				return fmt.Errorf("unexpected compatibility type")
			}
		}
	}
	if len(seen) != 3 {
		return fmt.Errorf("incomplete compatibility reply")
	}
	return nil
}

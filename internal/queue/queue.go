// Package queue connects bounded policy evaluation to NFQUEUE.
package queue

import (
	"context"
	"encoding/binary"
	"flowgate/internal/daemon"
	"flowgate/internal/identity"
	"fmt"
	nfqueue "github.com/florianl/go-nfqueue/v2"
	"net/netip"
	"time"
)

const Mark = 0x4647

func Parse(b []byte, direction string) (identity.Flow, string, error) {
	f := identity.Flow{Direction: direction, NetNS: identity.NetNS()}
	var src, dst netip.Addr
	var p byte
	var offset int
	if len(b) < 20 {
		return f, "", fmt.Errorf("short IP packet")
	}
	switch b[0] >> 4 {
	case 4:
		offset = int(b[0]&15) * 4
		if offset < 20 || len(b) < offset {
			return f, "", fmt.Errorf("invalid IPv4 header")
		}
		if binary.BigEndian.Uint16(b[6:8])&0x3fff != 0 {
			return f, "", fmt.Errorf("fragment unsupported")
		}
		src = netip.AddrFrom4([4]byte(b[12:16]))
		dst = netip.AddrFrom4([4]byte(b[16:20]))
		p = b[9]
	case 6:
		if len(b) < 40 {
			return f, "", fmt.Errorf("short IPv6 packet")
		}
		offset = 40
		src = netip.AddrFrom16([16]byte(b[8:24]))
		dst = netip.AddrFrom16([16]byte(b[24:40]))
		p = b[6]
	default:
		return f, "", fmt.Errorf("unknown IP version")
	}
	if len(b) < offset+8 {
		return f, "", fmt.Errorf("short transport header")
	}
	t := b[offset:]
	token := "udp"
	switch p {
	case 6:
		if len(t) < 20 || t[13]&0x12 != 2 {
			return f, "", fmt.Errorf("not an initial TCP SYN")
		}
		f.Protocol = "tcp"
		token = fmt.Sprint(binary.BigEndian.Uint32(t[4:8]))
	case 17:
		f.Protocol = "udp"
	default:
		return f, "", fmt.Errorf("unsupported protocol or IPv6 extension header")
	}
	s := netip.AddrPortFrom(src.Unmap(), binary.BigEndian.Uint16(t[:2]))
	d := netip.AddrPortFrom(dst.Unmap(), binary.BigEndian.Uint16(t[2:4]))
	f.Local = d
	f.Remote = s
	if direction == "outgoing" {
		f.Local = s
		f.Remote = d
	}
	return f, token, nil
}
func Run(ctx context.Context, e *daemon.Engine, direction string, ready func() error) error {
	return RunConfigured(ctx, e, direction, 100, true, ready)
}

// Host mode leaves marks untouched; its post-queue nft chain applies a masked OR.
func RunConfigured(ctx context.Context, e *daemon.Engine, direction string, number uint16, labMark bool, ready func() error) error {
	nf, err := nfqueue.Open(&nfqueue.Config{NfQueue: number, MaxQueueLen: 128, MaxPacketLen: 65535, Copymode: nfqueue.NfQnlCopyPacket, Flags: nfqueue.NfQaCfgFlagConntrack, WriteTimeout: time.Second})
	if err != nil {
		return err
	}
	defer nf.Close()
	retained := &Retainer{}
	verdictPacket := func(id uint32, allow bool) error {
		if allow && labMark {
			return nf.SetVerdictWithOption(id, nfqueue.NfAccept, nfqueue.WithConnMark(Mark))
		}
		if allow {
			return nf.SetVerdict(id, nfqueue.NfAccept)
		}
		return nf.SetVerdict(id, nfqueue.NfDrop)
	}
	defer retained.Flush(time.Now(), e.RetainedState, verdictPacket, true)
	errors := make(chan error, 1)
	fail := func(err error) {
		select {
		case errors <- err:
		default:
		}
	}
	err = nf.RegisterWithErrorFunc(ctx, func(a nfqueue.Attribute) int {
		if a.PacketID == nil {
			return 0
		}
		verdict := nfqueue.NfDrop
		if a.Payload != nil {
			f, token, err := Parse(*a.Payload, direction)
			if err == nil {
				if a.InDev != nil {
					f.Interface = *a.InDev
				}
				if direction == "outgoing" && a.OutDev != nil {
					f.Interface = *a.OutDev
				}
				v := e.Observe(f, token)
				if v.State == "awaiting-decision" && retained.Add(*a.PacketID, len(*a.Payload), v) {
					return 0
				}
				if v.State == "allowed" {
					verdict = nfqueue.NfAccept
				}
			}
		}
		var err error
		if verdict == nfqueue.NfAccept && labMark {
			err = nf.SetVerdictWithOption(*a.PacketID, verdict, nfqueue.WithConnMark(Mark))
		} else {
			err = nf.SetVerdict(*a.PacketID, verdict)
		}
		if err != nil {
			fail(err)
			return -1
		}
		return 0
	}, func(err error) int { fail(err); return -1 })
	if err != nil {
		return err
	}
	if err = ready(); err != nil {
		return err
	}
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-errors:
			return err
		case now := <-ticker.C:
			if err := retained.Flush(now, e.RetainedState, verdictPacket, false); err != nil {
				return err
			}
		}
	}
}

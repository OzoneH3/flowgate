// Package queue connects bounded policy evaluation to NFQUEUE.
package queue

import (
	"context"
	"encoding/binary"
	"errors"
	"flowgate/internal/daemon"
	"flowgate/internal/identity"
	"fmt"
	nfqueue "github.com/florianl/go-nfqueue/v2"
	"github.com/mdlayher/netlink"
	"log"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
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
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	nf, err := nfqueue.Open(&nfqueue.Config{NfQueue: number, MaxQueueLen: 128, MaxPacketLen: 65535, Copymode: nfqueue.NfQnlCopyPacket, Flags: nfqueue.NfQaCfgFlagConntrack, WriteTimeout: time.Second})
	if err != nil {
		return err
	}
	defer nf.Close()
	retained := &Retainer{}
	errors := make(chan error, 1)
	fail := func(err error) {
		select {
		case errors <- err:
		default:
		}
		cancel()
	}
	var selfFailures atomic.Uint64
	var selfFailureReason atomic.Pointer[string]
	selfFailure := func(err error) {
		selfFailures.Add(1)
		reason := err.Error()
		selfFailureReason.Store(&reason)
	}
	var selfUpdates sync.Map // packet ID -> exact kernel connection update; removed on every verdict
	submitVerdict := func(id uint32, allow bool) (bool, error) {
		if allow && ctx.Err() != nil {
			allow = false
		}
		var err error
		if update, ok := selfUpdates.LoadAndDelete(id); ok && allow {
			if err = applySelfConnectUpdate(update.(netlink.Message)); err != nil {
				selfFailure(err)
				allow = false
			}
		}
		if ctx.Err() != nil {
			allow = false
		}
		if allow && labMark {
			err = nf.SetVerdictWithOption(id, nfqueue.NfAccept, nfqueue.WithConnMark(Mark))
		} else if allow {
			err = nf.SetVerdict(id, nfqueue.NfAccept)
		} else {
			err = nf.SetVerdict(id, nfqueue.NfDrop)
		}
		if err != nil {
			fail(err)
		}
		return allow, err
	}
	verdictPacket := func(id uint32, allow bool) error {
		_, err := submitVerdict(id, allow)
		return err
	}
	var overloaded, expired, censusOverflow, displaced, receiveOverflow atomic.Uint64
	// Keep one bounded sample, without packet payload or an inferred owner. A
	// capacity rejection occurs before attribution and otherwise leaves no way
	// to distinguish a game's failed admission from unrelated background traffic.
	var overloadedSample atomic.Pointer[identity.Flow]
	processor := packetProcessor{ctx: ctx, observe: e.Observe, tryObserve: e.TryObserve, retain: retained.Add, record: e.RecordPacketOutcome, verdict: submitVerdict, expired: &expired}
	workers := newPacketLanes(AttributionWorkers, CensusWorkers, processor.processStage, func(p packetJob, cause rejectionCause) {
		if cause == rejectShutdown {
			expired.Add(1)
		} else if cause == rejectAdmission {
			displaced.Add(1)
		} else {
			censusOverflow.Add(1)
		}
		verdictPacket(p.id, false)
	})
	report := func() {
		if n := selfFailures.Swap(0); n != 0 {
			reason := "unknown"
			if r := selfFailureReason.Load(); r != nil {
				reason = *r
			}
			log.Printf("queue %d: self-connection tracking failures %d: %s", number, n, reason)
		}
		if n := receiveOverflow.Swap(0); n != 0 {
			log.Printf("queue %d: %d netlink receive overflow notifications; packets may have been dropped; continuing protection", number, n)
		}
		if n := displaced.Swap(0); n != 0 {
			log.Printf("queue %d: dropped %d packets: admission fairness displacement", number, n)
		}
		if n := censusOverflow.Swap(0); n != 0 {
			log.Printf("queue %d: dropped %d packets: census lane capacity exhausted", number, n)
		}
		if n := overloaded.Swap(0); n != 0 {
			if f := overloadedSample.Swap(nil); f != nil {
				log.Printf("queue %d: dropped %d packets: attribution capacity exhausted; sample %s %s %s -> %s (local -> remote; ownership not checked)", number, n, f.Protocol, f.Direction, f.Local, f.Remote)
			} else {
				log.Printf("queue %d: dropped %d packets: attribution capacity exhausted", number, n)
			}
		}
		if n := expired.Swap(0); n != 0 {
			log.Printf("queue %d: dropped %d packets: attribution deadline or shutdown", number, n)
		}
	}
	defer func() {
		cancel()
		workers.stop()
		if err := retained.Flush(time.Now(), e.RetainedState, verdictPacket, true); err != nil {
			log.Printf("queue %d: shutdown verdict: %v", number, err)
		}
		report()
	}()
	err = nf.RegisterWithErrorFunc(ctx, func(a nfqueue.Attribute) int {
		if a.PacketID == nil {
			return 0
		}
		if a.Payload != nil && ctx.Err() == nil {
			packetDirection := direction
			if direction == "both" {
				packetDirection = ""
				if a.Hook != nil {
					switch *a.Hook {
					case 1:
						packetDirection = "incoming"
					case 3:
						packetDirection = "outgoing"
					}
				}
			}
			f, token, err := Parse(*a.Payload, packetDirection)
			if packetDirection != "incoming" && packetDirection != "outgoing" {
				err = fmt.Errorf("unsupported queue hook")
			}
			if err == nil {
				if a.InDev != nil {
					f.Interface = *a.InDev
				}
				if packetDirection == "outgoing" && a.OutDev != nil {
					f.Interface = *a.OutDev
				}
				if selfConnect(f) {
					var raw []byte
					if a.Ct != nil {
						raw = *a.Ct
					}
					update, updateErr := selfConnectUpdate(f, raw)
					if updateErr != nil {
						// Keep ordinary attribution/prompt/logging when this optional
						// compatibility adjustment cannot be safely prepared.
						selfFailure(updateErr)
					} else {
						selfUpdates.Store(*a.PacketID, update)
					}
				}
				if workers.submitWait(ctx, packetJob{id: *a.PacketID, size: len(*a.Payload), flow: f, token: token, deadline: time.Now().Add(AttributionTimeout)}) {
					return 0
				}
				overloadedSample.CompareAndSwap(nil, &f)
				overloaded.Add(1)
			}
		}
		if err := verdictPacket(*a.PacketID, false); err != nil {
			return -1
		}
		return 0
	}, func(err error) int { return receiveError(ctx, err, &receiveOverflow, fail) })
	if err != nil {
		return err
	}
	if err = ready(); err != nil {
		return err
	}
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	reporting := time.NewTicker(time.Second)
	defer reporting.Stop()
	for {
		select {
		case <-ctx.Done():
			select {
			case err := <-errors:
				return err
			default:
				return nil
			}
		case err := <-errors:
			return err
		case <-reporting.C:
			report()
		case now := <-ticker.C:
			if err := retained.Flush(now, e.RetainedState, verdictPacket, false); err != nil {
				return err
			}
		}
	}
}

// ENOBUFS reports lost netlink messages, not loss of the queue binding. Continue
// draining; no missing packet is approved. Other receive failures remain fatal.
// After cancellation the library interrupts Receive with a past read deadline;
// that timeout is the requested shutdown, not a queue failure, and must not
// race a clean stop into a retained fail-closed table.
func receiveError(ctx context.Context, err error, overflow *atomic.Uint64, fail func(error)) int {
	if ctx.Err() != nil {
		return -1
	}
	if errors.Is(err, unix.ENOBUFS) {
		overflow.Add(1)
		return 0
	}
	fail(err)
	return -1
}

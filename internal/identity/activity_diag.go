package identity

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
	"syscall"
	"time"
)

// ErrSocketCensusCapacity denotes an incomplete bounded census, never an empty one.
var ErrSocketCensusCapacity = errors.New("socket diagnostic capacity exceeded")

// The ordinary netlink library assembles an entire multipart dump before return.
// Monitoring needs a bounded accumulator; enforcement retains its original path.
func boundedDiag(req []byte, limit int) ([]netlink.Message, error) {
	if limit <= 0 {
		return nil, ErrSocketCensusCapacity
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_SOCK_DIAG)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	if err = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 2}); err != nil {
		return nil, err
	}
	if err = unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	request := netlink.Message{Header: netlink.Header{Length: uint32(16 + len(req)), Type: 20, Flags: netlink.Request | netlink.Dump, Sequence: 1}, Data: req}
	data, err := request.MarshalBinary()
	if err != nil {
		return nil, err
	}
	if err = unix.Sendto(fd, data, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	buffer := make([]byte, 65536)
	start := time.Now()
	total := 0
	result := []netlink.Message{}
	for time.Since(start) < 2*time.Second {
		n, _, flags, from, err := unix.Recvmsg(fd, buffer, nil, 0)
		if err != nil {
			return result, err
		}
		sender, ok := from.(*unix.SockaddrNetlink)
		if !ok || sender.Pid != 0 || flags&unix.MSG_TRUNC != 0 {
			return result, fmt.Errorf("incomplete socket diagnostic datagram")
		}
		messages, err := syscall.ParseNetlinkMessage(buffer[:n])
		if err != nil {
			return result, err
		}
		for _, m := range messages {
			if m.Header.Seq != 1 || m.Header.Flags&unix.NLM_F_DUMP_INTR != 0 {
				return result, fmt.Errorf("socket diagnostic dump interrupted")
			}
			if m.Header.Type == unix.NLMSG_ERROR {
				if len(m.Data) >= 4 {
					code := int32(binary.NativeEndian.Uint32(m.Data[:4]))
					if code < 0 {
						return result, fmt.Errorf("socket diagnostics: %w", syscall.Errno(-code))
					}
				}
				return result, fmt.Errorf("socket diagnostic netlink error")
			}
			if m.Header.Type == unix.NLMSG_DONE {
				if len(m.Data) >= 4 && int32(binary.NativeEndian.Uint32(m.Data[:4])) != 0 {
					return result, fmt.Errorf("socket diagnostic dump error")
				}
				return result, nil
			}
			if len(result) >= limit || total+len(m.Data) > 3*1024*1024 {
				return result, ErrSocketCensusCapacity
			}
			total += len(m.Data)
			result = append(result, netlink.Message{Data: append([]byte(nil), m.Data...)})
		}
	}
	return result, fmt.Errorf("socket diagnostic time budget reached")
}

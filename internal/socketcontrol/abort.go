// Package socketcontrol provides an exact-socket Linux TCP abort primitive.
// It is deliberately not connected to a daemon API or policy evaluator.
//
// A socket cookie prevents targeting a replacement socket, but does not prove
// application ownership, exclusive descriptor use, or a winning Deny rule.
// Callers must establish authority separately before using Abort. In particular,
// an Activity row or VerifyObservedNative alone is not revocation authority.
package socketcontrol

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"time"

	"flowgate/internal/identity"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

type Status string

const (
	Acknowledged Status = "acknowledged"
	NotFound     Status = "not_found"
	Rejected     Status = "rejected"
	Unsupported  Status = "unsupported"
	Forbidden    Status = "forbidden"
	Unavailable  Status = "unavailable"
	Unknown      Status = "unknown"
)

// Result describes only the local kernel operation. Acknowledged does not prove
// remote delivery of a reset, absence of buffered payload, or a future Deny.
// Attempted means the destroy request reached the transport call; on transport
// failure it may or may not have reached the kernel. Never replay Unknown.
type Result struct {
	Status    Status
	Attempted bool
}

type exchange func(netlink.Message) ([]netlink.Message, error)

// Abort rechecks one established TCP socket then requests its local abort.
// No wildcard, socket dump, conntrack update, namespace switch, or retry occurs.
// This operation affects every descriptor referring to the socket, even when a
// descriptor changes holder between the fresh query and the abort.
func Abort(ctx context.Context, expected identity.Socket) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{Status: Unavailable}, err
	}
	request, err := encode(expected)
	if err != nil {
		return Result{Status: Rejected}, err
	}
	// Bind the netlink socket to the checked thread namespace. Do not rely on
	// /proc/self/ns/net when another OS thread might have used setns.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	namespace, err := os.Readlink("/proc/thread-self/ns/net")
	if err != nil {
		return Result{Status: Unavailable}, err
	}
	if namespace != expected.NetNS {
		return Result{Status: Rejected}, fmt.Errorf("socket namespace differs from current thread")
	}
	c, err := netlink.Dial(unix.NETLINK_SOCK_DIAG, nil)
	if err != nil {
		return Result{Status: Unavailable}, err
	}
	defer c.Close()
	deadline := time.Now().Add(2 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err = c.SetDeadline(deadline); err != nil {
		return Result{Status: Unavailable}, err
	}
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	return abort(ctx, expected, request, c.Execute)
}

func encode(s identity.Socket) ([]byte, error) {
	if s.Protocol != "tcp" || s.State != 1 || s.Inode == 0 || s.NetNS == "" {
		return nil, fmt.Errorf("established TCP socket with namespace and inode required")
	}
	if s.Family != unix.AF_INET && s.Family != unix.AF_INET6 {
		return nil, fmt.Errorf("unsupported address family")
	}
	if !s.Local.IsValid() || !s.Remote.IsValid() || s.Local.Port() == 0 || s.Remote.Port() == 0 || s.Local.Addr().IsUnspecified() || s.Remote.Addr().IsUnspecified() {
		return nil, fmt.Errorf("concrete local and remote endpoints required")
	}
	if s.Local.Addr().Unmap().Is4() != s.Remote.Addr().Unmap().Is4() || (s.Family == unix.AF_INET && !s.Local.Addr().Unmap().Is4()) {
		return nil, fmt.Errorf("address family mismatch")
	}
	for _, address := range []string{s.Local.Addr().Zone(), s.Remote.Addr().Zone()} {
		if address != "" && (s.Interface == 0 || address != strconv.FormatUint(uint64(s.Interface), 10)) {
			return nil, fmt.Errorf("address zone does not match diagnostic interface")
		}
	}
	cookie, err := hex.DecodeString(s.Cookie)
	if err != nil || len(cookie) != 8 || bytes.Equal(cookie, make([]byte, 8)) || bytes.Equal(cookie, bytes.Repeat([]byte{255}, 8)) {
		return nil, fmt.Errorf("exact nonzero kernel cookie required; wildcard refused")
	}
	b := make([]byte, 56)
	b[0], b[1] = s.Family, unix.IPPROTO_TCP
	binary.NativeEndian.PutUint32(b[4:8], 1<<1)
	binary.BigEndian.PutUint16(b[8:10], s.Local.Port())
	binary.BigEndian.PutUint16(b[10:12], s.Remote.Port())
	if s.Family == unix.AF_INET {
		local, remote := s.Local.Addr().Unmap().As4(), s.Remote.Addr().Unmap().As4()
		copy(b[12:16], local[:])
		copy(b[28:32], remote[:])
	} else {
		local, remote := s.Local.Addr().As16(), s.Remote.Addr().As16()
		copy(b[12:28], local[:])
		copy(b[28:44], remote[:])
	}
	binary.NativeEndian.PutUint32(b[44:48], s.Interface)
	copy(b[48:56], cookie)
	return b, nil
}

func abort(ctx context.Context, s identity.Socket, request []byte, call exchange) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{Status: Unavailable}, err
	}
	messages, err := call(netlink.Message{Header: netlink.Header{Type: 20, Flags: netlink.Request}, Data: request})
	if err != nil {
		return failure(err, false)
	}
	// Query result is fresh kernel evidence, not a cached Activity row. Socket
	// creator UID is checked for drift; it is not current-owner authorization.
	if len(messages) != 1 || messages[0].Header.Type != 20 || len(messages[0].Data) < 72 {
		return Result{Status: Rejected}, fmt.Errorf("incomplete exact socket response")
	}
	b := messages[0].Data
	if b[0] != s.Family || b[1] != 1 || !bytes.Equal(b[4:52], request[8:56]) || binary.NativeEndian.Uint32(b[64:68]) != s.UID || binary.NativeEndian.Uint32(b[68:72]) != s.Inode {
		return Result{Status: Rejected}, fmt.Errorf("socket identity or state changed")
	}
	if err := ctx.Err(); err != nil {
		return Result{Status: Unavailable}, err
	}
	messages, err = call(netlink.Message{Header: netlink.Header{Type: 21, Flags: netlink.Request | netlink.Acknowledge}, Data: request})
	if err != nil {
		return failure(err, true)
	}
	// Execute checks sequence/PID and kernel error codes, but an arbitrary
	// non-error reply is not an acknowledgement. nlmsgerr contains errno and
	// the original request header, even when the optional payload is capped.
	if len(messages) != 1 || messages[0].Header.Type != netlink.Error || len(messages[0].Data) < 20 || binary.NativeEndian.Uint32(messages[0].Data[:4]) != 0 || binary.NativeEndian.Uint16(messages[0].Data[8:10]) != 21 {
		return Result{Status: Unknown, Attempted: true}, fmt.Errorf("missing or malformed destroy acknowledgement; do not retry")
	}
	return Result{Status: Acknowledged, Attempted: true}, nil
}

func failure(err error, attempted bool) (Result, error) {
	status := Unavailable
	if attempted {
		status = Unknown
	}
	switch {
	case errors.Is(err, unix.ENOENT), errors.Is(err, unix.ESRCH):
		status = NotFound
	case errors.Is(err, unix.EPERM), errors.Is(err, unix.EACCES):
		status = Forbidden
	case errors.Is(err, unix.EOPNOTSUPP), errors.Is(err, unix.EPROTONOSUPPORT):
		status = Unsupported
	}
	return Result{Status: status, Attempted: attempted}, err
}

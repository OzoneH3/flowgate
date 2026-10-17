// Package udpaccount is an optional collection-only adapter, never enforcement.
package udpaccount

import (
	"encoding/json"
	"flowgate/internal/identity"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"time"
)

func Request(path, op string) (identity.UDPSnapshot, error) {
	var out identity.UDPSnapshot
	c, err := net.DialTimeout("unix", path, 200*time.Millisecond)
	if err != nil {
		return out, err
	}
	defer c.Close()
	u := c.(*net.UnixConn)
	raw, e := u.SyscallConn()
	if e != nil {
		return out, e
	}
	var cred *unix.Ucred
	raw.Control(func(fd uintptr) { cred, e = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
	if e != nil || cred == nil || cred.Uid != 0 {
		return out, fmt.Errorf("UDP API is not owned by privileged collector")
	}

	c.SetDeadline(time.Now().Add(time.Second))
	if _, err = fmt.Fprintf(c, "{\"version\":1,\"operation\":%q}\n", op); err != nil {
		return out, err
	}
	err = json.NewDecoder(io.LimitReader(c, 1024*1024)).Decode(&out)
	if err == nil && out.Version != 1 {
		return out, fmt.Errorf("unsupported UDP API version")
	}
	if err == nil && out.State == "error" {
		err = fmt.Errorf("%s", out.Reason)
	}
	return out, err
}
func Snapshot(path string) identity.UDPSnapshot {
	u, err := Request(path, "list")
	if err != nil {
		return identity.UDPSnapshot{State: "unavailable", Reason: err.Error()}
	}
	if u.NetNS != "" && u.NetNS != identity.NetNS() {
		return identity.UDPSnapshot{State: "unavailable", Reason: "UDP collector belongs to a different network namespace"}
	}
	if u.State == "warming-up" {
		return u
	}
	if len(u.Rows) > 2048 || time.Since(u.Collected) > 4*time.Second || u.Collected.IsZero() {
		return identity.UDPSnapshot{State: "unavailable", Reason: "UDP collector snapshot stale/oversized"}
	}
	return u
}

// Client is used by one serial observer worker, independently of control IPC.
type Client struct {
	Path string
	seen bool
}

func (c *Client) Snapshot() identity.UDPSnapshot {
	u := Snapshot(c.Path)
	if u.State == "active" {
		c.seen = true
	}
	if u.State == "unavailable" && c.seen {
		u.State = "disconnected"
	}
	return u
}

package udpaccount

import (
	"bufio"
	"context"
	"encoding/json"
	"flowgate/internal/identity"
	"flowgate/internal/readiness"
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"time"
)

// Run starts only the explicitly selected helper; it never invokes nft or a shell.
// The helper/object is built into one executable (libbpf skeleton), with no pins.
func Run(ctx context.Context, path, helper string, uid uint32) error {
	if os.Geteuid() != 0 {
		return readiness.Fail("permission_required", "extended collector requires privileged BPF load; frontend must remain unprivileged", "Run doctor; use the explicit terminal authentication workflow only when authorized")
	}
	if _, err := os.Stat(path); err == nil {
		return readiness.Fail("instance_or_socket_exists", "collector socket already exists; refusing to replace it", "Inspect doctor and collector status; Stop the confirmed owned collector")
	}
	if check := readiness.Helper(helper); check.Status != readiness.Ready {
		return &readiness.Failure{Check: check}
	}
	session, err := startSession(ctx, helper, uid, false)
	if err != nil {
		return err
	}
	defer session.close()
	ctx = session.ctx
	listener, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	defer listener.Close()

	if err = os.Chown(path, int(uid), -1); err != nil {
		return err
	}
	if err = os.Chmod(path, 0600); err != nil {
		return err
	}
	go func() { <-ctx.Done(); listener.Close() }()
	fmt.Fprintln(os.Stderr, "READY extended-traffic: collection only; no firewall changes", path)
	slots := make(chan struct{}, 8)
	for {
		c, e := listener.Accept()
		if e != nil {
			if ctx.Err() != nil {
				return nil
			}
			return e
		}
		select {
		case slots <- struct{}{}:
		default:
			c.Close()
			continue
		}
		go func() {
			defer func() { <-slots; c.Close() }()
			c.SetDeadline(time.Now().Add(time.Second))
			u := c.(*net.UnixConn)
			raw, _ := u.SyscallConn()
			var cred *unix.Ucred
			raw.Control(func(fd uintptr) { cred, _ = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
			if cred == nil || cred.Uid != uid {
				return
			}
			var q struct {
				Version   int
				Operation string
			}
			reader := bufio.NewReaderSize(c, 4096)
			line, _, err := reader.ReadLine()
			response := identity.UDPSnapshot{State: "error", Reason: "invalid collection-only request"}
			if err == nil && len(line) < 4096 && json.Unmarshal(line, &q) == nil && q.Version == 1 {
				switch q.Operation {
				case "list":
					response = session.snapshot()
				case "stop":
					response.State = "stopped"
					response.Reason = "Only this collector stopped; firewall unchanged"
					defer session.cancel()
				}
			}
			response.Version = 1
			json.NewEncoder(c).Encode(response)
		}()
	}
}

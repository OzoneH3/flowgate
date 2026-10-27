// Experimental isolated shaping discovery. No permission API or verdict output.
package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"flowgate/internal/identity"
	"fmt"
	"io"
	"os"
	"strings"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "serve-sockets" {
		if err := serveSockets(os.Stdin, os.Stdout, func() ([]identity.Socket, error) {
			return identity.SocketsLimited(1024)
		}, identity.SocketExists); err != nil {
			fail(err)
		}
		return
	}
	var out any
	if len(os.Args) == 2 && os.Args[1] == "sockets" {
		ss, err := identity.SocketsLimited(1024)
		if err != nil {
			fail(err)
		}
		out = ss
	} else if len(os.Args) == 5 && os.Args[1] == "bind" {
		f, err := identity.ParseFlow(os.Args[2], "outgoing", os.Args[3], os.Args[4])
		if err != nil {
			fail(err)
		}
		f.NetNS = identity.NetNS()
		a := identity.Resolve(f)
		if !a.VisibilityComplete || a.Status != "directly-associated" || len(a.Owners) != 1 || len(a.Sockets) != 1 || a.Application == nil {
			fail(fmt.Errorf("unproven or shared socket: %s", a.Status))
		}
		p := a.Owners[0]
		if p.PID != p.ThreadGroup || p.HolderWitness != "" || p.Application.Kind != "native" || p.Application.Executable != p.Executable || p.Application.Revision != p.ExecutableRevision || identity.RuntimeRuleBlocked(&p.Application) != "" || !identity.LiveRuleable(p.Application) {
			fail(fmt.Errorf("native leader evidence required"))
		}
		fresh, err := identity.Inspect(p.PID)
		if err != nil {
			fail(err)
		}
		if fresh.Start != p.Start || fresh.UID != p.UID || fresh.NetNS != p.NetNS || fresh.MountNS != p.MountNS || fresh.PIDNS != p.PIDNS || fresh.Executable != p.Executable || fresh.ExecutableRevision != p.ExecutableRevision || fresh.Application.Kind != "native" || fresh.Application.Key != p.Application.Key || identity.RuntimeRuleBlocked(&fresh.Application) != "" || !identity.LiveRuleable(fresh.Application) {
			fail(fmt.Errorf("identity changed during binding"))
		}
		// Bookend with a second complete holder/socket proof, not just process liveness.
		b := identity.Resolve(f)
		if !b.VisibilityComplete || b.Status != "directly-associated" || b.Fingerprint != a.Fingerprint || len(b.Sockets) != 1 || b.Sockets[0].Cookie != a.Sockets[0].Cookie {
			fail(fmt.Errorf("socket evidence changed"))
		}
		out = b
	} else {
		fail(fmt.Errorf("usage: probe sockets | bind protocol local remote"))
	}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		fail(err)
	}
}

// Private, serial pipe protocol. Each request makes a new kernel census; there
// is no retained socket evidence, permission decision or bind operation here.
// The controller enforces the same deadline and output bound as finite helpers.
func serveSockets(in io.Reader, out io.Writer, census func() ([]identity.Socket, error), exact ...func(identity.Socket) (bool, error)) error {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 1024), 1024)
	for scanner.Scan() {
		var result any
		var err error
		if scanner.Text() == "sockets -" {
			result, err = census()
		} else if strings.HasPrefix(scanner.Text(), "exists ") && len(exact) == 1 {
			var raw []byte
			raw, err = hex.DecodeString(strings.TrimPrefix(scanner.Text(), "exists "))
			if err == nil {
				var descriptor identity.Socket
				err = json.Unmarshal(raw, &descriptor)
				if err == nil {
					result, err = exact[0](descriptor)
				}
			}
		} else {
			return fmt.Errorf("invalid socket worker request")
		}
		if err != nil {
			return err
		} // No ACK or partial evidence on failure.
		payload, err := json.Marshal(result)
		if err != nil {
			return err
		}
		if len(payload)+5 > 2*1024*1024 {
			return fmt.Errorf("socket worker output bound")
		}
		payload = append(payload, '\n')
		if n, err := out.Write(payload); err != nil {
			return err
		} else if n != len(payload) {
			return io.ErrShortWrite
		}
		if n, err := io.WriteString(out, "\x1eOK\n"); err != nil {
			return err
		} else if n != 4 {
			return io.ErrShortWrite
		}
	}
	return scanner.Err()
}
func fail(err error) { fmt.Fprintln(os.Stderr, err); os.Exit(1) }

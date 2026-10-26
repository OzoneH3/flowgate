// Experimental isolated shaping discovery. No permission API or verdict output.
package main

import (
	"encoding/json"
	"flowgate/internal/identity"
	"fmt"
	"os"
)

func main() {
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
func fail(err error) { fmt.Fprintln(os.Stderr, err); os.Exit(1) }

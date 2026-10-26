package main

import (
	"encoding/json"
	"flowgate/internal/identity"
	"net/netip"
	"os"
	"strconv"
)

func main() {
	var v any
	if os.Args[1] == "inspect" {
		p, _ := strconv.Atoi(os.Args[2])
		x, e := identity.Inspect(p)
		if e != nil {
			panic(e)
		}
		v = x
	} else {
		f := identity.Flow{Protocol: os.Args[2], Direction: "outgoing", Local: netip.MustParseAddrPort(os.Args[3]), Remote: netip.MustParseAddrPort(os.Args[4]), NetNS: identity.NetNS()}
		v = identity.Resolve(f)
	}
	json.NewEncoder(os.Stdout).Encode(v)
}

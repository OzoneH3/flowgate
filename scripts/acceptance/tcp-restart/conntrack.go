// Read the mark of exactly one original IPv4 TCP tuple in a disposable guest.
package main

import (
	"encoding/json"
	"log"
	"net/netip"
	"os"
	"time"

	ct "github.com/ti-mo/conntrack"
)

func main() {
	if len(os.Args) != 3 {
		log.Fatal("usage: conntrack-mark LOCAL_IP:PORT REMOTE_IP:PORT")
	}
	local, err := netip.ParseAddrPort(os.Args[1])
	if err != nil || !local.Addr().Is4() {
		log.Fatal("expected an IPv4 local endpoint")
	}
	remote, err := netip.ParseAddrPort(os.Args[2])
	if err != nil || !remote.Addr().Is4() {
		log.Fatal("expected an IPv4 remote endpoint")
	}
	c, err := ct.Dial(nil)
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()
	timeout := time.AfterFunc(3*time.Second, func() { c.Close() })
	defer timeout.Stop()
	flows, err := c.Dump(nil)
	if err != nil {
		log.Fatal(err)
	}
	var match *ct.Flow
	for i := range flows {
		f := &flows[i]
		t := f.TupleOrig
		if t.Proto.Protocol != 6 ||
			netip.AddrPortFrom(t.IP.SourceAddress, t.Proto.SourcePort) != local ||
			netip.AddrPortFrom(t.IP.DestinationAddress, t.Proto.DestinationPort) != remote {
			continue
		}
		if match != nil {
			log.Fatal("original TCP tuple overlaps multiple conntrack rows")
		}
		match = f
	}
	if match == nil || match.ProtoInfo.TCP == nil {
		log.Fatal("no TCP conntrack state for original tuple")
	}
	info := map[string]any{"local": local, "remote": remote, "mark": match.Mark,
		"id": match.ID, "zone": match.Zone, "status": match.Status.Value, "state": match.ProtoInfo.TCP.State}
	if err := json.NewEncoder(os.Stdout).Encode(info); err != nil {
		log.Fatal(err)
	}
}

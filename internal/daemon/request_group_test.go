package daemon

import (
	"flowgate/internal/policy"
	"testing"
)

func TestRequestGroupDestinationBurstKeepsAuthorityBoundaries(t *testing.T) {
	base := policy.Filter{Application: "app-prefix-a", Revision: "revision-a", UID: 1000, Direction: "outgoing", Protocol: "udp", RemoteAddress: "192.0.2.1", RemotePort: 27000}
	key := requestGroup(base)
	for i := 1; i <= 132; i++ {
		next := base
		next.RemoteAddress = "198.51.100.1"
		next.RemotePort = uint16(i)
		next.LocalPort = uint16(40000 + i)
		if requestGroup(next) != key {
			t.Fatal("destination burst split into multiple presentation groups")
		}
	}
	for _, change := range []func(*policy.Filter){
		func(f *policy.Filter) { f.Application = "another-app-or-prefix" },
		func(f *policy.Filter) { f.Revision = "another-revision" },
		func(f *policy.Filter) { f.UID = 1001 },
		func(f *policy.Filter) { f.Direction = "incoming" },
		func(f *policy.Filter) { f.Protocol = "tcp" },
	} {
		next := base
		change(&next)
		if requestGroup(next) == key {
			t.Fatal("authority boundary collapsed")
		}
	}
}

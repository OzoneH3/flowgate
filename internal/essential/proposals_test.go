package essential

import (
	"flowgate/internal/identity"
	"os"
	"testing"
	"time"
)

func TestSetupDefaultsToDHCPAndNeverRecreatesLocalhost(t *testing.T) {
	p, err := identity.Inspect(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	s := Snapshot{Collected: time.Now(), DNS: []DNS{{"192.0.2.53", 53, 2, "test0", false}}, Stubs: []Stub{{"127.0.0.53", "udp", 1}, {"127.0.0.53", "tcp", 1}}, DHCP: []DHCP{{"test0", 2, true, true}}, NTP: []string{"192.0.2.123"}}
	for _, id := range []string{"dns", "dns-stub-client", "dhcp", "time"} {
		s.Components = append(s.Components, Component{ID: id, State: "ready", Service: &p})
	}
	s.Seal()
	defaults, _, err := s.Proposals(Options{}, time.Now())
	if err != nil || len(defaults) != 2 {
		t.Fatalf("DHCP defaults: %v %v", defaults, err)
	}
	for _, r := range defaults {
		if r.Preset.Component != "dhcp" {
			t.Fatal("unexpected default", r)
		}
	}
	optional, _, err := s.Proposals(Options{ServiceAssistance: true}, time.Now())
	if err != nil || len(optional) != 5 {
		t.Fatalf("optional plan: %v %v", optional, err)
	}
	for _, r := range optional {
		if r.Filter.TargetsLoopback() {
			t.Fatal("new localhost permission", r)
		}
	}
	legacy, _, _ := s.Rules(Options{}, time.Now())
	stubs := 0
	for _, r := range legacy {
		if r.Filter.TargetsLoopback() {
			stubs++
			if !s.EntryActive(r) {
				t.Fatal("existing localhost permission invalidated")
			}
		}
	}
	if stubs != 4 {
		t.Fatal("legacy fixture missing stub rules", stubs)
	}
	if (Options{}).Equal(Options{ServiceAssistance: true}) {
		t.Fatal("review does not bind assistance option")
	}
}

package policy_test

import (
	"encoding/json"
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"flowgate/internal/store"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEssentialDNSReviewFiltersAndPersistence(t *testing.T) {
	path := os.Getenv("FLOWGATE_ESSENTIAL_PLAN")
	if path == "" {
		t.Skip("generated review-only fixture required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var plan struct {
		Identity identity.Process `json:"identity"`
		Items    []struct {
			Rule policy.Rule `json:"candidate_rule"`
		} `json:"items"`
	}
	if err = json.Unmarshal(data, &plan); err != nil {
		t.Fatal(err)
	}
	rules := []policy.Rule{}
	for _, item := range plan.Items {
		if err = item.Rule.Validate(); err != nil {
			t.Fatal(err)
		}
		rules = append(rules, item.Rule)
	}
	db, err := store.Open(filepath.Join(t.TempDir(), "rules.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = db.Replace(rules); err != nil {
		t.Fatal(err)
	}
	loaded, err := db.Load()
	if err != nil || len(loaded) != len(rules) {
		t.Fatal(err)
	}
	a := identity.Attribution{Application: &plan.Identity.Application, Owners: []identity.Process{plan.Identity}, VisibilityComplete: true}
	for _, rule := range loaded {
		f := identity.Flow{Protocol: rule.Filter.Protocol, Direction: "outgoing", Local: netip.MustParseAddrPort("127.0.0.1:45000"), Remote: netip.AddrPortFrom(netip.MustParseAddr(rule.Filter.RemoteAddress), 53)}
		if action, _, _ := policy.Evaluate(loaded, f, a, time.Now()); action != "allow" {
			t.Fatal("configured DNS not allowed", action)
		}
		for _, variant := range []string{"incoming", "other_service", "other_peer", "other_executable", "new_revision"} {
			g, b := f, a
			p := plan.Identity
			app := *a.Application
			b.Application = &app
			b.Owners = []identity.Process{p}
			switch variant {
			case "incoming":
				g.Direction = "incoming"
			case "other_service":
				g.Remote = netip.AddrPortFrom(g.Remote.Addr(), 443)
			case "other_peer":
				g.Remote = netip.MustParseAddrPort("198.51.100.10:53")
			case "other_executable":
				b.Application.Key = "unrelated-service"
				b.Owners[0].Application = *b.Application
			case "new_revision":
				b.Application.Revision = "changed"
				b.Owners[0].Application = *b.Application
			}
			if action, _, _ := policy.Evaluate(loaded, g, b, time.Now()); action == "allow" {
				t.Fatal("preset leaked to", variant)
			}
		}
	}
}

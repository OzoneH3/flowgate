package daemon

import (
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"net/netip"
	"testing"
	"time"
)

func migrationFixture(t *testing.T) (*Engine, policy.Rule, *identity.NetworkZones) {
	t.Helper()
	e := New(5 * time.Second)
	e.SaveRules = func([]policy.Rule) error { return nil }
	d := observedDraft("outgoing")
	d.Protocol = "*"
	d.RemoteAddress = "*"
	p, err := e.PreviewZoneRule(e.Generation, e.Zones.Revision, ZoneTarget{"local", "self"}, d, 1000, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	r, _, _, err := e.SaveZoneRule(e.Generation, e.Zones.Revision, p.Token, ZoneTarget{"local", "self"}, d, 1000, false)
	if err != nil {
		t.Fatal(err)
	}
	z := identity.AutomaticNetworkZones(e.Zones, identity.CollectNetwork())
	e.ZoneSource = func() identity.NetworkZones { return z }
	e.CurrentZones()
	return e, r, &z
}
func TestMigrationNeverImplicitAndReceiptSafe(t *testing.T) {
	e, r, z := migrationFixture(t)
	scope := z.Classify(netip.MustParseAddr("10.9.8.7"))
	if scope.Zone != "local" || scope.LegacyZone != "" {
		t.Fatal(scope)
	}
	if e.rules[0].Schema != 4 || e.rules[0].Filter.ZoneModel != "" {
		t.Fatal("startup silently migrated", e.rules)
	}
	p, err := e.PreviewZoneMigration(e.Generation, r.ID, &r.Version, z.Revision, 1000, false)
	if err != nil {
		t.Fatal(err)
	}
	if p.Rule.Schema != 6 || p.Rule.Version != r.Version+1 || p.Rule.ID != r.ID || p.Rule.Action != r.Action || p.Rule.Expires != r.Expires || len(p.AddedPrefixes) == 0 {
		t.Fatal(p)
	}
	if e.rules[0].Schema != 4 {
		t.Fatal("preview wrote rule")
	}
	if _, _, _, err = e.SaveZoneMigration(e.Generation, r.ID, &r.Version, z.Revision, p.Token, 1001, false); err == nil {
		t.Fatal("foreign token accepted")
	}
	saved, _, replay, err := e.SaveZoneMigration(e.Generation, r.ID, &r.Version, z.Revision, p.Token, 1000, false)
	if err != nil || replay {
		t.Fatal(err)
	}
	_, _, replay, err = e.SaveZoneMigration(e.Generation, r.ID, &r.Version, z.Revision, p.Token, 1000, false)
	if err != nil || !replay || len(e.rules) != 1 {
		t.Fatal("lost ACK duplicated", err)
	}
	if _, err = e.DeleteRule(e.Generation, saved.ID, &saved.Version, 1000, false); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = e.SaveZoneMigration(e.Generation, r.ID, &r.Version, z.Revision, p.Token, 1000, false); err == nil {
		t.Fatal("deleted migration replayed")
	}
}
func TestMigrationRejectsTopologyAndRuleChanges(t *testing.T) {
	e, r, z := migrationFixture(t)
	p, err := e.PreviewZoneMigration(e.Generation, r.ID, &r.Version, z.Revision, 1000, false)
	if err != nil {
		t.Fatal(err)
	}
	before := z.Revision
	z.Revision = "changed"
	e.CurrentZones()
	if _, _, _, err = e.SaveZoneMigration(e.Generation, r.ID, &r.Version, before, p.Token, 1000, false); err == nil {
		t.Fatal("stale topology saved")
	}
	z.Revision = before
	e.CurrentZones()
	e.rules[0].Version++
	if _, _, _, err = e.SaveZoneMigration(e.Generation, r.ID, &r.Version, before, p.Token, 1000, false); err == nil {
		t.Fatal("changed rule migrated")
	}
}
func TestNewZoneRulesBindAutomaticModel(t *testing.T) {
	e, _, z := migrationFixture(t)
	d := observedDraft("incoming")
	p, err := e.PreviewZoneRule(e.Generation, z.Revision, ZoneTarget{"internet", "self"}, d, 1000, false, nil)
	if err != nil || p.Rule.Schema != 6 || p.Rule.Filter.ZoneModel != identity.AutomaticZoneModel {
		t.Fatal(p, err)
	}
}

func TestAutomaticRevisionPreservesPendingAndFencesRemember(t *testing.T) {
	e, f, _, _ := fixture()
	e.Timeout = time.Minute
	e.SaveRules = func([]policy.Rule) error { return nil }
	z := identity.AutomaticNetworkZones(e.Zones, identity.CollectNetwork())
	e.ZoneSource = func() identity.NetworkZones { return z }
	v := e.Observe(f, "udp")
	p, err := e.PreviewDecision(e.Generation, v.ID, "allow", "application", "local", z.Revision, 1000, false)
	if err != nil {
		t.Fatal(err)
	}
	oldRevision := z.Revision
	z.Revision = "updated-network-generation"
	rows := e.List(1000, false)
	if len(rows) != 1 || rows[0].ID != v.ID || rows[0].Deadline != v.Deadline || rows[0].State != "awaiting-decision" {
		t.Fatal("pending replaced/deadline extended", rows)
	}
	if _, _, _, err = e.DecideReviewed(e.Generation, v.ID, "allow", "application", "local", oldRevision, p.Token, 1000, false); err == nil {
		t.Fatal("old network decision preview accepted")
	}
	if len(e.rules) != 0 {
		t.Fatal("stale preview saved permission")
	}
}

func TestMigrationNormalizesLegacyAnyWithoutChangingMeaning(t *testing.T) {
	e, r, z := migrationFixture(t)
	e.rules[0].Filter.RemoteAddress = ""
	p, err := e.PreviewZoneMigration(e.Generation, r.ID, &r.Version, z.Revision, 1000, false)
	if err != nil || p.Rule.Filter.RemoteAddress != "*" {
		t.Fatal(p, err)
	}
	saved, _, _, err := e.SaveZoneMigration(e.Generation, r.ID, &r.Version, z.Revision, p.Token, 1000, false)
	if err != nil || saved.ID != r.ID || saved.Filter.RemoteAddress != "*" {
		t.Fatal(saved, err)
	}
}

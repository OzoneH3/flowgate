package daemon

import (
	"encoding/json"
	"errors"
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"testing"
	"time"
)

func TestZonePreviewAuthorityReplayAndFailure(t *testing.T) {
	e := New(time.Second)
	now := time.Now()
	e.Now = func() time.Time { return now }
	e.SaveRules = func([]policy.Rule) error { return nil }
	d := observedDraft("incoming")
	d.Protocol = "*"
	d.RemoteAddress = "*"
	target := ZoneTarget{"local", "machine"}
	if _, err := e.PreviewZoneRule(e.Generation, e.Zones.Revision, target, d, 1000, false, nil); err == nil {
		t.Fatal("ordinary machine mutation")
	}
	target.Scope = "self"
	v, err := e.PreviewZoneRule(e.Generation, e.Zones.Revision, target, d, 1000, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if v.Rule.Filter.UID != 1000 || v.Rule.Filter.AllUIDs || !v.Rule.Filter.AllPrograms || v.Rule.Filter.Application != "" {
		t.Fatal(v)
	}
	bad := d
	bad.Action = "allow"
	if _, _, _, err = e.SaveZoneRule(e.Generation, e.Zones.Revision, v.Token, target, bad, 1000, false); err == nil {
		t.Fatal("draft mismatch")
	}
	if _, _, _, err = e.SaveZoneRule(e.Generation, "old", v.Token, target, d, 1000, false); err == nil {
		t.Fatal("zone mismatch")
	}
	e.SaveRules = func([]policy.Rule) error { return errors.New("disk") }
	if _, _, _, err = e.SaveZoneRule(e.Generation, e.Zones.Revision, v.Token, target, d, 1000, false); err == nil || len(e.rules) != 0 {
		t.Fatal("persistence failure published")
	}
	e.SaveRules = func([]policy.Rule) error { return nil }
	r, _, replay, err := e.SaveZoneRule(e.Generation, e.Zones.Revision, v.Token, target, d, 1000, false)
	if err != nil || replay {
		t.Fatal(err)
	}
	_, _, replay, err = e.SaveZoneRule(e.Generation, e.Zones.Revision, v.Token, target, d, 1000, false)
	if err != nil || !replay || len(e.rules) != 1 {
		t.Fatal("duplicate replay")
	}
	c := r
	c.Action = "allow"
	edited, _, err := e.EditRule(r.ID, "", &r.Version, c, 1000, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = e.SaveZoneRule(e.Generation, e.Zones.Revision, v.Token, target, d, 1000, false); err == nil {
		t.Fatal("oldreceipt after edit")
	}
	if _, err = e.DeleteRule(e.Generation, r.ID, &r.Version, 1000, false); err == nil {
		t.Fatal("stale delete")
	}
	if _, err = e.DeleteRule(e.Generation, r.ID, &edited.Version, 1000, false); err != nil {
		t.Fatal(err)
	}
	v, err = e.PreviewZoneRule(e.Generation, e.Zones.Revision, target, d, 1000, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(31 * time.Second)
	if _, _, _, err = e.SaveZoneRule(e.Generation, e.Zones.Revision, v.Token, target, d, 1000, false); err == nil {
		t.Fatal("expired preview")
	}
	// Administrator machine rules cannot be modified by UID0-shaped ordinary role.
	target.Scope = "machine"
	v, err = e.PreviewZoneRule(e.Generation, e.Zones.Revision, target, d, 0, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	r, _, _, err = e.SaveZoneRule(e.Generation, e.Zones.Revision, v.Token, target, d, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.DeleteRule(e.Generation, r.ID, &r.Version, 0, false); err == nil {
		t.Fatal("ordinary global delete")
	}
	c = r
	c.Filter.AllUIDs = false
	if _, _, err = e.EditRule(r.ID, "", &r.Version, c, 0, true, true); err == nil {
		t.Fatal("global scope lost")
	}
}
func TestZoneAPIAndObservedBinding(t *testing.T) {
	a, _, _, _ := observedAPI(t)
	d := observedDraft("incoming")
	d.NetworkZone = "local"
	d.ZoneRevision = a.e.Zones.Revision
	pv := requirePreview(t, a, d)
	if pv.Rule.Schema != 4 || pv.Rule.Filter.NetworkZone != "local" {
		t.Fatal(pv)
	}
	sv := callResponse(a.path, saveRequest(a, pv, d))
	if sv.Error != "" {
		t.Fatal(sv.Error)
	}
	q := Request{Version: 1, Operation: "zone-rule-preview", Generation: a.e.Generation, ZoneRevision: a.e.Zones.Revision, ZoneTarget: &ZoneTarget{"internet", "self"}, ObservedDraft: func() *ObservedDraft { x := observedDraft("outgoing"); return &x }()}
	r := callResponse(a.path, q)
	if r.Error != "" || r.ZonePreview == nil || r.NetworkZones == nil {
		t.Fatalf("%+v", r)
	}
	l, err := Serve(a.path+".monitor", a.e, true)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	r = callResponse(a.path+".monitor", q)
	if r.ErrorCode != "read_only" {
		t.Fatal(r)
	}
	view, err := a.e.PolicyView(a.e.Generation, "", 1000, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(view.Zones) != 2 {
		t.Fatal("zone views missing")
	}
	_ = identity.DefaultNetworkZones()
}

func TestZoneSQLiteRestartAndDefinitionBinding(t *testing.T) {
	a, _, _, _ := observedAPI(t)
	d := observedDraft("incoming")
	target := ZoneTarget{"internet", "self"}
	v, err := a.e.PreviewZoneRule(a.e.Generation, a.e.Zones.Revision, target, d, 1000, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	r, _, _, err := a.e.SaveZoneRule(a.e.Generation, a.e.Zones.Revision, v.Token, target, d, 1000, false)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := a.s.Load()
	if err != nil {
		t.Fatal(err)
	}
	next := New(time.Second)
	if err = next.SetRules(stored); err != nil {
		t.Fatal(err)
	}
	beforeJSON, _ := json.Marshal(r)
	afterJSON, _ := json.Marshal(next.Rules(1000, false)[0])
	if len(next.Rules(1000, false)) != 1 || string(beforeJSON) != string(afterJSON) {
		t.Fatal("schema4 document changed on restart")
	}
	if _, _, _, err = next.SaveZoneRule(a.e.Generation, a.e.Zones.Revision, v.Token, target, d, 1000, false); err == nil {
		t.Fatal("old generation replayed")
	}
	q := Request{Version: 1, Operation: "rule-preview", Generation: a.e.Generation, ID: r.ID, ExpectedVersion: &r.Version, Rule: &r}
	if response := callResponse(a.path, q); response.ErrorCode != "zone_conflict" {
		t.Fatal("missing definition accepted", response)
	}
}

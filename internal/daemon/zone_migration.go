package daemon

import (
	"encoding/json"
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"fmt"
	"net/netip"
	"time"
)

type ZoneMigrationSample struct {
	Address string `json:"address"`
	OldZone string `json:"old_zone"`
	NewZone string `json:"new_zone"`
	Reason  string `json:"reason"`
}
type ZoneMigrationPreview struct {
	Token           string                `json:"token"`
	ExpiresAt       time.Time             `json:"expires_at"`
	RuleID          string                `json:"rule_id"`
	OldVersion      uint64                `json:"old_version"`
	ZoneRevision    string                `json:"zone_revision"`
	OldModel        string                `json:"old_model"`
	NewModel        string                `json:"new_model"`
	OldPrefixes     []string              `json:"old_prefixes"`
	NewPrefixes     []string              `json:"new_prefixes"`
	AddedPrefixes   []string              `json:"added_prefixes"`
	RemovedPrefixes []string              `json:"removed_prefixes"`
	Samples         []ZoneMigrationSample `json:"samples"`
	ScopePreview    string                `json:"scope_preview"`
	Rule            policy.Rule           `json:"rule"`
}
type zoneMigration struct {
	View     ZoneMigrationPreview
	UID      uint32
	Admin    bool
	Saved    bool
	Until    time.Time
	Original policy.Rule
}

func (e *Engine) PreviewZoneMigration(generation, id string, expected *uint64, revision string, uid uint32, admin bool) (ZoneMigrationPreview, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.refreshZonesLocked()
	fail := func(code, text string) (ZoneMigrationPreview, error) {
		return ZoneMigrationPreview{}, mutationError(code, text)
	}
	if err := e.checkCreationLocked(generation); err != nil {
		return ZoneMigrationPreview{}, err
	}
	if e.Zones.Model != identity.AutomaticZoneModel {
		return fail("unavailable", "Automatic zones are not enabled")
	}
	if revision == "" || revision != e.Zones.Revision {
		return fail("zone_conflict", "Network classification changed; review migration again")
	}
	var old *policy.Rule
	for _, r := range e.rules {
		if r.ID == id {
			c := r
			old = &c
			break
		}
	}
	if old == nil {
		return fail("not_found", "Rule no longer exists")
	}
	if !admin && (old.Filter.AllUIDs || old.Filter.UID != uid) {
		return fail("forbidden", "Rule belongs to another principal")
	}
	if expected == nil || *expected != old.Version {
		return fail("version_conflict", "Rule version changed; reload")
	}
	if old.Schema != 4 || old.Filter.NetworkZone == "" || old.Filter.ZoneModel != "" || old.Preset != nil {
		return fail("invalid_request", "Only legacy configured-zone rules require migration")
	}
	if old.Version == ^uint64(0) {
		return fail("limit_exceeded", "Rule version exhausted")
	}
	if !old.Filter.Process.IsZero() && !old.Disabled && e.targetStateLocked(*old).State != "active" {
		return fail("target_inactive", "Process target ended; do not migrate an active permission")
	}
	candidate := *old
	// Stored legacy empty peer constraints mean Any; make that meaning explicit
	// before strict creation review without broadening the old predicate.
	candidate.Filter = canonicalFilter(candidate.Filter)
	candidate.Schema = 6
	candidate.Version++
	candidate.Filter.ZoneModel = identity.AutomaticZoneModel
	if _, _, err := e.reviewRuleLocked(candidate, e.Now(), true); err != nil {
		return fail("policy_conflict", err.Error())
	}
	legacy := e.Zones.Legacy()
	before, after, added, removed, err := identity.ZoneCoverage(legacy, e.Zones, old.Filter.NetworkZone)
	if err != nil {
		return fail("limit_exceeded", err.Error())
	}
	v := ZoneMigrationPreview{Token: randomID(), ExpiresAt: e.Now().Add(30 * time.Second), RuleID: id, OldVersion: old.Version, ZoneRevision: revision, OldModel: legacy.Model, NewModel: e.Zones.Model, OldPrefixes: before, NewPrefixes: after, AddedPrefixes: added, RemovedPrefixes: removed, Rule: candidate, Samples: []ZoneMigrationSample{}}
	peers := []string{"127.0.0.1", "10.1.2.3", "192.168.1.2", "100.101.2.3", "169.254.1.2", "1.1.1.1", "::1", "fe80::1", "fd7a:115c:a1e0::1", "2001:4860:4860::8888", "224.0.0.251", "ff02::1", "192.0.2.1"}
	for _, ip := range peers {
		a := netip.MustParseAddr(ip)
		b, n := legacy.Classify(a), e.Zones.Classify(a)
		v.Samples = append(v.Samples, ZoneMigrationSample{ip, b.Zone, n.Zone, n.Reason})
	}
	v.ScopePreview = fmt.Sprintf("Migrate rule %s version %d to %d. %s. Current %s coverage: %d added CIDRs, %d removed CIDRs. Old identity, action, principal, direction, ports and absolute expiry remain unchanged. Automatic scope follows future interface/address/route changes and versioned IANA registry updates. Local is not trusted and does not grant permission by itself. Review exact added/removed coverage before confirming. Registry %s; definition %s.", id, old.Version, candidate.Version, RuleSentence(candidate), old.Filter.NetworkZone, len(added), len(removed), e.Zones.RegistryVersion, revision)
	if e.zoneMigrations == nil {
		e.zoneMigrations = map[string]*zoneMigration{}
	}
	own := 0
	for k, p := range e.zoneMigrations {
		if !e.Now().Before(p.Until) {
			delete(e.zoneMigrations, k)
		} else if p.UID == uid {
			own++
		}
	}
	if own >= 16 || len(e.zoneMigrations) >= 256 {
		return fail("limit_exceeded", "Migration preview capacity reached")
	}
	e.zoneMigrations[v.Token] = &zoneMigration{View: v, UID: uid, Admin: admin, Until: v.ExpiresAt, Original: *old}
	return v, nil
}
func (e *Engine) SaveZoneMigration(generation, id string, expected *uint64, revision, token string, uid uint32, admin bool) (policy.Rule, string, bool, error) {
	e.mu.Lock()
	defer e.unlockAndSettle()
	e.refreshZonesLocked()
	fail := func(code, text string) (policy.Rule, string, bool, error) {
		return policy.Rule{}, "", false, mutationError(code, text)
	}
	if err := e.checkCreationLocked(generation); err != nil {
		return policy.Rule{}, "", false, err
	}
	p := e.zoneMigrations[token]
	if p == nil || p.UID != uid || p.Admin != admin || !e.Now().Before(p.Until) {
		return fail("preview_expired", "Preview unavailable; reconcile rule ID/version before trying again")
	}
	if id != p.View.RuleID || expected == nil || *expected != p.View.OldVersion || revision != p.View.ZoneRevision {
		return fail("preview_mismatch", "Migration target/version/revision changed")
	}
	index := -1
	for i, r := range e.rules {
		if r.ID == id {
			index = i
			break
		}
	}
	if index < 0 {
		return fail("replay_conflict", "Rule was deleted; no migration was retried")
	}
	current := e.rules[index]
	if p.Saved {
		a, _ := json.Marshal(current)
		b, _ := json.Marshal(p.View.Rule)
		if string(a) != string(b) {
			return fail("replay_conflict", "Completed migration rule changed; inspect inventory")
		}
		return current, p.View.ScopePreview, true, nil
	}
	if revision != e.Zones.Revision {
		return fail("zone_conflict", "Network changed after migration preview; review again")
	}
	a, _ := json.Marshal(current)
	b, _ := json.Marshal(p.Original)
	if string(a) != string(b) {
		return fail("version_conflict", "Original rule changed after preview")
	}
	if !current.Disabled && !current.Expires.IsZero() && !e.Now().Before(current.Expires) {
		return fail("preview_expired", "Original rule expired; migration never extends expiry")
	}
	if !current.Filter.Process.IsZero() && !current.Disabled {
		if err := e.verifyProcessEditLocked(current.Filter.Process); err != nil {
			return policy.Rule{}, "", false, err
		}
		if !e.Now().Before(p.Until) || (!current.Expires.IsZero() && !e.Now().Before(current.Expires)) {
			return fail("preview_expired", "Migration expired during process verification")
		}
	}
	if _, _, err := e.reviewRuleLocked(p.View.Rule, e.Now(), true); err != nil {
		return fail("policy_conflict", err.Error())
	}
	next := append([]policy.Rule{}, e.rules...)
	next[index] = p.View.Rule
	if err := e.publishRulesLocked(next); err != nil {
		return policy.Rule{}, "", false, err
	}
	p.Saved = true
	p.Until = e.Now().Add(5 * time.Minute)
	e.resetCachedLocked("explicit zone migration")
	return p.View.Rule, p.View.ScopePreview, false, nil
}

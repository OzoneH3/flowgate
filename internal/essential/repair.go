package essential

import (
	"flowgate/internal/policy"
	"reflect"
	"time"
)

// RepairMigratedRule repairs derived metadata only when a revision-format
// migration left an unedited rule's target hash stale. A fresh discovery must
// independently derive the identical permission. No new endpoint or executable
// revision is approved, and ordinary stale/edited rules remain inactive.
func (s Snapshot) RepairMigratedRule(old policy.Rule, now time.Time) (policy.Rule, bool) {
	if len(s.Failures) != 0 || !now.Before(s.ValidUntil) || !policy.UneditedPreset(old) || old.Validate() != nil || old.Version == ^uint64(0) {
		return old, false
	}
	target := old.Filter
	if target.InterfaceName != "" {
		target.InterfaceIndex = 0
	}
	if old.Preset.EntryID == Hash([]any{old.Preset.Component, target}) {
		return old, false
	}
	candidates, _, err := s.Rules(Options{Tailscale: true, TailscaleIncoming: true, TailscaleHTTP: true}, now)
	if err != nil {
		return old, false
	}
	for _, candidate := range candidates {
		// Compare all policy fields, ignoring only record bookkeeping and derived
		// preset metadata. Interface renumbering has its existing named scope.
		a, b := old, candidate
		a.ID, b.ID = "", ""
		a.Version, b.Version = 0, 0
		a.Created, b.Created = time.Time{}, time.Time{}
		a.Preset, b.Preset = nil, nil
		if a.Filter.InterfaceName != "" {
			a.Filter.InterfaceIndex = 0
		}
		if b.Filter.InterfaceName != "" {
			b.Filter.InterfaceIndex = 0
		}
		if old.Preset.Component != candidate.Preset.Component || !reflect.DeepEqual(a, b) {
			continue
		}
		repaired := old
		preset := *candidate.Preset
		repaired.Preset = &preset
		repaired.Version++
		repaired.Preset.Digest = policy.PresetDigest(repaired)
		return repaired, true
	}
	return old, false
}

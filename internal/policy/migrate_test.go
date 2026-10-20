package policy

import (
	"flowgate/internal/identity"
	"testing"
	"time"
)

// Rules saved with the earlier device-dependent stamp match the same unchanged
// file again after a reboot gave its btrfs subvolume another st_dev.
func TestMigrateRevisionsDropsDevice(t *testing.T) {
	if got := identity.MigrateStamp("53:12718026:289101384:179087601094049500:179087601094049500"); got != "12718026:289101384:179087601094049500:179087601094049500" {
		t.Fatal(got)
	}
	for _, keep := range []string{"12718026:289101384:1790876010940495:1790876010940495", "", "essential-v3", "a:b:c:d:e", "1:2:3"} {
		if identity.MigrateStamp(keep) != keep {
			t.Fatalf("must keep %q", keep)
		}
	}
	old := "52:7:100:5:6"
	r := Rule{ID: "user:x", Version: 1, Schema: 2, Action: "allow", Created: time.Unix(1, 0), Filter: Filter{Application: "k", Revision: old, UID: 1000, Direction: "outgoing", Protocol: "*"}}
	if !MigrateRevisions(&r) || r.Filter.Revision != "7:100:5:6" {
		t.Fatal(r.Filter.Revision)
	}
	if MigrateRevisions(&r) || r.Filter.Revision != "7:100:5:6" {
		t.Fatal("migration must be idempotent")
	}
	// Two rules for the same file differing only by device now share one revision.
	a, b := Rule{Filter: Filter{Revision: "52:7:100:5:6"}}, Rule{Filter: Filter{Revision: "53:7:100:5:6"}}
	MigrateRevisions(&a)
	MigrateRevisions(&b)
	if a.Filter.Revision != b.Filter.Revision {
		t.Fatal("same file, different device must merge")
	}
}

func TestMigrateRevisionsResealsUneditedPreset(t *testing.T) {
	r := Rule{ID: "preset:x", Version: 1, Schema: 5, Action: "allow", Created: time.Unix(1, 0),
		Preset: &Preset{Name: "essential-system-networking", Component: "dns", EntryID: "e", Revision: "essential-v3"},
		Filter: Filter{AllUIDs: true, Direction: "outgoing", Protocol: "udp", PeerService: PeerService{Application: "k", Revision: "36:9:10:11:12", UID: 0}}}
	r.Preset.Digest = PresetDigest(r)
	if !UneditedPreset(r) {
		t.Fatal("fixture")
	}
	MigrateRevisions(&r)
	if r.Filter.PeerService.Revision != "9:10:11:12" || !UneditedPreset(r) {
		t.Fatalf("migrated preset must stay unedited: %+v", r.Filter.PeerService)
	}
	// An edited preset stays edited (never silently re-sealed).
	e := r
	e.Preset = &Preset{Name: "essential-system-networking", Component: "dns", EntryID: "e", Revision: "essential-v3", Digest: "edited"}
	e.Filter.PeerService.Revision = "36:9:10:11:12"
	MigrateRevisions(&e)
	if UneditedPreset(e) {
		t.Fatal("edited preset was re-sealed")
	}
}

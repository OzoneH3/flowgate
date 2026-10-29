package identity

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// PermissionTarget states, before any decision, what each decision scope is
// enforced against TODAY. It is derived from the same identity fields the
// daemon matches (application key = UID + kind + prefix + executable path,
// revision = file stamp; For a while = PID + start ticks + boot). Launch
// provenance only names the context; it never widens or narrows a scope.
type PermissionTarget struct {
	Kind           string `json:"kind"` // helper | application | interpreter | unavailable
	Label          string `json:"label"`
	Once           string `json:"once"`
	ForAWhile      string `json:"for_a_while"`
	Remember       string `json:"remember"`
	SharedWithNote string `json:"shared_with_note,omitempty"`
	KeyBasis       string `json:"key_basis"`
	Prefix         string `json:"prefix,omitempty"`
}

var interpreterNames = []string{"python", "bash", "sh", "dash", "zsh", "fish", "perl", "ruby", "node", "java", "lua", "php", "mono", "dotnet"}

func isInterpreter(name string) bool {
	name = strings.ToLower(name)
	for _, n := range interpreterNames {
		if name == n || (strings.HasPrefix(name, n) && strings.Trim(strings.TrimPrefix(name, n), "0123456789.") == "") {
			return true
		}
	}
	return false
}

// ShortPrefix abbreviates a prefix for display: home becomes ~, long paths keep
// their last two components.
func ShortPrefix(p string) string {
	if p == "" {
		return ""
	}
	if home, err := os.UserHomeDir(); err == nil && home != "/" && strings.HasPrefix(p, home+"/") {
		p = "~" + strings.TrimPrefix(p, home)
	} else if i := strings.Index(p, "/home/"); i == 0 {
		if j := strings.Index(p[6:], "/"); j > 0 {
			p = "~" + p[6+j:]
		}
	}
	parts := strings.Split(p, "/")
	if len(p) > 48 && len(parts) > 3 {
		p = "…/" + strings.Join(parts[len(parts)-2:], "/")
	}
	return p
}

// principalOwner is the single process the attribution names (broker client or sole owner).
func (a Attribution) principalOwner() *Process {
	if a.Table != nil {
		return nil
	}
	if a.Association != nil {
		for i := range a.Owners {
			if a.Owners[i].PID == a.Association.ClientPID {
				return &a.Owners[i]
			}
		}
		return nil
	}
	if len(a.Owners) == 1 {
		return &a.Owners[0]
	}
	return nil
}

// DescribePermissionTarget mirrors the daemon's current keys; see docs/WINE.md
// "Launch provenance and permission scope".
func DescribePermissionTarget(a Attribution) *PermissionTarget {
	t := &PermissionTarget{Once: "This connection request only; no rule is saved"}
	app := a.Application
	owner := a.principalOwner()
	if app == nil || app.Key == "" || app.Revision == "" || a.Principal() == nil {
		t.Kind = "unavailable"
		t.Label = "No verified application identity"
		t.ForAWhile = "Unavailable: no verified application identity"
		t.Remember = "Unavailable: no verified application identity to bind a rule to"
		t.KeyBasis = "none"
		return t
	}
	uid := a.Principal().UID
	name := app.Name
	switch {
	case a.Table != nil:
		t.ForAWhile = "Unavailable: Windows application identified, but Linux requester generation is not established"
	case !a.VisibilityComplete:
		t.ForAWhile = "Unavailable: socket-holder visibility is incomplete"
	case len(a.Owners) != 1:
		t.ForAWhile = fmt.Sprintf("Unavailable: %d visible socket holders (needs exactly one owning process)", len(a.Owners))
	case owner == nil || owner.BootID == "":
		t.ForAWhile = "Unavailable: owner PID/start/boot identity missing"
	case owner.HolderWitness != "" || (owner.ThreadGroup != 0 && owner.ThreadGroup != owner.PID):
		t.ForAWhile = "Unavailable: worker or merged descriptor evidence does not establish process-instance authority"
	default:
		t.ForAWhile = fmt.Sprintf("This process instance only: %s PID %d, same direction; a relaunch or another %s process is not covered", name, owner.PID, name)
	}
	var prov *Provenance
	if owner != nil {
		prov = owner.Provenance
	}
	game := ""
	if prov != nil && prov.Evidence == "verified" && prov.Launch != nil && prov.Launch.Game != nil && prov.Launch.Game.Status == "verified-file" {
		game = prov.Launch.Game.Name
		if prov.Launch.Game.Title != "" {
			game = prov.Launch.Game.Title + " (" + prov.Launch.Game.Name + ")"
		}
	}
	if why := RuntimeRuleBlocked(app); why != "" {
		// A shared runtime whose hosted app is not verified: no application-wide rule.
		t.Kind = "runtime-unverified"
		t.KeyBasis = "none: application unverified"
		t.Label = fmt.Sprintf("%s runtime (application unverified)", name)
		t.Remember = "Unavailable: " + why
		t.ForAWhile = "Unavailable: hosted application execution is unverified; no process rule can be bound"
		if NativeProcessAuthority(a) {
			t.Remember = "This process only; ends on process exit or backend restart. Other processes and relaunches are not covered."
			t.ForAWhile = "This verified native process only, for the selected duration; no other process or relaunch is covered"
		}
		t.SharedWithNote = fmt.Sprintf("%s is the observed executable; the claimed bundle is not permission authority", app.Executable)
		return t
	}
	if BestEffortElectron(*app) {
		t.Kind = "application"
		t.Label = name + " (best-effort Electron match)"
		t.KeyBasis = "uid+runtime executable+canonical application entry; best-effort, not verified execution"
		t.Remember = fmt.Sprintf("%s (%s), UID %d; best-effort match survives relaunches at this entry with the same runtime path", name, app.Executable, uid)
		t.SharedWithNote = "Matching Electron network processes are covered; other application entries, users, runtimes and independent helpers remain separate. Manipulated launch/package evidence can impersonate this identity."
		return t
	}
	if app.Kind == "wine" {
		short := ShortPrefix(app.Prefix)
		t.Prefix = app.Prefix
		t.KeyBasis = "uid+wine+prefix+executable path; revision = file stamp"
		t.Label = fmt.Sprintf("%s in prefix %s", name, short)
		if a.Table != nil {
			t.Label = name + " · via wineserver"
		}
		t.Remember = fmt.Sprintf("%s (%s) in prefix %s, UID %d, saved application permissions follow verified program updates", name, app.Executable, short, uid)
		role := ""
		if prov != nil && prov.Evidence == "verified" {
			role = prov.Role
		}
		if role == "game" || a.Table != nil {
			t.Kind = "application"
			t.SharedWithNote = fmt.Sprintf("Any process running %s from this path in prefix %s is covered; another prefix or a changed file is not", name, short)
		} else {
			t.Kind = "helper"
			t.Label += " (shared by every game using this prefix)"
			note := fmt.Sprintf("Shared by every game using prefix %s: any program there running this %s file is covered", short, name)
			if game != "" {
				note += ", not only " + game
			}
			t.SharedWithNote = note + ". Another prefix or another Proton/Wine build (different file) is a different application"
		}
		return t
	}
	t.KeyBasis = "uid+executable path; revision = file stamp"
	if contentRevision(*app) {
		t.KeyBasis = "uid+verified runtime deployment path; revision = SHA-256 of executable content"
	}
	t.Remember = fmt.Sprintf("%s (%s), UID %d, saved application permissions follow verified program updates", name, app.KeyPath(), uid)
	switch {
	case isInterpreter(name):
		t.Kind = "interpreter"
		t.Label = fmt.Sprintf("%s interpreter (every script it runs)", name)
		script := ""
		if prov != nil && prov.Role == "launcher" && prov.Launch != nil {
			script = prov.Launch.LauncherName
		}
		t.SharedWithNote = fmt.Sprintf("Every program run by %s for UID %d is covered", app.KeyPath(), uid)
		if script != "" {
			t.SharedWithNote += ", not only " + script
		}
	case prov != nil && prov.Evidence == "verified" && prov.Role != "game":
		t.Kind = "helper"
		t.Label = fmt.Sprintf("%s (every process running %s)", name, filepath.Base(app.Executable))
		t.SharedWithNote = fmt.Sprintf("Any process running %s for UID %d is covered, in any launch or prefix", app.KeyPath(), uid)
		if game != "" {
			t.SharedWithNote += ", not only " + game
		}
	default:
		t.Kind = "application"
		t.Label = fmt.Sprintf("%s (every process running this executable)", name)
	}
	return t
}

// WithPermissionPresentation preserves a backend-derived label through an
// immutable list snapshot's JSON copy. It restores no resolver receipt and is
// never consulted by policy. Any serialized attribution change drops the label.
type permissionPresentation struct {
	target  PermissionTarget
	binding string
}

func (a Attribution) presentationBinding() string {
	type plain Attribution
	b, _ := json.Marshal(plain(a))
	return digest(string(b))
}
func (a Attribution) WithPermissionPresentation(target PermissionTarget) Attribution {
	a.presentationTarget = &permissionPresentation{target: target, binding: a.presentationBinding()}
	return a
}

// MarshalJSON adds the principal owner's launch provenance and the permission
// target, derived from the attribution's current fields at serialization, so
// wrappers that withdraw an application identity can never leave a stale target.
func (a Attribution) MarshalJSON() ([]byte, error) {
	type plain Attribution
	out := struct {
		plain
		Provenance       *Provenance       `json:"provenance,omitempty"`
		PermissionTarget *PermissionTarget `json:"permission_target,omitempty"`
	}{plain: plain(a)}
	if owner := a.principalOwner(); owner != nil {
		out.Provenance = owner.Provenance
	}
	if len(a.Owners) > 0 || a.Application != nil {
		out.PermissionTarget = DescribePermissionTarget(a)
		if p := a.presentationTarget; p != nil && p.binding == a.presentationBinding() {
			target := p.target
			out.PermissionTarget = &target
		}
	}
	return json.Marshal(out)
}

package daemon

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func fileStamp(t *testing.T, p string) (string, uint64, uint64, string) {
	t.Helper()
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	s := st.Sys().(*syscall.Stat_t)
	b, _ := os.ReadFile(p)
	h := sha256.Sum256(b)
	return fmt.Sprintf("%d:%d:%d:%d", s.Ino, st.Size(), st.ModTime().UnixNano(), s.Ctim.Nano()), uint64(s.Dev), s.Ino, hex.EncodeToString(h[:])
}

// sandboxApp is a native executable seen inside a per-instance mount
// namespace at nsPath, backed by the host file host.
func sandboxApp(t *testing.T, host, nsPath string, uid uint32) identity.Application {
	rev, _, _, _ := fileStamp(t, host)
	a := identity.Application{Kind: "native", Name: filepath.Base(nsPath), Executable: nsPath, HostExecutable: host, Revision: rev}
	a.Key = identity.ApplicationKey(uid, a)
	return a
}

func sandboxAttribution(app identity.Application, uid uint32, pid int, mountNS, fp string) identity.Attribution {
	o := identity.Process{PID: pid, Start: fmt.Sprint(pid * 10), UID: uid, MountNS: mountNS, Executable: app.Executable, ExecutableRevision: app.Revision, Application: app}
	return identity.Attribution{Application: &app, Owners: []identity.Process{o}, VisibilityComplete: true, Fingerprint: fp}
}

type sandboxEngine struct {
	*Engine
	f       identity.Flow
	a       *identity.Attribution
	now     *time.Time
	alive   *bool
	visible string // host path the capture proves; "" = sandbox-only
}

func newSandboxEngine(t *testing.T, a identity.Attribution, file, host string) *sandboxEngine {
	e, f, attr, now := fixture()
	e.Timeout = time.Minute
	e.SaveRules = func([]policy.Rule) error { return nil }
	*attr = a
	alive := true
	e.instanceRunning = func(int, string) bool { return alive }
	s := &sandboxEngine{Engine: e, f: f, a: attr, now: now, alive: &alive, visible: host}
	e.captureExecutable = func(o identity.Process, app identity.Application) (*identity.RetainedExecutable, error) {
		ev := identity.ExecutableEvidence{PID: o.PID, Start: o.Start, UID: o.UID, MountNS: o.MountNS, Path: o.Executable, Visibility: identity.VisibilitySandboxOnly, Reason: "no host-visible file (test sandbox tmpfs)", DigestState: "done"}
		var sum string
		ev.Stamp, ev.Dev, ev.Inode, sum = fileStamp(t, file)
		ev.SHA256 = sum
		if s.visible != "" {
			ev.Visibility, ev.HostPath, ev.HostSource, ev.Reason = identity.VisibilityHost, s.visible, "mountinfo", ""
		}
		return identity.RetainEvidence(ev), nil
	}
	return s
}

func errCode(err error) string {
	var m *RuleMutationError
	if errors.As(err, &m) {
		return m.Code
	}
	return ""
}

func (s *sandboxEngine) save(t *testing.T, id, action string) (policy.Rule, error) {
	p, err := s.PreviewRequestRule(s.Generation, id, action, "persistent", "any", s.Zones.Revision, 1000, false, appOnly())
	if err != nil {
		return policy.Rule{}, err
	}
	r, _, _, err := s.SaveRequestRule(s.Generation, p.Token, id, action, "persistent", "any", s.Zones.Revision, 1000, false, appOnly())
	return r, err
}

func TestSandboxRequestRuleAfterExitBindsVerifiedIdentity(t *testing.T) {
	dir := t.TempDir()
	host := filepath.Join(dir, "Steam/linux32/steamerrorreporter")
	os.MkdirAll(filepath.Dir(host), 0o755)
	os.WriteFile(host, []byte("reporter v1"), 0o755)
	app := sandboxApp(t, host, "/run/pv/inst-1/steamerrorreporter", 1000)
	first := sandboxAttribution(app, 1000, 42, "mnt:[1001]", "first")
	first.Owners[0].Provenance = &identity.Provenance{Evidence: "verified", Role: "helper", Launch: &identity.Launch{Kind: "steam", SteamAppID: "480"}}
	s := newSandboxEngine(t, first, host, host)
	v := s.Observe(s.f, "first")
	if v.State != "awaiting-decision" {
		t.Fatal(v)
	}
	// The sandboxed process exits; its request times out.
	*s.alive = false
	*s.a = identity.Attribution{Fingerprint: "gone"}
	*s.now = s.now.Add(2 * time.Minute)
	s.List(1000, false)
	s.mu.Lock()
	src := s.requestRuleSourceLocked(v.ID)
	s.mu.Unlock()
	if src == nil || src.ExecutableIdentity != "verified" || src.ProcessState != "ended" || src.Provenance == nil || src.Provenance.Launch.SteamAppID != "480" {
		t.Fatalf("retained source %+v", src)
	}
	rule, err := s.save(t, v.ID, "allow")
	if err != nil {
		t.Fatal("verified sandbox evidence refused:", err)
	}
	if rule.Filter.Application != app.Key || rule.Filter.Revision != app.Revision || rule.Filter.UID != 1000 || !rule.Filter.Process.IsZero() {
		t.Fatalf("rule not bound to the authoritative identity: %+v", rule.Filter)
	}
	if s.RetainedState(v.ID, v.Attribution.Fingerprint) != "drop" {
		t.Fatal("ended request approved")
	}
	// New process in a NEW mount namespace at another per-instance path, same
	// backing file: same key and revision, decided by the rule without prompt.
	relaunch := sandboxApp(t, host, "/run/pv/inst-2/steamerrorreporter", 1000)
	if relaunch.Key != app.Key {
		t.Fatal("key depends on the per-instance namespace path")
	}
	*s.a = sandboxAttribution(relaunch, 1000, 77, "mnt:[2002]", "relaunch")
	if n := s.Observe(s.f, "relaunch"); n.State != "allowed" || n.Rule != rule.ID {
		t.Fatal("relaunch in a new sandbox not matched", n)
	}
	// Different UID, same file: not covered.
	other := sandboxApp(t, host, "/run/pv/inst-3/steamerrorreporter", 1001)
	*s.a = sandboxAttribution(other, 1001, 78, "mnt:[2003]", "uid")
	if n := s.Observe(s.f, "uid"); n.State != "awaiting-decision" {
		t.Fatal("different UID inherited the rule", n)
	}
	// Sibling sandbox running a different executable with the same name.
	sib := filepath.Join(dir, "Other/linux32/steamerrorreporter")
	os.MkdirAll(filepath.Dir(sib), 0o755)
	os.WriteFile(sib, []byte("another program"), 0o755)
	sibling := sandboxApp(t, sib, "/run/pv/inst-1/steamerrorreporter", 1000)
	*s.a = sandboxAttribution(sibling, 1000, 79, "mnt:[2004]", "sibling")
	if n := s.Observe(s.f, "sibling"); n.State != "awaiting-decision" {
		t.Fatal("sibling executable inherited the rule", n)
	}
	// An updated file at the same verified host identity inherits saved program scope.
	tmp := host + ".new"
	os.WriteFile(tmp, []byte("reporter v2"), 0o755)
	os.Rename(tmp, host)
	replaced := sandboxApp(t, host, "/run/pv/inst-5/steamerrorreporter", 1000)
	if replaced.Key != app.Key || replaced.Revision == app.Revision {
		t.Fatal("fixture")
	}
	*s.a = sandboxAttribution(replaced, 1000, 80, "mnt:[2005]", "replaced")
	if n := s.Observe(s.f, "replaced"); n.State != "allowed" {
		t.Fatal("updated verified program lost saved permissions", n)
	}
}

func TestSandboxRequestRuleRefusesChangedBackingFile(t *testing.T) {
	dir := t.TempDir()
	host := filepath.Join(dir, "app")
	os.WriteFile(host, []byte("one"), 0o755)
	app := sandboxApp(t, host, "/run/pv/a/app", 1000)
	s := newSandboxEngine(t, sandboxAttribution(app, 1000, 42, "mnt:[1]", "x"), host, host)
	v := s.Observe(s.f, "x")
	*s.alive = false
	*s.a = identity.Attribution{Fingerprint: "gone"}
	*s.now = s.now.Add(2 * time.Minute)
	f, _ := os.OpenFile(host, os.O_APPEND|os.O_WRONLY, 0)
	f.Write([]byte("modified"))
	f.Close()
	if _, err := s.save(t, v.ID, "allow"); errCode(err) != "executable_changed" || !strings.Contains(err.Error(), "modified") {
		t.Fatal("modified backing file accepted:", err)
	}
	if len(s.rules) != 0 {
		t.Fatal(s.rules)
	}
}

func TestSandboxOnlyRequestRuleIsUnverifiable(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "app")
	os.WriteFile(file, []byte("tmpfs"), 0o755)
	app := sandboxApp(t, file, "/tmp/pv/app", 1000)
	app.HostExecutable = ""
	app.Key = identity.ApplicationKey(1000, app)
	s := newSandboxEngine(t, sandboxAttribution(app, 1000, 42, "mnt:[1]", "x"), file, "")
	v := s.Observe(s.f, "x")
	*s.alive = false
	*s.a = identity.Attribution{Fingerprint: "gone"}
	*s.now = s.now.Add(2 * time.Minute)
	s.mu.Lock()
	src := s.requestRuleSourceLocked(v.ID)
	s.mu.Unlock()
	if src.ExecutableIdentity != identity.VisibilitySandboxOnly {
		t.Fatal(src)
	}
	_, err := s.save(t, v.ID, "allow")
	if errCode(err) != identity.CodeIdentityUnverifiable || !strings.Contains(err.Error(), identityUnverifiableHint) || !strings.Contains(err.Error(), "/tmp/pv/app") || !strings.Contains(err.Error(), "mountns") {
		t.Fatal("sandbox-only executable not refused precisely:", err)
	}
	// No evidence at all (capture failed) from another mount namespace: same code.
	s2 := newSandboxEngine(t, sandboxAttribution(app, 1000, 43, "mnt:[2]", "y"), file, "")
	s2.captureExecutable = func(identity.Process, identity.Application) (*identity.RetainedExecutable, error) {
		return nil, errors.New("executable unreadable")
	}
	v2 := s2.Observe(s2.f, "y")
	*s2.alive = false
	*s2.a = identity.Attribution{Fingerprint: "gone"}
	if _, err := s2.save(t, v2.ID, "allow"); errCode(err) != identity.CodeIdentityUnverifiable || !strings.Contains(err.Error(), "executable unreadable") {
		t.Fatal(err)
	}
	// A dead process still never gets a For a while lease.
	if _, _, err := s.ForAWhileFromRequest(s.Generation, v.ID, "allow", 0, 1000, false); err == nil {
		t.Fatal("lease for an exited process")
	}
}

// Real capture of this test process: the executable reference is closed
// once the digest is known, and evidence is released with the record.
func TestRequestRuleRealCaptureReleasesReferences(t *testing.T) {
	p, err := identity.Inspect(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	base := identity.OpenExecutableReferences()
	e, f, a, now := fixture()
	e.Timeout = time.Minute
	e.SaveRules = func([]policy.Rule) error { return nil }
	e.instanceRunning = func(int, string) bool { return false }
	*a = identity.Attribution{Application: &p.Application, Owners: []identity.Process{p}, VisibilityComplete: true, Fingerprint: "self"}
	v := e.Observe(f, "self")
	e.mu.Lock()
	r := e.requestRules[v.ID]
	e.mu.Unlock()
	if r == nil || r.Exe == nil {
		t.Fatal("no evidence captured", r)
	}
	if !r.Exe.Wait(30 * time.Second) {
		t.Fatal("digest timeout")
	}
	ev := r.Exe.Evidence()
	if ev.SHA256 == "" || ev.HostSource != "same-path" || r.Exe.HeldReference() || identity.OpenExecutableReferences() != base {
		t.Fatalf("evidence %+v refs %d/%d", ev, identity.OpenExecutableReferences(), base)
	}
	*a = identity.Attribution{Fingerprint: "gone"}
	*now = now.Add(2 * time.Minute)
	p2, err := e.PreviewRequestRule(e.Generation, v.ID, "allow", "persistent", "any", e.Zones.Revision, p.UID, false, appOnly())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := e.SaveRequestRule(e.Generation, p2.Token, v.ID, "allow", "persistent", "any", e.Zones.Revision, p.UID, false, appOnly()); err != nil {
		t.Fatal(err)
	}
	// Retention expiry prunes the record.
	*now = now.Add(requestRuleRetention + time.Minute)
	e.List(p.UID, false)
	if len(e.requestRules) != 0 || identity.OpenExecutableReferences() != base {
		t.Fatal("retained record/reference not pruned", len(e.requestRules), identity.OpenExecutableReferences())
	}
}

func TestWineTableRetainsPEFileWithoutBrokerProcessPermission(t *testing.T) {
	for _, mode := range []string{"broker", "direct-client"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			pe := filepath.Join(dir, "alpha.exe")
			os.WriteFile(pe, []byte("verified PE"), 0644)
			app := sandboxApp(t, pe, pe, 1000)
			app.Kind, app.Prefix = "wine", dir
			app.Key = identity.ApplicationKey(1000, app)
			a := sandboxAttribution(app, 1000, 42, identity.SelfMountNS(), "table")
			a.Table = &identity.TableEvidence{BrokerPID: 42, BrokerStart: "420", Prefix: dir, UID: 1000}
			if mode == "direct-client" {
				a.Table.BrokerPID = 99
				a.Table.BrokerStart = "990"
				a.Table.DirectPID = 42
				a.Table.DirectStart = "420"
			}
			a.Owners[0].Application = identity.Application{Kind: "wine-unresolved", Key: "broker", Revision: "broker-revision"}
			s := newSandboxEngine(t, a, pe, pe)
			v := s.Observe(s.f, "held")
			s.mu.Lock()
			r := s.requestRules[v.ID]
			src := s.requestRuleSourceLocked(v.ID)
			s.mu.Unlock()
			if r == nil || r.Exe == nil || r.PID != 0 || r.Owner != nil || src.ExecutableIdentity != "verified" || src.ProcessLeaseAvailable {
				t.Fatalf("PE file must be retained without broker lease: request=%+v source=%+v", r, src)
			}
			*s.now = s.now.Add(2 * time.Minute)
			s.List(1000, false)
			retryFlow, _ := identity.ParseFlow("udp", "incoming", "127.0.0.1:80", "127.0.0.1:9001")
			otherPrefixFlow, _ := identity.ParseFlow("udp", "incoming", "127.0.0.1:80", "127.0.0.1:9002")
			otherAppFlow, _ := identity.ParseFlow("udp", "incoming", "127.0.0.1:80", "127.0.0.1:9003")
			otherPrefix := filepath.Join(dir, "other-prefix")
			if err := os.Mkdir(otherPrefix, 0700); err != nil {
				t.Fatal(err)
			}
			beta := filepath.Join(otherPrefix, "beta.exe")
			if err := os.WriteFile(beta, []byte("other verified PE"), 0644); err != nil {
				t.Fatal(err)
			}
			otherAttribution := func(other identity.Application, fp string) identity.Attribution {
				other.Prefix = otherPrefix
				other.Key = identity.ApplicationKey(1000, other)
				result := a
				result.Application, result.Fingerprint = &other, fp
				table := *a.Table
				table.Prefix = other.Prefix
				result.Table = &table
				return result
			}
			betaApp := sandboxApp(t, beta, beta, 1000)
			betaApp.Kind = "wine"
			otherApp := otherAttribution(betaApp, "other-image")
			other := otherAttribution(app, "other-prefix")
			s.Resolve = func(f identity.Flow) identity.Attribution {
				switch f.Remote.Port() {
				case 9002:
					return other
				case 9003:
					return otherApp
				default:
					return a
				}
			}
			retry := s.Observe(retryFlow, "retry")
			unrelated := s.Observe(otherPrefixFlow, "same-image-other-prefix")
			betaRequest := s.Observe(otherAppFlow, "other-image")
			for _, event := range []Event{retry, unrelated, betaRequest} {
				if event.State != "awaiting-decision" {
					t.Fatal(event)
				}
			}
			options := appOnly()
			options.DurationSeconds = 60
			preview, err := s.PreviewRequestRule(s.Generation, v.ID, "allow", "application", "any",
				s.Zones.Revision, 1000, false, options)
			if err != nil {
				t.Fatal(err)
			}
			rule, _, _, settled, err := s.SaveRequestRuleSettled(s.Generation, preview.Token, v.ID, "allow",
				"application", "any", s.Zones.Revision, 1000, false, options)
			if err != nil {
				t.Fatal(err)
			}
			if rule.Filter.Application != app.Key || !rule.Filter.Process.IsZero() ||
				!rule.Expires.Equal(s.now.Add(time.Minute)) {
				t.Fatal(rule)
			}
			if len(settled) != 1 || settled[0].ID != retry.ID || settled[0].Rule != rule.ID || settled[0].State != "allowed" {
				t.Fatalf("expected only the matching retry to settle: %+v", settled)
			}
			if s.RetainedState(v.ID, v.Attribution.Fingerprint) != "drop" {
				t.Fatal("ended request was released")
			}
			for _, event := range []Event{unrelated, betaRequest} {
				if s.RetainedState(event.ID, event.Attribution.Fingerprint) != "pending" {
					t.Fatalf("unrelated Wine request changed: %+v", event)
				}
			}
			future, _ := identity.ParseFlow("udp", "incoming", "127.0.0.1:80", "127.0.0.1:9004")
			if event := s.Observe(future, "later"); event.State != "allowed" || event.Rule != rule.ID {
				t.Fatalf("later matching connection prompted again: %+v", event)
			}
		})
	}
}

func TestRuntimeContentRuleSurvivesTemporaryHardlinkChurn(t *testing.T) {
	host := filepath.Join(t.TempDir(), "interpreter")
	os.WriteFile(host, []byte("verified runtime"), 0700)
	app := sandboxApp(t, host, "/usr/bin/interpreter", 1000)
	_, _, _, sum := fileStamp(t, host)
	app.Revision = "sha256:" + sum
	a := sandboxAttribution(app, 1000, 42, "mnt:[1001]", "first")
	s := newSandboxEngine(t, a, host, host)
	v := s.Observe(s.f, "first")
	*s.alive = false
	*s.a = identity.Attribution{Fingerprint: "gone"}
	*s.now = s.now.Add(2 * time.Minute)
	s.List(1000, false)
	// Same deployed file gains a temporary link before the user saves Remember.
	link := host + ".temporary"
	if err := os.Link(host, link); err != nil {
		t.Fatal(err)
	}
	rule, err := s.save(t, v.ID, "allow")
	if err != nil {
		t.Fatal(err)
	}
	os.Remove(link)
	*s.a = sandboxAttribution(app, 1000, 77, "mnt:[2002]", "next")
	if n := s.Observe(s.f, "next"); n.State != "allowed" || n.Rule != rule.ID {
		t.Fatal("remembered runtime reprompted", n)
	}
	other := app
	other.HostExecutable = host + ".other"
	other.Key = identity.ApplicationKey(1000, other)
	*s.a = sandboxAttribution(other, 1000, 78, "mnt:[2003]", "other")
	if n := s.Observe(s.f, "other"); n.State != "awaiting-decision" {
		t.Fatal("another deployment inherited rule", n)
	}
	*s.a = sandboxAttribution(app, 1001, 79, "mnt:[2004]", "uid")
	if n := s.Observe(s.f, "uid"); n.State != "awaiting-decision" {
		t.Fatal("another user inherited rule", n)
	}
	changed := app
	changed.Revision = "sha256:" + strings.Repeat("0", 64)
	*s.a = sandboxAttribution(changed, 1000, 80, "mnt:[2005]", "changed")
	if n := s.Observe(s.f, "changed"); n.State != "allowed" {
		t.Fatal("updated verified runtime lost saved program permissions", n)
	}
}

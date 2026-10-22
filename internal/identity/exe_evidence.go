package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Executable evidence retained for a prompted request while its process is
// alive, so an application rule can still be saved after the process exited —
// also when it ran in another mount namespace (Steam pressure-vessel, Flatpak,
// bubblewrap), where its namespace-local path means nothing on the host.
//
// Nothing here trusts a path string after exit. The evidence binds:
//   - the exact process generation (PID, start ticks, boot ID, UID),
//   - the executable file as opened through /proc/PID/exe (fstat device,
//     inode, size, mtime, ctime == the application revision stamp),
//   - a SHA-256 of that opened file (size-capped, computed once per stamp and
//     cached), and
//   - a host-visible backing path proven, while the process was alive, to be
//     the same device+inode (same path on the host, or a mount mapping from
//     /proc/PID/mountinfo to the daemon's own mounts). Without one the
//     executable is "sandbox-only" and can never be re-verified after exit.

const (
	// MaxExecutableDigestBytes caps the content digest of one executable.
	// Large single-file CLIs (codex ~290 MB, claude ~240 MB) must stay
	// re-verifiable after a sandboxed process exits; digests are cached per stamp.
	MaxExecutableDigestBytes = 1 << 30
	// maxRetainedExecutableRefs bounds open executable references (fds held
	// only until the digest of that file is known).
	maxRetainedExecutableRefs = 64
	// digestBudgetBytes bounds digest work per minute (cache hits are free).
	digestBudgetBytes = 2 << 30
	maxDigestCache    = 256
	maxHostPathCache  = 512
)

const (
	VisibilityHost        = "host"
	VisibilitySandboxOnly = "sandbox-only"
)

// ExecutableEvidence is the immutable result of a capture (digest fields are
// completed asynchronously; read it through RetainedExecutable.Evidence).
type ExecutableEvidence struct {
	PID     int    `json:"pid"`
	Start   string `json:"start_ticks"`
	BootID  string `json:"boot_id,omitempty"`
	UID     uint32 `json:"uid"`
	MountNS string `json:"mountns,omitempty"`
	// Path is the executable path as the process saw it (namespace-local).
	Path  string `json:"path"`
	Dev   uint64 `json:"device"`
	Inode uint64 `json:"inode"`
	// Stamp is dev:inode:size:mtime:ctime of the opened file; it equals the
	// application revision the request was attributed with.
	Stamp      string `json:"stamp"`
	Visibility string `json:"visibility"` // host | sandbox-only
	HostPath   string `json:"host_path,omitempty"`
	HostSource string `json:"host_source,omitempty"` // same-path | mountinfo
	Reason     string `json:"reason,omitempty"`      // why sandbox-only
	SHA256     string `json:"sha256,omitempty"`
	// DigestState: pending, done, too-large, skipped (budget) or failed.
	DigestState string    `json:"digest_state"`
	CapturedAt  time.Time `json:"captured_at"`
}

// RetainedExecutable owns the evidence and (until its digest is known) one
// open reference to the executable. Release is idempotent.
type RetainedExecutable struct {
	mu   sync.Mutex
	ev   ExecutableEvidence
	f    *os.File
	done chan struct{}
}

var openExecutableRefs atomic.Int64

// OpenExecutableReferences reports currently held executable references.
func OpenExecutableReferences() int64 { return openExecutableRefs.Load() }

// Evidence returns a snapshot.
func (r *RetainedExecutable) Evidence() ExecutableEvidence {
	if r == nil {
		return ExecutableEvidence{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.ev
}

// Wait waits (bounded) until the digest state is final.
func (r *RetainedExecutable) Wait(d time.Duration) bool {
	if r == nil || r.done == nil {
		return true
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-r.done:
		return true
	case <-t.C:
		return false
	}
}

// Release closes the held executable reference, if any. The evidence stays.
func (r *RetainedExecutable) Release() {
	if r == nil {
		return
	}
	r.mu.Lock()
	f := r.f
	r.f = nil
	if f != nil && r.ev.DigestState == "pending" {
		r.ev.DigestState = "failed"
	}
	r.mu.Unlock()
	if f != nil {
		f.Close()
		openExecutableRefs.Add(-1)
	}
}

// HeldReference reports whether this evidence still holds an open reference.
func (r *RetainedExecutable) HeldReference() bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.f != nil
}

// RetainEvidence wraps already-verified evidence (no open reference).
func RetainEvidence(ev ExecutableEvidence) *RetainedExecutable {
	d := make(chan struct{})
	close(d)
	return &RetainedExecutable{ev: ev, done: d}
}

// statStamp is a file revision: inode, size, modification and change time.
// The device number is deliberately excluded: btrfs assigns subvolume device
// numbers at mount time, so the same unchanged file gets another st_dev after
// a reboot and every rule for it would stop matching. Device identity is still
// checked separately where a file must be the very same one (devIno).
func statStamp(st os.FileInfo) string {
	s := st.Sys().(*syscall.Stat_t)
	return fmt.Sprintf("%d:%d:%d:%d", s.Ino, st.Size(), st.ModTime().UnixNano(), s.Ctim.Nano())
}

// MigrateStamp converts a stored revision of the earlier
// "dev:ino:size:mtime:ctime" form to the current device-independent form;
// any other value (already current, or not a file stamp) is returned unchanged.
func MigrateStamp(s string) string {
	f := strings.Split(s, ":")
	if len(f) != 5 {
		return s
	}
	for _, x := range f {
		if _, err := strconv.ParseInt(x, 10, 64); err != nil {
			if _, err := strconv.ParseUint(x, 10, 64); err != nil {
				return s
			}
		}
	}
	return strings.Join(f[1:], ":")
}

func devIno(st os.FileInfo) (uint64, uint64) {
	s := st.Sys().(*syscall.Stat_t)
	return uint64(s.Dev), s.Ino
}

// SelfMountNS is the daemon's own mount namespace.
func SelfMountNS() string { return link("/proc/self/ns/mnt") }

// CaptureExecutable retains verified executable evidence for the owning
// process of a prompted request. It must be called while the process is alive;
// it fails if the process instance or its executable changed since attribution.
func CaptureExecutable(owner Process, app Application) (*RetainedExecutable, error) {
	base := fmt.Sprintf("/proc/%d", owner.PID)
	var target, nsPath string
	switch app.Kind {
	case "native":
		target, nsPath = base+"/exe", owner.Executable
	case "wine":
		target, nsPath = base+"/root"+app.Executable, app.Executable
	default:
		return nil, fmt.Errorf("application kind %q has no verifiable executable", app.Kind)
	}
	alive := func() error {
		s, _, err := processStat(base)
		if err != nil || s != owner.Start {
			return fmt.Errorf("process %d is no longer the attributed instance", owner.PID)
		}
		return nil
	}
	resolve := func(p string, dev, ino uint64) (string, string, string) {
		return hostBackingPath(owner.PID, owner.MountNS, p, dev, ino)
	}
	return captureEvidence(target, nsPath, owner, app, alive, resolve)
}

func captureEvidence(target, nsPath string, owner Process, app Application, alive func() error, resolve func(string, uint64, uint64) (string, string, string)) (*RetainedExecutable, error) {
	if err := alive(); err != nil {
		return nil, err
	}
	f, err := os.Open(target)
	if err != nil {
		return nil, fmt.Errorf("executable unreadable: %v", err)
	}
	keep := false
	defer func() {
		if !keep {
			f.Close()
		}
	}()
	// The PID may have been reused between attribution and open.
	if err := alive(); err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return nil, fmt.Errorf("executable is not a regular file")
	}
	ev := ExecutableEvidence{PID: owner.PID, Start: owner.Start, BootID: owner.BootID, UID: owner.UID, MountNS: owner.MountNS, Path: nsPath, Stamp: statStamp(st), CapturedAt: time.Now()}
	ev.Dev, ev.Inode = devIno(st)
	if err := validateApplicationRevision(app, target, st); err != nil {
		return nil, fmt.Errorf("executable changed since attribution (revision %s, opened file %s)", app.Revision, ev.Stamp)
	}
	clean := strings.TrimSuffix(nsPath, " (deleted)")
	switch {
	case clean != nsPath || st.Sys().(*syscall.Stat_t).Nlink == 0:
		ev.Visibility, ev.Reason = VisibilitySandboxOnly, "executable was deleted while running"
	default:
		ev.HostPath, ev.HostSource, ev.Reason = resolve(clean, ev.Dev, ev.Inode)
		ev.Visibility = VisibilityHost
		if ev.HostPath == "" {
			ev.Visibility = VisibilitySandboxOnly
		}
	}
	r := &RetainedExecutable{ev: ev, done: make(chan struct{})}
	if d, ok := cachedDigest(ev.Stamp); ok {
		r.ev.SHA256, r.ev.DigestState = d, "done"
		close(r.done)
		return r, nil
	}
	if st.Size() > MaxExecutableDigestBytes {
		r.ev.DigestState = "too-large"
		close(r.done)
		return r, nil
	}
	if openExecutableRefs.Add(1) > maxRetainedExecutableRefs {
		openExecutableRefs.Add(-1)
		r.ev.DigestState = "skipped"
		close(r.done)
		return r, nil
	}
	keep = true
	r.f = f
	r.ev.DigestState = "pending"
	go r.digest(st.Size())
	return r, nil
}

var digestWorker = make(chan struct{}, 1)

func (r *RetainedExecutable) digest(size int64) {
	defer close(r.done)
	defer r.Release()
	digestWorker <- struct{}{}
	defer func() { <-digestWorker }()
	r.mu.Lock()
	f, stamp := r.f, r.ev.Stamp
	r.mu.Unlock()
	if f == nil {
		return
	}
	state, sum := "failed", ""
	if d, ok := cachedDigest(stamp); ok {
		state, sum = "done", d
	} else if !takeDigestBudget(size) {
		state = "skipped"
	} else if d, err := hashOpened(f, stamp); err == nil {
		state, sum = "done", d
		storeDigest(stamp, d)
	}
	r.mu.Lock()
	if r.ev.DigestState == "pending" {
		r.ev.DigestState, r.ev.SHA256 = state, sum
	}
	r.mu.Unlock()
}

// hashOpened digests an opened file and proves it unchanged while hashing.
func hashOpened(f *os.File, stamp string) (string, error) {
	st, err := f.Stat()
	if err != nil || statStamp(st) != stamp {
		return "", fmt.Errorf("file changed before hashing")
	}
	if st.Size() > MaxExecutableDigestBytes {
		return "", fmt.Errorf("executable larger than %d MiB", MaxExecutableDigestBytes>>20)
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.NewSectionReader(f, 0, st.Size())); err != nil {
		return "", err
	}
	if st2, err := f.Stat(); err != nil || statStamp(st2) != stamp {
		return "", fmt.Errorf("file changed while hashing")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

var digestCache = struct {
	sync.Mutex
	m          map[string]string
	order      []string
	windowFrom time.Time
	spent      int64
	computed   int
}{m: map[string]string{}}

func cachedDigest(stamp string) (string, bool) {
	digestCache.Lock()
	defer digestCache.Unlock()
	d, ok := digestCache.m[stamp]
	return d, ok
}

func storeDigest(stamp, d string) {
	digestCache.Lock()
	defer digestCache.Unlock()
	if _, ok := digestCache.m[stamp]; ok {
		return
	}
	digestCache.computed++
	if len(digestCache.order) >= maxDigestCache {
		delete(digestCache.m, digestCache.order[0])
		digestCache.order = digestCache.order[1:]
	}
	digestCache.m[stamp] = d
	digestCache.order = append(digestCache.order, stamp)
}

func takeDigestBudget(n int64) bool {
	digestCache.Lock()
	defer digestCache.Unlock()
	now := time.Now()
	if now.Sub(digestCache.windowFrom) > time.Minute {
		digestCache.windowFrom, digestCache.spent = now, 0
	}
	if digestCache.spent+n > digestBudgetBytes {
		return false
	}
	digestCache.spent += n
	return true
}

// digestsComputed reports how many digests were actually computed (tests).
func digestsComputed() int {
	digestCache.Lock()
	defer digestCache.Unlock()
	return digestCache.computed
}

// --- host-visible backing path ---------------------------------------------

type mountEntry struct{ dev, root, point string }

func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func parseMountinfo(s string) []mountEntry {
	var out []mountEntry
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		out = append(out, mountEntry{dev: f[2], root: unescapeMount(f[3]), point: unescapeMount(f[4])})
	}
	return out
}

// under reports whether p is base or inside it, and the remainder.
func under(p, base string) (string, bool) {
	if base == "/" {
		return p, strings.HasPrefix(p, "/")
	}
	if p == base {
		return "/", true
	}
	if strings.HasPrefix(p, base+"/") {
		return p[len(base):], true
	}
	return "", false
}

// mountCandidates maps a path inside a process's mount namespace to candidate
// host paths through the filesystem (device + root) backing it. Candidates are
// NOT proof: each must still match device and inode.
func mountCandidates(nsPath, procInfo, selfInfo string) []string {
	var best *mountEntry
	var rest string
	for _, m := range parseMountinfo(procInfo) {
		if r, ok := under(nsPath, m.point); ok && (best == nil || len(m.point) >= len(best.point)) {
			m := m
			best, rest = &m, r
		}
	}
	if best == nil {
		return nil
	}
	src := path.Join(best.root, rest)
	var out []string
	for _, m := range parseMountinfo(selfInfo) {
		if m.dev != best.dev {
			continue
		}
		if r, ok := under(src, m.root); ok {
			c := path.Join(m.point, r)
			out = append(out, c)
			if len(out) >= 16 {
				break
			}
		}
	}
	return out
}

func sameFile(p string, dev, ino uint64) bool {
	st, err := os.Stat(p)
	if err != nil || !st.Mode().IsRegular() {
		return false
	}
	d, i := devIno(st)
	return d == dev && i == ino
}

var hostPathCache = struct {
	sync.Mutex
	m map[string][3]string
}{m: map[string][3]string{}}

// hostBackingPath returns a host-visible path proven to be the same device and
// inode as the executable the process runs, or "" with the reason.
func hostBackingPath(pid int, mountNS, nsPath string, dev, ino uint64) (string, string, string) {
	if !path.IsAbs(nsPath) {
		return "", "", "executable path is not absolute"
	}
	if sameFile(nsPath, dev, ino) {
		return nsPath, "same-path", ""
	}
	key := fmt.Sprintf("%s|%s|%d|%d", mountNS, nsPath, dev, ino)
	hostPathCache.Lock()
	c, ok := hostPathCache.m[key]
	hostPathCache.Unlock()
	if ok && (c[0] == "" || sameFile(c[0], dev, ino)) {
		return c[0], c[1], c[2]
	}
	host, src, reason := "", "", ""
	procInfo := string(readBound(fmt.Sprintf("/proc/%d/mountinfo", pid), 1<<20))
	if procInfo == "" {
		reason = "process mount table unavailable"
	} else {
		for _, cand := range mountCandidates(nsPath, procInfo, string(readBound("/proc/self/mountinfo", 1<<20))) {
			if sameFile(cand, dev, ino) {
				if source := runtimeBackingSource(cand, dev, ino); source != "" {
					cand = source
				}
				host, src = cand, "mountinfo"
				break
			}
		}
		if host == "" {
			reason = fmt.Sprintf("no host-visible file has device %d inode %d (the executable lives only inside the sandbox mount namespace)", dev, ino)
		}
	}
	hostPathCache.Lock()
	if len(hostPathCache.m) >= maxHostPathCache {
		hostPathCache.m = map[string][3]string{}
	}
	hostPathCache.m[key] = [3]string{host, src, reason}
	hostPathCache.Unlock()
	return host, src, reason
}

// sandboxKeyPath: for a process in another mount namespace whose executable
// path is not the same file on the host, the application key is derived from
// the host-visible backing path (proven by device+inode) so every sandbox
// instance of the same file shares one application identity. Empty keeps the
// namespace-local path (same file on the host, or sandbox-only).
func sandboxKeyPath(pid int, mountNS, nsPath string, st os.FileInfo) string {
	if mountNS == "" || mountNS == SelfMountNS() || st == nil {
		return ""
	}
	dev, ino := devIno(st)
	host, _, _ := hostBackingPath(pid, mountNS, nsPath, dev, ino)
	if host == "" || host == nsPath {
		return ""
	}
	return host
}

// KeyPath is the path the application key is derived from.
func (a Application) KeyPath() string {
	if a.HostExecutable != "" {
		return a.HostExecutable
	}
	// A verified unlinked native image is still this program. Only Inspect's
	// inode link-count evidence grants this normalization; a linked file with
	// a literal " (deleted)" suffix remains a different program.
	if a.Kind == "native" && a.ExecutableStatus == "deleted" {
		return strings.TrimSuffix(a.Executable, " (deleted)")
	}
	return a.Executable
}

// ApplicationKey derives the application key (user, kind, prefix, key path).
func ApplicationKey(uid uint32, a Application) string {
	return digest(fmt.Sprintf("%d|%s|%s|%s", uid, a.Kind, a.Prefix, a.KeyPath()))
}

// --- verification after exit ----------------------------------------------

const (
	CodeIdentityUnverifiable = "identity_unverifiable"
	CodeExecutableChanged    = "executable_changed"
)

// RetainedError is a refusal with a stable code and field diagnostics.
type RetainedError struct {
	Code    string
	Reason  string
	Changes []BindingChange
}

func (e *RetainedError) Error() string {
	s := e.Reason
	for _, c := range e.Changes {
		s += fmt.Sprintf("; %s: %s → %s", c.Field, c.Before, c.After)
	}
	return s
}

func changed(code, reason string, changes ...BindingChange) error {
	return &RetainedError{Code: code, Reason: reason, Changes: changes}
}

// UnverifiableEvidence explains why no persistent identity exists.
func UnverifiableEvidence(mountNS string, ev *ExecutableEvidence, why string) error {
	c := []BindingChange{{Field: "mountns", Before: mountNS, After: "daemon " + SelfMountNS()}}
	if ev != nil {
		c = append(c, BindingChange{Field: "executable", Before: ev.Path, After: "not host-visible"})
		if ev.Stamp != "" {
			c = append(c, BindingChange{Field: "device_inode", Before: fmt.Sprintf("%d/%d", ev.Dev, ev.Inode), After: "no host path"})
		}
		if ev.Reason != "" {
			why = ev.Reason
		}
	}
	return changed(CodeIdentityUnverifiable, "The process ran in another mount namespace and exited; "+why, c...)
}

// VerifyRetainedEvidence re-validates retained evidence after the process may
// have exited, through the proven host-visible backing path: same device,
// inode, size, mtime, ctime and SHA-256 as captured. Never a path string alone.
func VerifyRetainedEvidence(a Application, uid uint32, ev ExecutableEvidence) error {
	if (a.Kind != "native" && a.Kind != "wine") || a.Key == "" || a.Revision == "" || a.Executable == "" {
		return changed(CodeIdentityUnverifiable, fmt.Sprintf("captured identity is not a verifiable executable (kind %q)", a.Kind))
	}
	if a.Key != ApplicationKey(uid, a) || ev.UID != uid {
		return changed(CodeExecutableChanged, "captured application key does not match its executable, prefix and user")
	}
	if (!contentRevision(a) && ev.Stamp != a.Revision) || (contentRevision(a) && "sha256:"+ev.SHA256 != a.Revision) {
		return changed(CodeExecutableChanged, "retained executable evidence differs from the request's revision", BindingChange{"revision", a.Revision, ev.Stamp})
	}
	if ev.Visibility != VisibilityHost || ev.HostPath == "" {
		return UnverifiableEvidence(ev.MountNS, &ev, "its executable has no host-visible backing file")
	}
	if a.HostExecutable != "" && a.HostExecutable != ev.HostPath {
		return changed(CodeExecutableChanged, "host backing path differs from the application identity", BindingChange{"host_executable", a.HostExecutable, ev.HostPath})
	}
	if ev.SHA256 == "" {
		return UnverifiableEvidence(ev.MountNS, nil, "the executable content digest was not retained ("+ev.DigestState+")")
	}
	p := ev.HostPath
	f, err := os.Open(p)
	if errors.Is(err, fs.ErrNotExist) {
		return changed(CodeExecutableChanged, fmt.Sprintf("executable %s no longer exists (deleted, moved or replaced)", p))
	}
	if err != nil {
		return changed(CodeExecutableChanged, fmt.Sprintf("executable %s cannot be inspected: %v", p, err))
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return changed(CodeExecutableChanged, fmt.Sprintf("%s is no longer a regular file", p))
	}
	now := statStamp(st)
	if dev, ino := devIno(st); dev != ev.Dev || ino != ev.Inode {
		return changed(CodeExecutableChanged, fmt.Sprintf("a different file now occupies %s (device/inode changed); the requesting executable is gone", p), BindingChange{"device_inode", fmt.Sprintf("%d/%d", ev.Dev, ev.Inode), fmt.Sprintf("%d/%d", dev, ino)})
	}
	if now != ev.Stamp && !contentRevision(a) {
		return changed(CodeExecutableChanged, fmt.Sprintf("%s was modified since the request (size, modification or change time differs)", p), BindingChange{"revision", ev.Stamp, now})
	}
	sum, ok := cachedDigest(now)
	if !ok {
		if sum, err = hashOpened(f, now); err != nil {
			return changed(CodeExecutableChanged, fmt.Sprintf("%s content cannot be verified: %v", p, err))
		}
		storeDigest(now, sum)
	}
	if sum != ev.SHA256 {
		return changed(CodeExecutableChanged, fmt.Sprintf("%s content differs from the requesting executable", p), BindingChange{"sha256", ev.SHA256, sum})
	}
	return nil
}

// VerifyInstanceExecutable proves the exact still-running instance executes
// the retained revision (sandbox-only executables while the process runs).
func VerifyInstanceExecutable(pid int, start string, a Application) error {
	base := fmt.Sprintf("/proc/%d", pid)
	target := base + "/exe"
	if a.Kind == "wine" {
		target = base + "/root" + a.Executable
	}
	s, _, err := processStat(base)
	if err != nil || s != start {
		return changed(CodeIdentityUnverifiable, "the process instance is no longer running")
	}
	now := stamp(target)
	if contentRevision(a) {
		now = runtimeContentRevision(target)
	}
	if s2, _, err := processStat(base); err != nil || s2 != start {
		return changed(CodeIdentityUnverifiable, "the process instance is no longer running")
	}
	if now != a.Revision {
		return changed(CodeExecutableChanged, "the running process now executes a different file", BindingChange{"revision", a.Revision, now})
	}
	return nil
}

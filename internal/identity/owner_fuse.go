package identity

// Owner-only FUSE mounts can refuse even root. Read their executable metadata
// in a separate, credential-dropped copy of this binary. Never change the
// policy daemon's credentials and never substitute a pathname for inode proof.
import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const OwnerExecutableHelper = "internal-owner-executable"

type ownerExeRequest struct {
	PID, TID                        int
	Start, GroupStart, Exe, MountNS string
	UID, GID                        uint32
	Groups                          []uint32
	Dev, Ino                        uint64
	Hash                            bool
}
type ownerExeReply struct {
	Stat   syscall.Stat_t
	Digest string
}
type ownerExeInfo struct{ stat syscall.Stat_t }

func (s ownerExeInfo) Name() string { return "exe" }
func (s ownerExeInfo) Size() int64  { return s.stat.Size }
func (s ownerExeInfo) Mode() os.FileMode {
	if s.stat.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return os.ModeIrregular
	}
	return os.FileMode(s.stat.Mode & 0777)
}
func (s ownerExeInfo) ModTime() time.Time { return time.Unix(s.stat.Mtim.Sec, s.stat.Mtim.Nsec) }
func (s ownerExeInfo) IsDir() bool        { return false }
func (s ownerExeInfo) Sys() any           { return &s.stat }

func procExeTarget(target string) (int, int, bool) {
	f := strings.Split(target, "/")
	var p, t string
	if len(f) == 4 && f[1] == "proc" && f[3] == "exe" {
		p = f[2]
		t = p
	} else if len(f) == 6 && f[1] == "proc" && f[3] == "task" && f[5] == "exe" {
		p = f[2]
		t = f[4]
	} else {
		return 0, 0, false
	}
	pid, e := strconv.Atoi(p)
	tid, e2 := strconv.Atoi(t)
	return pid, tid, e == nil && e2 == nil && pid > 0 && tid > 0 && strconv.Itoa(pid) == p && strconv.Itoa(tid) == t
}
func ownerCredentials(status string) (uint32, uint32, []uint32, error) {
	var uid, gid uint32
	var groups []uint32
	seen := map[string]bool{}
	for _, line := range strings.Split(status, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if f[0] != "Uid:" && f[0] != "Gid:" && f[0] != "Groups:" {
			continue
		}
		if seen[f[0]] {
			return 0, 0, nil, fmt.Errorf("duplicate credentials")
		}
		seen[f[0]] = true
		vals := []uint32{}
		for _, s := range f[1:] {
			n, e := strconv.ParseUint(s, 10, 32)
			if e != nil {
				return 0, 0, nil, e
			}
			vals = append(vals, uint32(n))
		}
		if f[0] == "Groups:" {
			if len(vals) > 256 {
				return 0, 0, nil, fmt.Errorf("too many groups")
			}
			groups = vals
			continue
		}
		if len(vals) != 4 || vals[0] != vals[1] || vals[0] != vals[2] || vals[0] != vals[3] || vals[0] == 0 {
			return 0, 0, nil, fmt.Errorf("mixed or root credentials")
		}
		if f[0] == "Uid:" {
			uid = vals[0]
		} else {
			gid = vals[0]
		}
	}
	if len(seen) != 3 {
		return 0, 0, nil, fmt.Errorf("incomplete credentials")
	}
	return uid, gid, groups, nil
}

// Longest mountpoint wins; mount source/fsname is never identity evidence.
func ownerFuseMount(info, exe string, uid, gid uint32) (string, bool) {
	best := ""
	ok := false
	id := ""
	for _, line := range strings.Split(info, "\n") {
		f := strings.Fields(line)
		sep := -1
		for i, s := range f {
			if s == "-" {
				sep = i
				break
			}
		}
		if sep < 6 || len(f) != sep+4 {
			continue
		}
		point := unescapeMount(f[4])
		if _, under := under(exe, point); !under || len(point) < len(best) {
			continue
		}
		best = point
		ok = false
		id = f[0]
		if !(f[sep+1] == "fuse" || strings.HasPrefix(f[sep+1], "fuse.")) {
			continue
		}
		opts := map[string]string{}
		for _, part := range strings.Split(f[sep+3], ",") {
			k, v, _ := strings.Cut(part, "=")
			opts[k] = v
		}
		if _, allow := opts["allow_other"]; allow {
			continue
		}
		ok = opts["user_id"] == strconv.FormatUint(uint64(uid), 10) && opts["group_id"] == strconv.FormatUint(uint64(gid), 10)
	}
	return id, ok
}
func mappedExecutable(info, exe string) (uint64, uint64, error) {
	var dev, ino uint64
	found := false
	for _, line := range strings.Split(info, "\n") {
		f := strings.Fields(line)
		if len(f) < 6 || strings.Join(f[5:], " ") != exe || !strings.Contains(f[1], "x") {
			continue
		}
		d := strings.Split(f[3], ":")
		if len(d) != 2 {
			return 0, 0, fmt.Errorf("bad mapping device")
		}
		major, e := strconv.ParseUint(d[0], 16, 32)
		minor, e2 := strconv.ParseUint(d[1], 16, 32)
		n, e3 := strconv.ParseUint(f[4], 10, 64)
		if e != nil || e2 != nil || e3 != nil || n == 0 {
			return 0, 0, fmt.Errorf("bad mapping identity")
		}
		v := unix.Mkdev(uint32(major), uint32(minor))
		if found && (dev != v || ino != n) {
			return 0, 0, fmt.Errorf("ambiguous executable mapping")
		}
		found = true
		dev = v
		ino = n
	}
	if !found {
		return 0, 0, fmt.Errorf("executable mapping unavailable")
	}
	return dev, ino, nil
}
func ownerExeAnchor(pid, tid int) (ownerExeRequest, error) {
	r := ownerExeRequest{PID: pid, TID: tid}
	base := fmt.Sprintf("/proc/%d/task/%d", pid, tid)
	var err error
	r.Start, _, err = processStat(base)
	if err != nil {
		return r, err
	}
	r.GroupStart, _, err = processStat(fmt.Sprintf("/proc/%d", pid))
	if err != nil {
		return r, err
	}
	r.Exe = link(base + "/exe")
	r.MountNS = link(base + "/ns/mnt")
	if !filepath.IsAbs(r.Exe) || strings.HasSuffix(r.Exe, " (deleted)") || r.MountNS == "" {
		return r, fmt.Errorf("unavailable or deleted executable")
	}
	r.UID, r.GID, r.Groups, err = ownerCredentials(string(readBound(base+"/status", 65536)))
	if err != nil {
		return r, err
	}
	if _, ok := ownerFuseMount(string(readBound(base+"/mountinfo", 1<<20)), r.Exe, r.UID, r.GID); !ok {
		return r, fmt.Errorf("not a verified owner-only FUSE mount")
	}
	r.Dev, r.Ino, err = mappedExecutable(string(readBound(base+"/maps", 16<<20)), r.Exe)
	return r, err
}
func sameOwnerExe(a, b ownerExeRequest) bool {
	a.Hash = false
	b.Hash = false
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

var ownerExeSlots = make(chan struct{}, 4)

// No metadata time cache: each fallback has fresh generation/mapping bookends.
func readOwnerExecutable(target string, hash bool) (ownerExeReply, error) {
	var reply ownerExeReply
	pid, tid, ok := procExeTarget(target)
	if !ok || os.Geteuid() != 0 {
		return reply, fmt.Errorf("not an eligible process executable")
	}
	select {
	case ownerExeSlots <- struct{}{}:
		defer func() { <-ownerExeSlots }()
	default:
		return reply, fmt.Errorf("owner executable helper capacity")
	}
	before, err := ownerExeAnchor(pid, tid)
	if err != nil {
		return reply, err
	}
	before.Hash = hash
	reply, err = runOwnerExe(before)
	if err != nil {
		return reply, err
	}
	after, err := ownerExeAnchor(pid, tid)
	if err != nil || !sameOwnerExe(before, after) {
		return reply, fmt.Errorf("owner executable changed during helper")
	}
	if uint64(reply.Stat.Dev) != before.Dev || reply.Stat.Ino != before.Ino || reply.Stat.Mode&syscall.S_IFMT != syscall.S_IFREG || reply.Stat.Size < 0 {
		return reply, fmt.Errorf("owner executable inode mismatch")
	}
	return reply, nil
}

type ownerBoundBuffer struct {
	bytes.Buffer
	max int
}

func (b *ownerBoundBuffer) Write(p []byte) (int, error) {
	if len(p) > b.max-b.Len() {
		return 0, fmt.Errorf("helper output limit")
	}
	return b.Buffer.Write(p)
}

var runOwnerExe = func(r ownerExeRequest) (ownerExeReply, error) {
	var reply ownerExeReply
	// Credential is applied by the fork/exec child, never in the daemon.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	raw, _ := json.Marshal(r)
	cmd := exec.CommandContext(ctx, "/proc/self/exe", OwnerExecutableHelper, string(raw))
	cmd.Env = []string{"LANG=C"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: r.UID, Gid: r.GID, Groups: r.Groups}, Unshareflags: syscall.CLONE_NEWNET, Pdeathsig: syscall.SIGKILL}
	out := &ownerBoundBuffer{max: 4096}
	stderr := &ownerBoundBuffer{max: 1024}
	cmd.Stdout = out
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return reply, fmt.Errorf("owner executable helper: %w", err)
	}
	dec := json.NewDecoder(&out.Buffer)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&reply); err != nil {
		return reply, err
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return reply, fmt.Errorf("extra helper output")
	}
	return reply, nil
}

func executableStat(target string) (os.FileInfo, error) {
	st, err := os.Stat(target)
	if err == nil || !errors.Is(err, os.ErrPermission) {
		return st, err
	}
	r, e := readOwnerExecutable(target, false)
	if e != nil {
		return nil, err
	}
	return ownerExeInfo{r.Stat}, nil
}

// RunOwnerExecutableHelper is an internal, read-only command. It cannot change
// policy and accepts only a pinned /proc task, never an arbitrary file path.
func RunOwnerExecutableHelper(args []string) error {
	if len(args) != 1 || len(args[0]) > 4096 {
		return fmt.Errorf("invalid helper request")
	}
	var r ownerExeRequest
	dec := json.NewDecoder(strings.NewReader(args[0]))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return err
	}
	var trailing any
	if dec.Decode(&trailing) != io.EOF {
		return fmt.Errorf("extra helper request")
	}
	if r.PID <= 0 || r.TID <= 0 || r.UID == 0 || r.GID == 0 || uint32(os.Getuid()) != r.UID || uint32(os.Geteuid()) != r.UID || uint32(os.Getgid()) != r.GID || uint32(os.Getegid()) != r.GID {
		return fmt.Errorf("helper credentials mismatch")
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return err
	}
	var hdr unix.CapUserHeader
	hdr.Version = unix.LINUX_CAPABILITY_VERSION_3
	data := [2]unix.CapUserData{}
	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return err
	}
	before, err := ownerExeAnchor(r.PID, r.TID)
	if err != nil || !sameOwnerExe(r, before) {
		return fmt.Errorf("helper target changed")
	}
	f, err := os.Open(fmt.Sprintf("/proc/%d/task/%d/exe", r.PID, r.TID))
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return fmt.Errorf("helper executable unreadable")
	}
	dev, ino := devIno(st)
	if dev != r.Dev || ino != r.Ino {
		return fmt.Errorf("helper inode mismatch")
	}
	reply := ownerExeReply{Stat: *st.Sys().(*syscall.Stat_t)}
	if r.Hash {
		if st.Size() > MaxExecutableDigestBytes {
			return fmt.Errorf("helper digest size limit")
		}
		reply.Digest, err = hashOpened(f, statStamp(st))
		if err != nil {
			return err
		}
	}
	after, err := ownerExeAnchor(r.PID, r.TID)
	if err != nil || !sameOwnerExe(r, after) {
		return fmt.Errorf("helper target changed after open")
	}
	return json.NewEncoder(os.Stdout).Encode(reply)
}

// Retention uses the same normal native stamp and digest, but does not invent a
// stable host backing path for a disposable owner-only FUSE mount.
func captureOwnerFuseEvidence(target, nsPath string, owner Process, app Application, alive func() error) (*RetainedExecutable, error) {
	if app.Kind != "native" {
		return nil, fmt.Errorf("owner FUSE fallback is native only")
	}
	if err := alive(); err != nil {
		return nil, err
	}
	pid, tid, ok := procExeTarget(target)
	if !ok {
		return nil, fmt.Errorf("not a process executable")
	}
	anchor, err := ownerExeAnchor(pid, tid)
	if err != nil || anchor.Start != owner.Start || anchor.UID != owner.UID || anchor.MountNS != owner.MountNS || anchor.Exe != nsPath {
		return nil, fmt.Errorf("owner executable identity changed")
	}
	reply, err := readOwnerExecutable(target, false)
	if err != nil {
		return nil, err
	}
	st := ownerExeInfo{reply.Stat}
	if statStamp(st) != app.Revision {
		return nil, fmt.Errorf("owner executable revision changed")
	}
	ev := ExecutableEvidence{PID: owner.PID, Start: owner.Start, BootID: owner.BootID, UID: owner.UID, MountNS: owner.MountNS, Path: nsPath, Dev: uint64(reply.Stat.Dev), Inode: reply.Stat.Ino, Stamp: statStamp(st), Visibility: VisibilitySandboxOnly, Reason: "owner-credential-fuse-read; no verified stable host backing path", CapturedAt: time.Now()}
	switch {
	case st.Size() > MaxExecutableDigestBytes:
		ev.DigestState = "too-large"
	case !takeDigestBudget(st.Size()):
		ev.DigestState = "skipped"
	default:
		hashed, e := readOwnerExecutable(target, true)
		if e != nil {
			return nil, e
		}
		if statStamp(ownerExeInfo{hashed.Stat}) != ev.Stamp || hashed.Stat.Dev != reply.Stat.Dev || hashed.Stat.Ino != reply.Stat.Ino || len(hashed.Digest) != 64 {
			return nil, fmt.Errorf("owner executable changed while hashing")
		}
		if _, err := hex.DecodeString(hashed.Digest); err != nil {
			return nil, fmt.Errorf("invalid executable digest")
		}
		ev.SHA256 = hashed.Digest
		ev.DigestState = "done"
	}
	after, err := ownerExeAnchor(pid, tid)
	if err != nil || !sameOwnerExe(anchor, after) {
		return nil, fmt.Errorf("owner changed during retention")
	}
	if err := alive(); err != nil {
		return nil, err
	}
	return RetainEvidence(ev), nil
}

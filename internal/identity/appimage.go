package identity

// A mount name or APPIMAGE environment variable is not authority. Link the
// executing inode's read-only FUSE filesystem to an actual /dev/fuse holder,
// then require that holder to execute and hold open the same type-2 AppImage.
import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type AppImageIdentity struct {
	Container          string `json:"container"`
	RelativeExecutable string `json:"relative_executable"`
	ContainerRevision  string `json:"container_revision"`
	verified           bool   // Only live discovery may issue this receipt; JSON cannot.
}

type appImageMount struct {
	ID, Point, Relative string
	Connection          uint64
}

func appImageMountFor(info string, r ownerExeRequest) (appImageMount, error) {
	id, ok := ownerFuseMount(info, r.Exe, r.UID, r.GID)
	if !ok {
		return appImageMount{}, fmt.Errorf("not owner-only FUSE")
	}
	var out appImageMount
	count := 0
	for _, line := range strings.Split(info, "\n") {
		f := strings.Fields(line)
		if len(f) < 10 || f[0] != id {
			continue
		}
		count++
		point := unescapeMount(f[4])
		rel, under := under(r.Exe, point)
		if !under || rel == "" || rel == "." || rel == "/" || f[3] != "/" || !hasMountOption(f[5], "ro") {
			return out, fmt.Errorf("not a read-only whole-filesystem executable")
		}
		parts := strings.Split(f[2], ":")
		if len(parts) != 2 || parts[0] != "0" {
			return out, fmt.Errorf("unsupported FUSE device")
		}
		minor, e := strconv.ParseUint(parts[1], 10, 32)
		if e != nil || minor == 0 || r.Dev != unix.Mkdev(0, uint32(minor)) {
			return out, fmt.Errorf("mount/mapping device mismatch")
		}
		out = appImageMount{id, point, strings.TrimPrefix(rel, "/"), minor}
	}
	if count != 1 {
		return out, fmt.Errorf("ambiguous mount")
	}
	return out, nil
}
func hasMountOption(s, want string) bool {
	for _, v := range strings.Split(s, ",") {
		if v == want {
			return true
		}
	}
	return false
}
func fuseConnection(info string) (uint64, error) {
	var n uint64
	count := 0
	for _, line := range strings.Split(info, "\n") {
		f := strings.Fields(line)
		if len(f) > 0 && f[0] == "fuse_connection:" {
			count++
			if len(f) != 2 {
				return 0, fmt.Errorf("invalid FUSE descriptor")
			}
			v, e := strconv.ParseUint(f[1], 10, 32)
			if e != nil || v == 0 {
				return 0, fmt.Errorf("invalid connection")
			}
			n = v
		}
	}
	if count != 1 {
		return 0, fmt.Errorf("missing or ambiguous FUSE connection")
	}
	return n, nil
}

type appImageLocator struct {
	PID               int
	Start, Path       string
	FuseFD, ArchiveFD string
}
type appImageProvider struct {
	Locator  appImageLocator
	Revision string
	Dev, Ino uint64
}

func appImageHeader(path string) (os.FileInfo, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	s, e := f.Stat()
	if e != nil || !s.Mode().IsRegular() || s.Size() <= appImageRuntimeSize {
		return nil, fmt.Errorf("not an archive executable")
	}
	// The marker is only a format hint. Permission authority requires the exact
	// validated runtime implementation, including its embedded SquashFS reader.
	prefix := make([]byte, appImageRuntimeSize)
	if _, e = io.ReadFull(f, prefix); e != nil || appImageRuntimeDigest(prefix) != appImageRuntimeSHA256 {
		return nil, fmt.Errorf("unsupported AppImage runtime implementation")
	}
	var magic [4]byte
	if _, e = io.ReadFull(f, magic[:]); e != nil || string(magic[:]) != "hsqs" {
		return nil, fmt.Errorf("missing embedded SquashFS at validated offset")
	}
	var fs unix.Statfs_t
	if e = unix.Fstatfs(int(f.Fd()), &fs); e != nil || uint64(fs.Type) == 0x65735546 {
		return nil, fmt.Errorf("archive itself is FUSE or unavailable")
	}
	return s, nil
}

// Validate one connection holder. Discovery below must also account for every
// other holder; an accepted holder is not proof that it serves the mount alone.
func inspectAppImageProvider(l appImageLocator, r ownerExeRequest, m appImageMount) (appImageProvider, error) {
	p := appImageProvider{Locator: l}
	base := fmt.Sprintf("/proc/%d", l.PID)
	start, _, e := processStat(base)
	if e != nil || (l.Start != "" && l.Start != start) {
		return p, fmt.Errorf("provider generation changed")
	}
	p.Locator.Start = start
	uid, gid, _, e := ownerCredentials(string(readBound(base+"/status", 65536)))
	if e != nil || uid != r.UID || gid != r.GID || link(base+"/ns/mnt") != r.MountNS || r.MountNS != SelfMountNS() {
		return p, fmt.Errorf("provider credentials/namespace mismatch")
	}
	path := link(base + "/exe")
	if !filepath.IsAbs(path) || strings.HasSuffix(path, " (deleted)") || (l.Path != "" && path != l.Path) {
		return p, fmt.Errorf("provider executable changed")
	}
	canonical, e := filepath.EvalSymlinks(path)
	if e != nil || canonical != path {
		return p, fmt.Errorf("provider path not canonical")
	}
	st, e := appImageHeader(base + "/exe")
	if e != nil {
		return p, e
	}
	host, e := os.Stat(path)
	if e != nil || !os.SameFile(st, host) || statStamp(st) != statStamp(host) {
		return p, fmt.Errorf("provider host backing mismatch")
	}
	if e = appImageRuntimeMappings(base, st); e != nil {
		return p, e
	}
	p.Locator.Path = path
	p.Revision = statStamp(st)
	p.Dev, p.Ino = devIno(st)
	if l.FuseFD != "" && l.ArchiveFD != "" {
		if e = verifyAppImageFDs(base, l.FuseFD, l.ArchiveFD, m.Connection, st); e != nil {
			return p, e
		}
	} else {
		entries, e := os.ReadDir(base + "/fd")
		if e != nil || len(entries) > 4096 {
			return p, fmt.Errorf("provider descriptors unavailable")
		}
		for _, fd := range entries {
			q := base + "/fd/" + fd.Name()
			s, e := os.Stat(q)
			if e != nil {
				return p, fmt.Errorf("provider descriptor changed")
			}
			if os.SameFile(st, s) && fd.Name() != "0" && fd.Name() != "1" && fd.Name() != "2" {
				p.Locator.ArchiveFD = fd.Name()
			}
			if s.Mode()&os.ModeCharDevice != 0 && s.Sys().(*syscall.Stat_t).Rdev == unix.Mkdev(10, 229) {
				n, e := fuseConnection(string(readBound(base+"/fdinfo/"+fd.Name(), 4096)))
				if e == nil && n == m.Connection {
					p.Locator.FuseFD = fd.Name()
				}
			}
		}
		if p.Locator.FuseFD == "" || p.Locator.ArchiveFD == "" {
			return p, fmt.Errorf("no bound FUSE and self-archive descriptors")
		}
		if e = verifyAppImageFDs(base, p.Locator.FuseFD, p.Locator.ArchiveFD, m.Connection, st); e != nil {
			return p, e
		}
	}
	// Supported self-mounting runtime layout: every non-stdio regular FD is
	// the executable archive itself. An external-payload runtime is not this
	// binding, even if it also holds its own executable open.
	fds, e := os.ReadDir(base + "/fd")
	if e != nil || len(fds) > 4096 {
		return p, fmt.Errorf("provider descriptor inventory unavailable")
	}
	for _, fd := range fds {
		n, err := strconv.Atoi(fd.Name())
		if err != nil {
			return p, err
		}
		if n < 3 {
			// Stdio may be output logs, but cannot conceal an external readable
			// SquashFS source after the caller closed its normal stdin.
			flags, err := appImageFDFlags(base + "/fdinfo/" + fd.Name())
			if err != nil {
				return p, err
			}
			if flags&unix.O_ACCMODE == unix.O_WRONLY {
				continue
			}
		}
		s, err := os.Stat(base + "/fd/" + fd.Name())
		if err != nil {
			return p, err
		}
		if s.Mode().IsRegular() && !os.SameFile(st, s) {
			return p, fmt.Errorf("external provider file: unsupported runtime layout")
		}
	}
	end, _, e := processStat(base)
	if e != nil || start != end || link(base+"/exe") != path {
		return p, fmt.Errorf("provider changed during observation")
	}
	return p, nil
}
func verifyAppImageFDs(base, fuseFD, archiveFD string, connection uint64, exe os.FileInfo) error {
	f, e := os.Stat(base + "/fd/" + fuseFD)
	if e != nil || f.Mode()&os.ModeCharDevice == 0 || f.Sys().(*syscall.Stat_t).Rdev != unix.Mkdev(10, 229) {
		return fmt.Errorf("not a FUSE descriptor")
	}
	n, e := fuseConnection(string(readBound(base+"/fdinfo/"+fuseFD, 4096)))
	if e != nil || n != connection {
		return fmt.Errorf("wrong FUSE connection")
	}
	a, e := os.Stat(base + "/fd/" + archiveFD)
	if e != nil || !os.SameFile(exe, a) || statStamp(exe) != statStamp(a) {
		return fmt.Errorf("archive descriptor mismatch")
	}
	return nil
}

// Reuse the descriptor-table census's KCMP_FILES and generation/recheck logic.
// The socket iterator does not enumerate FUSE devices, so this scoped census
// uses fresh proc observations. Table sharing never grants process authority:
// every task in every matching table must pass provider validation separately.
func appImageProviderCensus(connection uint64) HolderCensus {
	p := procHolders()
	p.iterator = nil
	token := fmt.Sprintf("fuse-connection:[%d]", connection)
	p.fds = func(tgid, tid int, visit func(path, target string) bool) error {
		base := fmt.Sprintf("/proc/%d/task/%d", tgid, tid)
		_, err := appImageStableHolderScan(func() (bool, error) {
			return appImageTableScan(base, connection, visit)
		}, func() (string, error) { start, _, err := processStat(base); return start, err })
		if err != nil {
			// Exhausted or known-holder failures must not become a topology
			// retry that erases the partial observation. Budget already charged.
			return fmt.Errorf("FUSE table observation failed: %v", err)
		}
		return nil
	}
	p.readlink = func(path string) (string, error) {
		// Recheck the exact matched FD against its kernel connection ID, not its
		// display path. fdinfo errors cannot become an empty/nonmatching result.
		raw, err := appImageReadBound(filepath.Join(filepath.Dir(filepath.Dir(path)), "fdinfo", filepath.Base(path)), 4096)
		if err != nil {
			return "", err
		}
		n, err := fuseConnection(string(raw))
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("fuse-connection:[%d]", n), nil
	}
	lim := defaultHolderLimits
	lim.Time = 250 * time.Millisecond
	return p.census(map[string]bool{token: true}, lim)
}

func discoverAppImageProvider(r ownerExeRequest, m appImageMount) (appImageProvider, error) {
	census := appImageProviderCensus(m.Connection)
	if !census.Complete {
		return appImageProvider{}, fmt.Errorf("FUSE holder census incomplete: %v", census.Issues)
	}
	var found *appImageProvider
	for _, h := range census.Holders {
		for _, member := range h.Members {
			p, err := inspectAppImageProvider(appImageLocator{PID: member.TID, Start: member.Start}, r, m)
			if err != nil {
				return p, fmt.Errorf("unverified FUSE holder %d: %w", member.TID, err)
			}
			if found != nil && (found.Dev != p.Dev || found.Ino != p.Ino || found.Locator.Path != p.Locator.Path) {
				return p, fmt.Errorf("ambiguous AppImage provider")
			}
			found = &p
		}
	}
	if err := census.Recheck(); err != nil {
		return appImageProvider{}, fmt.Errorf("FUSE holder census changed: %w", err)
	}
	if found == nil {
		return appImageProvider{}, fmt.Errorf("no verified AppImage provider")
	}
	return *found, nil
}

func observeAppImage(pid int, st os.FileInfo) (*AppImageIdentity, error) {
	r, e := ownerExeAnchor(pid, pid)
	if e != nil {
		return nil, e
	}
	if st == nil {
		return nil, fmt.Errorf("no executable metadata")
	}
	dev, ino := devIno(st)
	if dev != r.Dev || ino != r.Ino {
		return nil, fmt.Errorf("executable changed before AppImage discovery")
	}
	info := string(readBound(fmt.Sprintf("/proc/%d/mountinfo", pid), 1<<20))
	m, e := appImageMountFor(info, r)
	if e != nil {
		return nil, e
	}
	before, e := discoverAppImageProvider(r, m)
	if e != nil {
		return nil, e
	}
	after, e := discoverAppImageProvider(r, m)
	if e != nil || before != after {
		return nil, fmt.Errorf("AppImage provider changed")
	}
	end, e := ownerExeAnchor(pid, pid)
	if e != nil || !sameOwnerExe(r, end) {
		return nil, fmt.Errorf("AppImage process changed")
	}
	endMount, e := appImageMountFor(string(readBound(fmt.Sprintf("/proc/%d/mountinfo", pid), 1<<20)), end)
	if e != nil || endMount != m {
		return nil, fmt.Errorf("AppImage mount changed")
	}
	return &AppImageIdentity{Container: before.Locator.Path, RelativeExecutable: m.Relative, ContainerRevision: before.Revision, verified: true}, nil
}
func verifiedAppImage(a Application) bool {
	return a.AppImage != nil && a.AppImage.verified && a.Kind == "native"
}

package identity

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// AppImageKit effcebc, x86_64 type-2 runtime. This is a runtime implementation
// pin, never an application pin. Its embedded squashfuse opens one archive and
// services requests from that live descriptor at the ELF-end offset. Unknown
// implementations keep the ordinary, per-mount native identity.
const appImageRuntimeSize int64 = 188392
const appImageRuntimeSHA256 = "24da8e0e149b7211cbfb00a545189a1101cb18d1f27d4cfc1895837d2c30bc30"

// AppImage packaging fills these non-ALLOC sections after producing the
// runtime. They follow the last PT_LOAD file byte (175704) in this exact
// implementation. Only these fixed bytes are normalized: ELF/program/section
// headers, their flags/offsets, and all loaded code/data remain in the pin. An
// altered ELF layout therefore cannot pass. Metadata can occupy the exact
// supported executable page padding, but never an added/relocated RX mapping.
// This recognizes a runtime implementation, not a signature or update authority.
func appImageRuntimeDigest(prefix []byte) string {
	if int64(len(prefix)) != appImageRuntimeSize {
		return ""
	}
	normalized := append([]byte(nil), prefix...)
	for _, section := range [][2]int{{175704, 16}, {175720, 1024}, {176744, 1024}, {177768, 8192}} {
		clear(normalized[section[0] : section[0]+section[1]])
	}
	sum := sha256.Sum256(normalized)
	return hex.EncodeToString(sum[:])
}

// Scan all processes, including those that do not look like AppImages. A FUSE
// connection can be passed to a process in another UID or mount namespace.
// Disappearance is inconclusive if a descriptor inventory was already opened.
func appImageConnectionHolder(base string, connection uint64) (bool, error) {
	return appImageStableHolderScan(func() (bool, error) { return appImageHolderScan(base, connection) }, func() (string, error) {
		start, _, err := processStat(base)
		return start, err
	})
}

// Discard a transiently interrupted inventory in full, never splice or skip an
// entry. A known holder, generation change, or persistent error stays refused.
func appImageStableHolderScan(scan func() (bool, error), generation func() (string, error)) (bool, error) {
	start, err := generation()
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	} // task gone before observation
	if err != nil {
		return false, err
	}
	for attempt := 0; attempt < 3; attempt++ {
		holds, err := scan()
		end, changed := generation()
		if changed != nil || end != start {
			return holds, fmt.Errorf("FUSE task generation changed")
		}
		if err == nil || holds || !errors.Is(err, os.ErrNotExist) || attempt == 2 {
			return holds, err
		}
	}
	panic("unreachable")
}

func appImageHolderScan(base string, connection uint64) (bool, error) {
	return appImageTableScan(base, connection, nil)
}

func appImageTableScan(base string, connection uint64, visit func(path, target string) bool) (bool, error) {
	dir, e := os.Open(base + "/fd")
	if e != nil {
		// Not retriable: a task/table disappearing is not per-FD churn.
		return false, fmt.Errorf("FUSE holder inventory unavailable: %s", base)
	}
	defer dir.Close()
	fds, e := dir.ReadDir(4097)
	if e != nil && e != io.EOF || len(fds) > 4096 {
		return false, fmt.Errorf("FUSE holder inventory unavailable: %s", base)
	}
	found := false
	for _, fd := range fds {
		// Charge every attempted FD, including failed/retried and anonymous
		// observations, before doing work. A matching update below adds a
		// conservative extra budget charge; it preserves partial positives.
		path := base + "/fd/" + fd.Name()
		if visit != nil && !visit(path, "") {
			return found, nil
		}
		// The kernel formats anonymous-inode magic links as "anon_inode:...".
		// These are not character-device /dev/fuse handles. In particular epoll
		// and inotify fdinfo grow with registrations and need not fit 4 KiB.
		// Do not stat unrelated files here: owner-only FUSE getattr can reject
		// even root. Every non-anonymous descriptor still needs its full record.
		target, err := os.Readlink(base + "/fd/" + fd.Name())
		if errors.Is(err, os.ErrNotExist) {
			// A listed FD closed before observation; it is not a current
			// holder. Budget was charged. Task generation and any previously
			// matched FUSE descriptors are still independently rechecked.
			continue
		}
		if err != nil {
			return found, fmt.Errorf("FUSE descriptor link unavailable: %s/%s: %w", base, fd.Name(), err)
		}
		if strings.HasPrefix(target, "anon_inode:") {
			continue
		}
		// fdinfo is kernel-owned and does not stat the object behind the FD.
		// Stat would fail on unrelated owner-only FUSE files even for root.
		raw, e := appImageReadBound(base+"/fdinfo/"+fd.Name(), 4096)
		if errors.Is(e, os.ErrNotExist) {
			continue // closed between link and fdinfo; same charged observation
		}
		if e != nil || len(raw) > 4096 {
			return found, fmt.Errorf("FUSE descriptor observation unavailable: %s/%s: %w", base, fd.Name(), e)
		}
		if !strings.Contains(string(raw), "fuse_connection:") {
			continue
		}
		n, e := fuseConnection(string(raw))
		if e != nil {
			return found, e
		}
		matched := ""
		if n == connection {
			found = true
			matched = fmt.Sprintf("fuse-connection:[%d]", connection)
		}
		if matched != "" && visit != nil && !visit(path, matched) {
			return found, nil
		}
	}
	return found, nil
}

// Trusted system DSOs may implement libc and libfuse, but an arbitrary preload
// must not replace the pinned reader. Require root-owned, non-user-writable
// files and parent directories, then compare every executable mapping to its
// mapped file. This is a live code/layout observation, not an attestation against
// a same-UID debugger modifying the process after observation.
func appImageSystemCode(path string) bool {
	if !filepath.IsAbs(path) {
		return false
	}
	canonical, e := filepath.EvalSymlinks(path)
	if e != nil || canonical != path {
		return false
	}
	for q := path; ; q = filepath.Dir(q) {
		s, e := os.Lstat(q)
		if e != nil || s.Mode()&os.ModeSymlink != 0 || s.Mode().Perm()&0022 != 0 {
			return false
		}
		st, ok := s.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 {
			return false
		}
		if q == "/" {
			return true
		}
	}
}

func appImageRuntimeMappings(base string, exe os.FileInfo) error {
	raw, e := appImageReadBound(base+"/maps", 1<<20)
	if e != nil || len(raw) > 1<<20 {
		return fmt.Errorf("runtime mappings unavailable")
	}
	mem, e := os.Open(base + "/mem")
	if e != nil {
		return fmt.Errorf("runtime code observation: %w", e)
	}
	defer mem.Close()
	budget := int64(16 << 20)
	runtimeSeen := false
	a, b := make([]byte, 64<<10), make([]byte, 64<<10)
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || !strings.Contains(f[1], "x") {
			continue
		}
		if len(f) == 6 && ((f[5] == "[vdso]" && f[1] == "r-xp") || (f[5] == "[vsyscall]" && f[1] == "--xp")) {
			continue
		}
		if len(f) != 6 || f[1] != "r-xp" {
			return fmt.Errorf("unsupported runtime executable mapping")
		}
		if f[5] == "[vdso]" || f[5] == "[vsyscall]" {
			continue
		}
		r := strings.Split(f[0], "-")
		dev := strings.Split(f[3], ":")
		if len(r) != 2 || len(dev) != 2 {
			return fmt.Errorf("invalid runtime mapping")
		}
		lo, e1 := strconv.ParseUint(r[0], 16, 63)
		hi, e2 := strconv.ParseUint(r[1], 16, 63)
		off, e3 := strconv.ParseUint(f[2], 16, 63)
		major, e4 := strconv.ParseUint(dev[0], 16, 32)
		minor, e5 := strconv.ParseUint(dev[1], 16, 32)
		ino, e6 := strconv.ParseUint(f[4], 10, 64)
		if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil || e6 != nil || hi <= lo || hi-lo > uint64(budget) {
			return fmt.Errorf("runtime mapping budget/layout")
		}
		disk, e := os.Open(f[5])
		if e != nil {
			return e
		}
		st, e := disk.Stat()
		if e != nil {
			disk.Close()
			return e
		}
		if !appImageMappedFile(st, unix.Mkdev(uint32(major), uint32(minor)), ino, fmt.Sprintf("%s/map_files/%x-%x", base, lo, hi), os.Stat) {
			disk.Close()
			return fmt.Errorf("runtime mapped file changed")
		}
		if os.SameFile(st, exe) {
			if !appImageRuntimeCodeRange(lo, hi, off, runtimeSeen) {
				disk.Close()
				return fmt.Errorf("unsupported archive executable mapping")
			}
			runtimeSeen = true
		} else if !appImageSystemCode(f[5]) || !appImageRuntimeDSO(disk) {
			disk.Close()
			return fmt.Errorf("untrusted runtime code mapping")
		}
		n := int64(hi - lo)
		if int64(off)+n > st.Size() {
			disk.Close()
			return fmt.Errorf("runtime code outside file")
		}
		for pos := int64(0); pos < n; {
			size := min(n-pos, int64(len(a)))
			_, e1 = io.ReadFull(io.NewSectionReader(disk, int64(off)+pos, size), a[:size])
			_, e2 = mem.ReadAt(b[:size], int64(lo)+pos)
			if e1 != nil || e2 != nil || !bytes.Equal(a[:size], b[:size]) {
				disk.Close()
				return fmt.Errorf("runtime code differs from backing file")
			}
			pos += size
		}
		disk.Close()
		budget -= n
	}
	if !runtimeSeen {
		return fmt.Errorf("missing runtime code mapping")
	}
	return nil
}

func appImageFDFlags(path string) (uint64, error) {
	raw, e := appImageReadBound(path, 4096)
	if e != nil || len(raw) > 4096 {
		return 0, fmt.Errorf("descriptor flags unavailable")
	}
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == "flags:" {
			return strconv.ParseUint(f[1], 8, 64)
		}
	}
	return 0, fmt.Errorf("descriptor flags absent")
}

// Only the system library roles used by the validated implementation are
// supported, not arbitrary root-installed preloads or plugin libraries.
func appImageRuntimeDSO(f *os.File) bool {
	e, err := elf.NewFile(f)
	if err != nil {
		return false
	}
	names, err := e.DynString(elf.DT_SONAME)
	if err != nil || len(names) != 1 {
		return false
	}
	switch names[0] {
	case "libc.so.6", "libdl.so.2", "libpthread.so.0", "librt.so.1", "libz.so.1", "libfuse.so.2", "ld-linux-x86-64.so.2":
		return true
	}
	return false
}

func appImageReadBound(path string, limit int64) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil {
		return nil, e
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("AppImage observation exceeds bound")
	}
	return b, nil
}

// Btrfs maps report the superblock device, while stat reports the subvolume
// device. Resolve the kernel mapping itself on a mismatch; inode equality alone
// cannot distinguish files in different subvolumes. Unreadable proof refuses.
func appImageMappedFile(info os.FileInfo, device, inode uint64, mapping string, stat func(string) (os.FileInfo, error)) bool {
	d, i := devIno(info)
	if i != inode {
		return false
	}
	if d == device {
		return true
	}
	mapped, err := stat(mapping)
	return err == nil && os.SameFile(info, mapped)
}

// The pinned non-PIE runtime has exactly this one executable PT_LOAD mapping.
// Its final page includes non-ALLOC packaging metadata as ordinary page padding.
// Do not admit extra/relocated mappings of unhashed metadata as executable code.
// This remains a live-process check, not protection against a same-UID debugger.
func appImageRuntimeCodeRange(lo, hi, offset uint64, seen bool) bool {
	return !seen && lo == 0x400000 && hi == 0x42b000 && offset == 0
}

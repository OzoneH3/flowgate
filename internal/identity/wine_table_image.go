package identity

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// Only the independently validated Windows owner table supplies path here.
// Some launchers retain their original argv[0] after loading a different main
// image. That command line cannot corroborate the new image, but a mapped PE
// file with the exact device/inode and revision can. This fallback never gives
// a command-line-only process an application identity in Inspect.
func wineTableImageVisible(p Process, path, revision, maps string) bool {
	return wineTableImageWithMapping(p, path, revision, maps, os.Stat)
}

func wineTableImageWithMapping(p Process, path, revision, maps string, mappingStat func(string) (os.FileInfo, error)) bool {
	if strings.Contains(maps, path+" (deleted)") {
		return false
	}
	if p.Application.Executable == path && p.Application.Revision == revision && p.Application.Key != "" {
		return true
	}
	if p.Application.Kind != "wine-unresolved" || revision == "" {
		return false
	}
	source := fmt.Sprintf("/proc/%d/root%s", p.PID, path)
	f, err := os.Open(source)
	if err != nil {
		return false
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || stamp(source) != revision {
		return false
	}
	st := info.Sys().(*syscall.Stat_t)
	if st.Nlink == 0 {
		return false
	}
	if headers, _ := peHeaders(f); headers == nil {
		return false
	}
	headerMapped, sectionMapped := false, false
	for _, line := range strings.Split(maps, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 || strings.Join(fields[5:], " ") != path || !strings.HasPrefix(fields[1], "r") {
			continue
		}
		offset, e := strconv.ParseUint(fields[2], 16, 64)
		if e != nil {
			continue
		}
		inode, e := strconv.ParseUint(fields[4], 10, 64)
		if e != nil || inode != st.Ino {
			continue
		}
		major, minor, ok := strings.Cut(fields[3], ":")
		if !ok {
			continue
		}
		ma, e1 := strconv.ParseUint(major, 16, 32)
		mi, e2 := strconv.ParseUint(minor, 16, 32)
		if e1 != nil || e2 != nil {
			continue
		}
		if ma != uint64(unix.Major(uint64(st.Dev))) || mi != uint64(unix.Minor(uint64(st.Dev))) {
			// Btrfs proc maps can report the superblock device while stat
			// reports the subvolume device. The mapped file itself must then
			// prove identity; never accept an inode match alone.
			mapped, err := mappingStat(fmt.Sprintf("/proc/%d/map_files/%s", p.PID, fields[0]))
			if err != nil || !os.SameFile(info, mapped) {
				continue
			}
		}
		if offset == 0 {
			headerMapped = true
		} else {
			sectionMapped = true
		}
	}
	current, err := os.Stat(source)
	return headerMapped && sectionMapped && err == nil && os.SameFile(info, current) && stamp(source) == revision
}

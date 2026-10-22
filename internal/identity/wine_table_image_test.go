package identity

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestWineTableImageLauncherHandoff(t *testing.T) {
	// Identical headers deliberately cannot identify an app by themselves.
	header := make([]byte, 4096)
	copy(header, "MZ")
	binary.LittleEndian.PutUint32(header[60:], 128)
	copy(header[128:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(header[134:], 1)
	binary.LittleEndian.PutUint16(header[148:], 240)
	binary.LittleEndian.PutUint16(header[152:], 0x20b)
	binary.LittleEndian.PutUint32(header[208:], 8192)
	binary.LittleEndian.PutUint32(header[212:], 1024)
	var paths []string
	for _, prefix := range []string{"prefix-one", "prefix-two"} {
		dir := filepath.Join(t.TempDir(), prefix)
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		for _, app := range []string{"alpha.exe", "beta.exe"} {
			path := filepath.Join(dir, app)
			if err := os.WriteFile(path, header, 0600); err != nil {
				t.Fatal(err)
			}
			paths = append(paths, path)
		}
	}
	p := Process{PID: os.Getpid(), Application: Application{Kind: "wine-unresolved"}}
	for _, path := range paths {
		t.Run(filepath.Base(filepath.Dir(path))+"/"+filepath.Base(path), func(t *testing.T) {
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			st := info.Sys().(*syscall.Stat_t)
			// Synthetic proc maps use the file's identity; some filesystems
			// report a different superblock device in real proc maps, which
			// map_files must prove identity if the device differs.
			row := func(offset int) string {
				return fmt.Sprintf("%x-%x r--p %08x %02x:%02x %d %s", 0x1000+offset, 0x2000+offset, offset, unix.Major(uint64(st.Dev)), unix.Minor(uint64(st.Dev)), st.Ino, path)
			}
			maps := row(0) + "\n" + row(4096)
			revision := stamp(path)
			if wineTableImageVisible(p, path, revision, row(0)) {
				t.Fatal("header-only data mapping accepted")
			}

			if !wineTableImageVisible(p, path, revision, maps) {
				t.Fatal("runtime-selected mapped PE rejected")
			}
			for _, other := range paths {
				if other != path && wineTableImageVisible(p, other, stamp(other), maps) {
					t.Fatal("association transferred across executable/prefix")
				}
			}
			if wineTableImageVisible(p, path, "old-revision", maps) || wineTableImageVisible(p, path, revision, "") {
				t.Fatal("missing or stale evidence accepted")
			}
			if wineTableImageVisible(p, path, revision, strings.ReplaceAll(maps, path, path+" (deleted)")) {
				t.Fatal("deleted image accepted")
			}
			// Correct inode without its device is not file identity.
			var forged []string
			for _, line := range strings.Split(maps, "\n") {
				if strings.HasSuffix(line, path) {
					fields := strings.Fields(line)
					fields[3] = "00:00"
					line = strings.Join(fields, " ")
				}
				forged = append(forged, line)
			}
			foreignMaps := strings.Join(forged, "\n")
			if wineTableImageWithMapping(p, path, revision, foreignMaps, func(string) (os.FileInfo, error) { return nil, os.ErrPermission }) {
				t.Fatal("unreadable mapped-file identity accepted")
			}
			if !wineTableImageWithMapping(p, path, revision, foreignMaps, func(string) (os.FileInfo, error) { return info, nil }) {
				t.Fatal("proven subvolume mapping rejected")
			}
			otherPath := paths[0]
			if otherPath == path {
				otherPath = paths[1]
			}
			otherInfo, err := os.Stat(otherPath)
			if err != nil {
				t.Fatal(err)
			}
			if wineTableImageWithMapping(p, path, revision, foreignMaps, func(string) (os.FileInfo, error) { return otherInfo, nil }) {
				t.Fatal("different mapped file accepted")
			}
			other := p
			other.Application = Application{Kind: "wine", Executable: paths[(len(paths) - 1)], Revision: "different", Key: "different"}
			if wineTableImageVisible(other, path, revision, maps) {
				t.Fatal("conflicting identified application overridden")
			}
			other.Application.Kind = "native"
			if wineTableImageVisible(other, path, revision, maps) {
				t.Fatal("native process accepted")
			}
		})
	}
}

package identity

import (
	"bytes"
	"debug/elf"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// Capability hint, not a signature or execution attestation. Restrict matching
// to ELF runtimes exposing Node execution and Electron's documented fuse-v1 wire.
var electronCapabilities = struct {
	sync.Mutex
	entries map[string]bool
}{entries: map[string]bool{}}

func electronRuntimeCapable(path string) bool {
	key := stamp(path)
	if key == "" {
		return false
	}
	electronCapabilities.Lock()
	defer electronCapabilities.Unlock()
	if result, ok := electronCapabilities.entries[key]; ok {
		return result
	}
	result := false
	defer func() {
		if len(electronCapabilities.entries) >= 32 {
			electronCapabilities.entries = map[string]bool{}
		}
		electronCapabilities.entries[key] = result
	}()
	f, err := elf.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	if f.Class != elf.ELFCLASS64 {
		return false
	}
	symbols, err := f.DynamicSymbols()
	if err != nil {
		return false
	}
	node := false
	for _, s := range symbols {
		if strings.HasPrefix(s.Name, "_ZN4node14StartExecution") {
			node = true
			break
		}
	}
	if !node {
		return false
	}
	raw, err := os.Open(path)
	if err != nil {
		return false
	}
	defer raw.Close()
	b, err := io.ReadAll(io.LimitReader(raw, 64<<20))
	if err != nil {
		return false
	}
	marker := []byte("dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX")
	i := bytes.Index(b, marker) + len(marker)
	if i < len(marker) || i+2 >= len(b) || b[i] != 1 || b[i+1] < 6 || b[i+1] > 16 || i+2+int(b[i+1]) > len(b) {
		return false
	}
	result = true
	return true
}
func hasArgument(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}
func openArchiveMatches(pid int, path string) bool {
	target, err := os.Stat(path)
	if err != nil {
		return false
	}
	dir := filepath.Join("/proc", strconv.Itoa(pid), "fd")
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) > 4096 {
		return false
	}
	for _, entry := range entries {
		if info, e := os.Stat(filepath.Join(dir, entry.Name())); e == nil && os.SameFile(target, info) {
			return true
		}
	}
	return false
}

// sharedPackageArchive corroborates a separate package-utility association. It
// never grants the main application's identity. Libraries can be shared by
// different utility scripts: the advertised scope is the package utility group,
// not a claim to identify individual extensions or attest executed code.
func sharedPackageArchive(pid, main int, app string) bool {
	root := app
	if st, err := os.Stat(fmtProcRoot(main, app)); err != nil {
		return false
	} else if !st.IsDir() {
		root = filepath.Dir(app)
	}
	dir := filepath.Join("/proc", strconv.Itoa(pid), "fd")
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) > 4096 {
		return false
	}
	mainDir := filepath.Join("/proc", strconv.Itoa(main), "fd")
	mainEntries, err := os.ReadDir(mainDir)
	if err != nil || len(mainEntries) > 4096 {
		return false
	}
	opened := make(map[[2]uint64]bool)
	for _, entry := range mainEntries {
		if st, err := os.Stat(filepath.Join(mainDir, entry.Name())); err == nil && st.Mode().IsRegular() {
			dev, ino := devIno(st)
			opened[[2]uint64{dev, ino}] = true
		}
	}
	for _, entry := range entries {
		fd := filepath.Join(dir, entry.Name())
		path, err := filepath.EvalSymlinks(fd)
		if err != nil || !strings.HasSuffix(path, ".asar") {
			continue
		}
		rel, err := filepath.Rel(root, path)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
			continue
		}
		owner, err := os.Stat(fd)
		if err != nil || !owner.Mode().IsRegular() {
			continue
		}
		visible, err := os.Stat(fmtProcRoot(main, path))
		if err != nil || !os.SameFile(owner, visible) {
			continue
		}
		dev, ino := devIno(owner)
		if opened[[2]uint64{dev, ino}] {
			return true
		}
	}
	return false
}
func fmtProcRoot(pid int, path string) string {
	return filepath.Join("/proc", strconv.Itoa(pid), "root") + path
}

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

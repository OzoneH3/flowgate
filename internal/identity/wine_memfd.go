package identity

// Wine can copy a PE into a shared anonymous image before executing it. This
// corroborates argv[0] with the mapped image's complete PE headers and a source
// file unchanged since before process creation. It does not trust a memfd name
// or a Windows command line by itself, and does not grant broker ownership.
import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
)

func processStartUnix(start string) int64 {
	ticks, err := strconv.ParseUint(start, 10, 64)
	if err != nil {
		return 0
	}
	var hz, boot uint64
	aux := readBound("/proc/self/auxv", 65536)
	word := strconv.IntSize / 8
	number := func(b []byte) uint64 {
		if word == 8 {
			return binary.NativeEndian.Uint64(b)
		}
		return uint64(binary.NativeEndian.Uint32(b))
	}
	for i := 0; i+2*word <= len(aux); i += 2 * word {
		if number(aux[i:]) == 17 {
			hz = number(aux[i+word:])
			break
		}
	}
	for _, line := range strings.Split(string(readBound("/proc/stat", 1<<20)), "\n") {
		if strings.HasPrefix(line, "btime ") {
			boot, _ = strconv.ParseUint(strings.TrimSpace(line[6:]), 10, 64)
			break
		}
	}
	if hz == 0 || hz > 1000000 || boot == 0 || ticks/hz > 1<<40 {
		return 0
	}
	// btime's whole-second precision yields an earlier, conservative cutoff.
	return int64(boot+ticks/hz) * 1e9
}

func peHeaders(f *os.File) ([]byte, int64) {
	b := make([]byte, 4096)
	n, _ := f.ReadAt(b, 0)
	b = b[:n]
	if len(b) < 64 || string(b[:2]) != "MZ" {
		return nil, 0
	}
	pe := int(binary.LittleEndian.Uint32(b[60:]))
	if pe < 64 || pe+88 > len(b) || string(b[pe:pe+4]) != "PE\x00\x00" {
		return nil, 0
	}
	sections := int(binary.LittleEndian.Uint16(b[pe+6:]))
	size := int(binary.LittleEndian.Uint16(b[pe+20:]))
	magic := binary.LittleEndian.Uint16(b[pe+24:])
	if sections < 1 || sections > 96 || size < 64 || (magic != 0x10b && magic != 0x20b) {
		return nil, 0
	}
	headers := int(binary.LittleEndian.Uint32(b[pe+24+60:]))
	image := int64(binary.LittleEndian.Uint32(b[pe+24+56:]))
	if headers < pe+24+size+40*sections || headers > 65536 || image < int64(headers) || image > 1<<31 {
		return nil, 0
	}
	out := make([]byte, headers)
	if _, err := f.ReadAt(out, 0); err != nil {
		return nil, 0
	}
	return out, image
}

func wineMemfdImage(base, path, maps, start string) bool {
	return wineMemfdImageBefore(base, path, maps, processStartUnix(start))
}
func wineMemfdImageBefore(base, path, maps string, cutoff int64) bool {
	if !strings.HasSuffix(strings.ToLower(path), ".exe") {
		return false
	}
	if cutoff == 0 {
		return false
	}
	source, err := os.Open(base + "/root" + path)
	if err != nil {
		return false
	}
	defer source.Close()
	info, err := source.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	st := info.Sys().(*syscall.Stat_t)
	if st.Nlink == 0 || st.Ctim.Nano() >= cutoff || st.Mtim.Nano() >= cutoff {
		return false
	}
	header, imageSize := peHeaders(source)
	if header == nil {
		return false
	}
	// Require both header and executable mappings of the same anonymous inode.
	type mapping struct {
		header, code bool
		dev          string
	}
	objects := map[string]mapping{}
	for _, line := range strings.Split(maps, "\n") {
		f := strings.Fields(line)
		if len(f) < 6 || f[5] != "/memfd:wine-mapping" || f[4] == "0" {
			continue
		}
		m := objects[f[4]]
		m.dev = f[3]
		off, e := strconv.ParseUint(f[2], 16, 64)
		if e != nil {
			continue
		}
		if off == 0 && strings.HasPrefix(f[1], "r") {
			m.header = true
		}
		if strings.Contains(f[1], "x") {
			m.code = true
		}
		objects[f[4]] = m
	}
	fds, err := os.ReadDir(base + "/fd")
	if err != nil {
		return false
	}
	if len(fds) > 16384 {
		return false
	}
	for _, fd := range fds {
		name := base + "/fd/" + fd.Name()
		if link(name) != "/memfd:wine-mapping (deleted)" {
			continue
		}
		f, err := os.Open(name)
		if err != nil {
			continue
		}
		fi, err := f.Stat()
		if err != nil {
			f.Close()
			continue
		}
		ms := fi.Sys().(*syscall.Stat_t)
		m := objects[strconv.FormatUint(ms.Ino, 10)]
		dev := fmt.Sprintf("%02x:%02x", uint64(ms.Dev)>>8&0xfff, uint64(ms.Dev)&0xff|uint64(ms.Dev)>>12&0xffffff00)
		if !m.header || !m.code || m.dev != dev || fi.Size() != imageSize {
			f.Close()
			continue
		}
		actual := make([]byte, len(header))
		_, err = io.ReadFull(io.NewSectionReader(f, 0, int64(len(header))), actual)
		f.Close()
		if err != nil || !bytes.Equal(header, actual) {
			continue
		}
		after, err := source.Stat()
		current, err2 := os.Stat(base + "/root" + path)
		if err == nil && err2 == nil && os.SameFile(info, current) && os.SameFile(info, after) && info.ModTime() == after.ModTime() && info.Size() == after.Size() && st.Ctim == after.Sys().(*syscall.Stat_t).Ctim && st.Ctim == current.Sys().(*syscall.Stat_t).Ctim {
			return true
		}
	}
	return false
}

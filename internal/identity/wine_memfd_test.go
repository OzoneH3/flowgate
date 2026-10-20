package identity

import (
	"encoding/binary"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWineMemfdImageProof(t *testing.T) {
	// Source file exists before the synthetic process-start cutoff. The mapped
	// object and /proc descriptor observations are real; no Wine is executed.
	path := filepath.Join(t.TempDir(), "Example.exe")
	header := make([]byte, 1024)
	copy(header, "MZ")
	binary.LittleEndian.PutUint32(header[60:], 128)
	copy(header[128:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(header[134:], 1)
	binary.LittleEndian.PutUint16(header[148:], 240)
	binary.LittleEndian.PutUint16(header[152:], 0x20b)
	binary.LittleEndian.PutUint32(header[208:], 8192)
	binary.LittleEndian.PutUint32(header[212:], 1024)
	if err := os.WriteFile(path, header, 0600); err != nil {
		t.Fatal(err)
	}
	cutoff := time.Now().Add(time.Millisecond).UnixNano()
	fd, err := unix.MemfdCreate("wine-mapping", 0)
	if err != nil {
		t.Fatal(err)
	}
	f := os.NewFile(uintptr(fd), "fixture")
	defer f.Close()
	if err = f.Truncate(8192); err != nil {
		t.Fatal(err)
	}
	if _, err = f.WriteAt(header, 0); err != nil {
		t.Fatal(err)
	}
	mapped, err := unix.Mmap(fd, 0, 8192, unix.PROT_READ|unix.PROT_EXEC, unix.MAP_SHARED)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Munmap(mapped)
	base := fmt.Sprintf("/proc/%d", os.Getpid())
	maps := string(readBound(base+"/maps", 2<<20))
	if !wineMemfdImageBefore(base, path, maps, cutoff) {
		t.Fatal("exact mapped headers and preexisting source rejected")
	}
	if wineMemfdImageBefore(base, path, "", cutoff) {
		t.Fatal("open but unobserved mapping accepted")
	}
	if wineMemfdImageBefore(base, path, maps, 1) {
		t.Fatal("source created after process start accepted")
	}
	if _, err = f.WriteAt([]byte{0xff}, 256); err != nil {
		t.Fatal(err)
	}
	if wineMemfdImageBefore(base, path, maps, cutoff) {
		t.Fatal("different image headers accepted")
	}
	if _, err = f.WriteAt(header, 0); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Millisecond)
	if err = os.WriteFile(path, header, 0600); err != nil {
		t.Fatal(err)
	}
	if wineMemfdImageBefore(base, path, maps, cutoff) {
		t.Fatal("replacement source with identical headers accepted")
	}
}
func TestPEHeaderBounds(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bad.exe")
	for _, data := range [][]byte{nil, []byte("MZ"), []byte(strings.Repeat("MZ", 4096))} {
		if err := os.WriteFile(p, data, 0600); err != nil {
			t.Fatal(err)
		}
		f, err := os.Open(p)
		if err != nil {
			t.Fatal(err)
		}
		h, _ := peHeaders(f)
		f.Close()
		if h != nil {
			t.Fatal("malformed headers accepted")
		}
	}
	if processStartUnix("invalid") != 0 {
		t.Fatal("invalid process start accepted")
	}
	start, _, err := processStat(fmt.Sprintf("/proc/%d", os.Getpid()))
	if err != nil || processStartUnix(start) <= 0 || processStartUnix(start) > time.Now().UnixNano() {
		t.Fatal(start, err)
	}
}
